use std::time::{SystemTime, UNIX_EPOCH};

use crate::BoxedStream;
use crate::error::{ProxyError, ProxyErrorCode};
use crate::reality::auth::{
    AUTH_KEY_SIZE, SESSION_ID_OFFSET, SESSION_ID_SIZE, decode_pbk, derive_auth_key, parse_short_id,
    seal_session_id, verify_certificate, x25519_agree,
};
use crate::reality::hello::build as build_hello;
use crate::reality::hs_err;
use crate::reality::record::{CipherSuite, ContentType, RecordProtection, TlsRecordStream};
use crate::reality::schedule::{HashKind, derive_secret, extract, finished_verify};
use crate::reality::stream::RealityTlsStream;
use crate::reality::{auth_err};

const HRR: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];
const MAX_FLIGHT: usize = 8;
const CLIENT_VERSION: [u8; 3] = [26, 3, 27];

pub async fn handshake(
    transport: BoxedStream,
    server_name: &str,
    pbk: &str,
    short_id: Option<&str>,
    alpn: &[String],
) -> Result<RealityTlsStream, ProxyError> {
    let public = decode_pbk(pbk)?;
    let io = crate::SharedStream::new(transport);
    let mut records = TlsRecordStream::new(Box::pin(io.clone()));
    let mut auth_key = [0u8; AUTH_KEY_SIZE];
    let mut hello = build_hello(server_name, alpn);
    derive_auth_key(
        &mut auth_key,
        &hello.private_key,
        &public,
        &hello.handshake[6..38],
    )?;
    let sid = parse_short_id(short_id)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    seal_session_id(&mut hello.handshake, &auth_key, &sid, now, CLIENT_VERSION)?;
    records
        .write_record(ContentType::Handshake, &hello.handshake)
        .await?;

    let mut reader = HandshakeReader::default();
    let server_hello = reader.next(&mut records).await?;
    if server_hello.ty != 2 {
        return Err(hs_err(format!("Expected a ServerHello, got {}", server_hello.ty)));
    }
    let parsed = parse_server_hello(&server_hello.raw, &hello.handshake)?;
    if reader.has_buffered() {
        return Err(hs_err(
            "The peer sent unencrypted handshake bytes after its ServerHello.",
        ));
    }

    let mut transcript = Transcript::new(parsed.suite.hash);
    transcript.update(&hello.handshake);
    transcript.update(&server_hello.raw);

    let shared = x25519_agree(&hello.private_key, &parsed.key_share);
    let hlen = parsed.suite.hash.len();
    let mut handshake_secret = vec![0u8; hlen];
    let mut c_hs = vec![0u8; hlen];
    let mut s_hs = vec![0u8; hlen];
    let mut master = vec![0u8; hlen];
    derive_handshake_secrets(
        parsed.suite.hash,
        &shared,
        &transcript.current(),
        &mut handshake_secret,
        &mut c_hs,
        &mut s_hs,
        &mut master,
    );

    records.read = Some(RecordProtection::new(parsed.suite, &s_hs));

    let mut leaf = None;
    let mut finished = false;
    let mut flight = 0;
    while !finished {
        let msg = reader.next(&mut records).await?;
        flight += 1;
        if flight > MAX_FLIGHT {
            return Err(hs_err(format!(
                "The server sent more than {MAX_FLIGHT} handshake messages without a Finished."
            )));
        }
        match msg.ty {
            8 | 15 => transcript.update(&msg.raw),
            11 => {
                leaf = Some(extract_leaf(&msg.body)?);
                transcript.update(&msg.raw);
            }
            20 => {
                verify_finished(parsed.suite.hash, &s_hs, &transcript.current(), &msg.body)?;
                finished = true;
                transcript.update(&msg.raw);
            }
            13 => {
                return Err(hs_err(
                    "The server asked for a client certificate, which this client does not implement.",
                ));
            }
            other => return Err(hs_err(format!("Unexpected {other} in the server's handshake flight."))),
        }
    }
    let cert = leaf.ok_or_else(|| hs_err("The server sent no certificate."))?;
    assert_reality(&cert, &auth_key, server_name)?;
    let after = transcript.current();

    records
        .write_record(ContentType::ChangeCipherSpec, &[1])
        .await?;
    records.write = Some(RecordProtection::new(parsed.suite, &c_hs));
    let fin = build_finished(parsed.suite.hash, &c_hs, &after);
    records.write_record(ContentType::Handshake, &fin).await?;

    let mut c_ap = vec![0u8; hlen];
    let mut s_ap = vec![0u8; hlen];
    derive_secret(parsed.suite.hash, &master, b"c ap traffic", &after, &mut c_ap);
    derive_secret(parsed.suite.hash, &master, b"s ap traffic", &after, &mut s_ap);
    records.write = Some(RecordProtection::new(parsed.suite, &c_ap));
    records.read = Some(RecordProtection::new(parsed.suite, &s_ap));

    Ok(RealityTlsStream::new(records, reader.leftover, io))
}

struct Transcript {
    hash: HashKind,
    data: Vec<u8>,
}

impl Transcript {
    fn new(hash: HashKind) -> Self {
        Self {
            hash,
            data: Vec::new(),
        }
    }
    fn update(&mut self, m: &[u8]) {
        self.data.extend_from_slice(m);
    }
    fn current(&self) -> Vec<u8> {
        self.hash.digest(&self.data)
    }
}

fn derive_handshake_secrets(
    hash: HashKind,
    shared: &[u8],
    transcript: &[u8],
    handshake_secret: &mut [u8],
    client: &mut [u8],
    server: &mut [u8],
    master: &mut [u8],
) {
    let zeros = vec![0u8; hash.len()];
    let empty = hash.empty();
    let early = extract(hash, &zeros, &zeros);
    let mut derived = vec![0u8; hash.len()];
    derive_secret(hash, &early, b"derived", &empty, &mut derived);
    let hs = extract(hash, &derived, shared);
    handshake_secret.copy_from_slice(&hs);
    derive_secret(hash, &hs, b"c hs traffic", transcript, client);
    derive_secret(hash, &hs, b"s hs traffic", transcript, server);
    derive_secret(hash, &hs, b"derived", &empty, &mut derived);
    let ms = extract(hash, &derived, &zeros);
    master.copy_from_slice(&ms);
}

fn verify_finished(hash: HashKind, traffic: &[u8], transcript: &[u8], body: &[u8]) -> Result<(), ProxyError> {
    let mut expected = vec![0u8; hash.len()];
    finished_verify(hash, traffic, transcript, &mut expected);
    if body != expected {
        return Err(auth_err(
            "The server's Finished did not verify. The peer does not hold the private key for the key_share it sent.",
        ));
    }
    Ok(())
}

fn build_finished(hash: HashKind, traffic: &[u8], transcript: &[u8]) -> Vec<u8> {
    let mut msg = vec![0u8; 4 + hash.len()];
    msg[0] = 20;
    msg[2] = (hash.len() >> 8) as u8;
    msg[3] = hash.len() as u8;
    finished_verify(hash, traffic, transcript, &mut msg[4..]);
    msg
}

fn assert_reality(cert: &[u8], auth_key: &[u8], sni: &str) -> Result<(), ProxyError> {
    let (pk, sig) = read_ed25519_cert(cert).ok_or_else(|| {
        auth_err(format!(
            "The peer presented an ordinary certificate for '{sni}' rather than a REALITY one. The handshake was relayed to the real site — check the public key, the short id and the clock."
        ))
    })?;
    if !verify_certificate(auth_key, &pk, &sig) {
        return Err(auth_err(
            "The peer's certificate is not bound to our REALITY shared secret. Refusing to tunnel.",
        ));
    }
    Ok(())
}

fn read_ed25519_cert(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // Certificate ::= SEQUENCE { tbs SEQUENCE, sigAlg, signature BIT STRING }
    let mut outer = Der::new(der);
    let cert = outer.read_seq()?;
    let mut c = Der::new(cert);
    let tbs = c.read_seq()?;
    let mut t = Der::new(tbs);
    if t.peek_tag() == Some(0xA0) {
        t.skip_value()?;
    }
    t.skip_value()?; // serial
    t.skip_value()?; // sigalg
    t.skip_value()?; // issuer
    t.skip_value()?; // validity
    t.skip_value()?; // subject
    let spki = t.read_seq()?;
    let mut s = Der::new(spki);
    let alg = s.read_seq()?;
    let mut a = Der::new(alg);
    let oid = a.read_oid()?;
    if oid != [0x2B, 0x65, 0x70] {
        return None; // 1.3.101.112
    }
    let pk = s.read_bitstring()?;
    c.skip_value()?; // signatureAlgorithm
    let sig = c.read_bitstring()?;
    if pk.len() != 32 {
        return None;
    }
    Some((pk, sig))
}

struct Der<'a> {
    data: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }
    fn read_len_at(&self, i: usize) -> Option<(usize, usize)> {
        let b = *self.data.get(i)?;
        if b < 0x80 {
            return Some((b as usize, 1));
        }
        let n = (b & 0x7F) as usize;
        if n == 0 || n > 4 || i + n >= self.data.len() {
            return None;
        }
        let mut len = 0usize;
        for j in 0..n {
            len = (len << 8) | self.data[i + 1 + j] as usize;
        }
        Some((len, 1 + n))
    }
    fn take_tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.data.first()?;
        let (len, llen) = self.read_len_at(1)?;
        let start = 1 + llen;
        if self.data.len() < start + len {
            return None;
        }
        let body = &self.data[start..start + len];
        self.data = &self.data[start + len..];
        Some((tag, body))
    }
    fn read_seq(&mut self) -> Option<&'a [u8]> {
        let (tag, body) = self.take_tlv()?;
        if tag != 0x30 {
            return None;
        }
        Some(body)
    }
    fn skip_value(&mut self) -> Option<()> {
        self.take_tlv().map(|_| ())
    }
    fn read_oid(&mut self) -> Option<&'a [u8]> {
        let (tag, body) = self.take_tlv()?;
        if tag != 0x06 {
            return None;
        }
        Some(body)
    }
    fn read_bitstring(&mut self) -> Option<Vec<u8>> {
        let (tag, body) = self.take_tlv()?;
        if tag != 0x03 || body.is_empty() {
            return None;
        }
        Some(body[1..].to_vec())
    }
}

struct ServerHello {
    suite: CipherSuite,
    key_share: [u8; 32],
}

fn parse_server_hello(raw: &[u8], client_hello: &[u8]) -> Result<ServerHello, ProxyError> {
    if raw.len() < 4 {
        return Err(hs_err("short ServerHello"));
    }
    let mut body = &raw[4..];
    let vr = take(&mut body, 34, "the version and random")?;
    if vr[2..] == HRR {
        return Err(hs_err(
            "The server sent a HelloRetryRequest, which this client does not implement.",
        ));
    }
    let sid_len = take(&mut body, 1, "the session id length")?[0] as usize;
    let echo = take(&mut body, sid_len, "the session id")?;
    let sent = &client_hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_SIZE];
    if echo != sent {
        return Err(hs_err(
            "The server echoed a different session id than we sent. The ClientHello was altered in flight.",
        ));
    }
    let suite_id = u16::from_be_bytes(take(&mut body, 2, "the cipher suite")?.try_into().unwrap());
    if take(&mut body, 1, "the compression method")?[0] != 0 {
        return Err(hs_err("The server selected a compression method; TLS 1.3 has none."));
    }
    let suite = CipherSuite::from_id(suite_id).ok_or_else(|| {
        hs_err(format!(
            "The server chose cipher suite 0x{suite_id:04X}, which we did not offer."
        ))
    })?;
    let ext_len = u16::from_be_bytes(take(&mut body, 2, "the extensions length")?.try_into().unwrap()) as usize;
    let mut exts = take(&mut body, ext_len, "the extensions")?;
    let mut key_share = None;
    let mut tls13 = false;
    while !exts.is_empty() {
        let ty = u16::from_be_bytes(take(&mut exts, 2, "an extension type")?.try_into().unwrap());
        let len = u16::from_be_bytes(take(&mut exts, 2, "an extension length")?.try_into().unwrap()) as usize;
        let data = take(&mut exts, len, "extension")?;
        match ty {
            43 if data.len() == 2 && data == [0x03, 0x04] => tls13 = true,
            51 if data.len() >= 4 => {
                let group = u16::from_be_bytes([data[0], data[1]]);
                let sl = u16::from_be_bytes([data[2], data[3]]) as usize;
                if group == 0x001D && sl == 32 && data.len() >= 4 + sl {
                    let mut ks = [0u8; 32];
                    ks.copy_from_slice(&data[4..36]);
                    key_share = Some(ks);
                }
            }
            _ => {}
        }
    }
    if !tls13 {
        return Err(hs_err("The server did not select TLS 1.3."));
    }
    let key_share = key_share.ok_or_else(|| hs_err("The server's key_share is missing or is not X25519."))?;
    Ok(ServerHello { suite, key_share })
}

fn take<'a>(src: &mut &'a [u8], n: usize, what: &str) -> Result<&'a [u8], ProxyError> {
    if src.len() < n {
        return Err(hs_err(format!(
            "The peer's message ended before {what}: needed {n} more bytes, had {}.",
            src.len()
        )));
    }
    let (a, b) = src.split_at(n);
    *src = b;
    Ok(a)
}

fn read_u24(s: &[u8]) -> usize {
    ((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize
}

fn extract_leaf(body: &[u8]) -> Result<Vec<u8>, ProxyError> {
    let mut span = body;
    let ctx_len = take(&mut span, 1, "the certificate request context length")?[0] as usize;
    take(&mut span, ctx_len, "the certificate request context")?;
    let list_len = read_u24(take(&mut span, 3, "the certificate list length")?);
    let mut list = take(&mut span, list_len, "the certificate list")?;
    if list.is_empty() {
        return Err(hs_err("The server sent an empty certificate list."));
    }
    let cert_len = read_u24(take(&mut list, 3, "the leaf certificate length")?);
    Ok(take(&mut list, cert_len, "the leaf certificate")?.to_vec())
}

#[derive(Default)]
struct HandshakeReader {
    buf: Vec<u8>,
    leftover: Vec<u8>,
}

impl HandshakeReader {
    fn has_buffered(&self) -> bool {
        !self.buf.is_empty()
    }

    async fn next(&mut self, records: &mut TlsRecordStream) -> Result<HsMsg, ProxyError> {
        loop {
            if let Some(m) = self.try_take() {
                return Ok(m);
            }
            let rec = records.read_record().await.map_err(|e| {
                if e.code == ProxyErrorCode::ConnectionFailed {
                    ProxyError::new(
                        ProxyErrorCode::ConnectionFailed,
                        "The server closed the connection in the middle of the TLS handshake. For a REALITY server that usually means it did not accept the client: check pbk, sid and sni, and that this machine's clock is roughly right.",
                    )
                } else {
                    e
                }
            })?;
            match rec.ty {
                ContentType::ChangeCipherSpec => continue,
                ContentType::Alert => {
                    return Err(hs_err(if rec.payload.len() >= 2 {
                        format!(
                            "The server sent a {} TLS alert, description {}.",
                            if rec.payload[0] == 2 { "fatal" } else { "warning" },
                            rec.payload[1]
                        )
                    } else {
                        "The server sent a malformed alert.".into()
                    }));
                }
                ContentType::ApplicationData if records.read.is_none() => {
                    return Err(hs_err(
                        "The peer sent application data before its keys were established.",
                    ));
                }
                ContentType::ApplicationData => {
                    self.leftover.extend_from_slice(&rec.payload);
                }
                ContentType::Handshake => {
                    if rec.payload.is_empty() {
                        return Err(hs_err(
                            "The peer sent a zero-length handshake record, which TLS 1.3 forbids.",
                        ));
                    }
                    self.buf.extend_from_slice(&rec.payload);
                }
            }
        }
    }

    fn try_take(&mut self) -> Option<HsMsg> {
        if self.buf.len() < 4 {
            return None;
        }
        let body_len = ((self.buf[1] as usize) << 16) | ((self.buf[2] as usize) << 8) | self.buf[3] as usize;
        if self.buf.len() < 4 + body_len {
            return None;
        }
        let raw = self.buf.drain(..4 + body_len).collect::<Vec<_>>();
        Some(HsMsg {
            ty: raw[0],
            body: raw[4..].to_vec(),
            raw,
        })
    }
}

struct HsMsg {
    ty: u8,
    raw: Vec<u8>,
    body: Vec<u8>,
}
