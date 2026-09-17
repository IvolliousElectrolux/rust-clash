use rand::RngCore;

use crate::reality::auth::{SESSION_ID_SIZE, x25519_generate};
use crate::reality::writer::TlsWriter;

pub struct ClientHello {
    pub handshake: Vec<u8>,
    pub private_key: [u8; 32],
}

pub fn build(server_name: &str, alpn: &[String]) -> ClientHello {
    let (private_key, public_key) = x25519_generate();
    let mut w = TlsWriter::new(1024);
    w.write_u8(1);
    let body = w.begin_vector24();
    w.write_u16(0x0303);
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);
    w.write_bytes(&random);
    w.write_u8(SESSION_ID_SIZE as u8);
    w.write_zeros(SESSION_ID_SIZE);
    let suites = w.begin_vector16();
    w.write_u16(0x1301);
    w.write_u16(0x1302);
    w.write_u16(0x1303);
    w.end_vector(suites, 2);
    let comp = w.begin_vector8();
    w.write_u8(0);
    w.end_vector(comp, 1);
    let exts = w.begin_vector16();
    write_sni(&mut w, server_name);
    write_groups(&mut w);
    write_sigalgs(&mut w);
    write_versions(&mut w);
    write_psk(&mut w);
    write_key_share(&mut w, &public_key);
    if !alpn.is_empty() {
        write_alpn(&mut w, alpn);
    }
    w.end_vector(exts, 2);
    w.end_vector(body, 3);
    ClientHello {
        handshake: w.into_vec(),
        private_key,
    }
}

fn write_sni(w: &mut TlsWriter, name: &str) {
    let ascii = to_alabel(name);
    w.write_u16(0);
    let ext = w.begin_vector16();
    let list = w.begin_vector16();
    w.write_u8(0);
    let n = w.begin_vector16();
    w.write_bytes(ascii.as_bytes());
    w.end_vector(n, 2);
    w.end_vector(list, 2);
    w.end_vector(ext, 2);
}

fn to_alabel(name: &str) -> String {
    if name.bytes().all(|b| b < 128) {
        return name.to_string();
    }
    idna::domain_to_ascii(name).unwrap_or_else(|_| name.to_string())
}

fn write_groups(w: &mut TlsWriter) {
    w.write_u16(10);
    let ext = w.begin_vector16();
    let g = w.begin_vector16();
    w.write_u16(0x001D);
    w.end_vector(g, 2);
    w.end_vector(ext, 2);
}

fn write_sigalgs(w: &mut TlsWriter) {
    w.write_u16(13);
    let ext = w.begin_vector16();
    let a = w.begin_vector16();
    for id in [0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601] {
        w.write_u16(id);
    }
    w.end_vector(a, 2);
    w.end_vector(ext, 2);
}

fn write_versions(w: &mut TlsWriter) {
    w.write_u16(43);
    let ext = w.begin_vector16();
    let v = w.begin_vector8();
    w.write_u16(0x0304);
    w.end_vector(v, 1);
    w.end_vector(ext, 2);
}

fn write_psk(w: &mut TlsWriter) {
    w.write_u16(45);
    let ext = w.begin_vector16();
    let m = w.begin_vector8();
    w.write_u8(1);
    w.end_vector(m, 1);
    w.end_vector(ext, 2);
}

fn write_key_share(w: &mut TlsWriter, pk: &[u8; 32]) {
    w.write_u16(51);
    let ext = w.begin_vector16();
    let shares = w.begin_vector16();
    w.write_u16(0x001D);
    let share = w.begin_vector16();
    w.write_bytes(pk);
    w.end_vector(share, 2);
    w.end_vector(shares, 2);
    w.end_vector(ext, 2);
}

fn write_alpn(w: &mut TlsWriter, alpn: &[String]) {
    w.write_u16(16);
    let ext = w.begin_vector16();
    let list = w.begin_vector16();
    for p in alpn {
        let e = w.begin_vector8();
        w.write_bytes(p.as_bytes());
        w.end_vector(e, 1);
    }
    w.end_vector(list, 2);
    w.end_vector(ext, 2);
}
