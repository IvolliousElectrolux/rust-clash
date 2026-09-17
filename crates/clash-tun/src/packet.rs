use std::net::Ipv4Addr;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const IP_HDR_MIN: usize = 20;
pub const UDP_HDR: usize = 8;
pub const TCP_HDR_MIN: usize = 20;

pub fn parse_ipv4(
    packet: &[u8],
) -> Option<(usize, u8, Ipv4Addr, Ipv4Addr, usize)> {
    if packet.len() < IP_HDR_MIN {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = ((packet[0] & 0x0F) as usize) * 4;
    if header_len < IP_HDR_MIN || packet.len() < header_len {
        return None;
    }
    let mut total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len || total_len > packet.len() {
        total_len = packet.len();
    }
    let proto = packet[9];
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some((header_len, proto, src, dst, total_len))
}

pub fn set_addresses(packet: &mut [u8], header_len: usize, src: Ipv4Addr, dst: Ipv4Addr) {
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    update_ip_checksum(packet, header_len);
}

pub fn set_total_length(packet: &mut [u8], total_len: u16) {
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    let header_len = ((packet[0] & 0x0F) as usize) * 4;
    update_ip_checksum(packet, header_len);
}

fn update_ip_checksum(packet: &mut [u8], header_len: usize) {
    packet[10] = 0;
    packet[11] = 0;
    let sum = fold(sum_words(&packet[..header_len]));
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
}

pub fn parse_udp(segment: &[u8]) -> Option<(u16, u16, usize)> {
    if segment.len() < UDP_HDR {
        return None;
    }
    let src = u16::from_be_bytes([segment[0], segment[1]]);
    let dst = u16::from_be_bytes([segment[2], segment[3]]);
    let mut udp_len = u16::from_be_bytes([segment[4], segment[5]]) as usize;
    if udp_len < UDP_HDR || udp_len > segment.len() {
        udp_len = segment.len();
    }
    Some((src, dst, udp_len - UDP_HDR))
}

pub fn write_udp(
    segment: &mut [u8],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
) {
    let udp_len = UDP_HDR + payload.len();
    segment[0..2].copy_from_slice(&src_port.to_be_bytes());
    segment[2..4].copy_from_slice(&dst_port.to_be_bytes());
    segment[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    segment[6] = 0;
    segment[7] = 0;
    segment[UDP_HDR..udp_len].copy_from_slice(payload);
    let mut sum = 0u32;
    add_ip(&mut sum, src);
    add_ip(&mut sum, dst);
    sum += PROTO_UDP as u32;
    sum += udp_len as u32;
    sum += sum_words(&segment[..udp_len]);
    let mut csum = fold(sum);
    if csum == 0 {
        csum = 0xFFFF;
    }
    segment[6..8].copy_from_slice(&csum.to_be_bytes());
}

pub fn parse_tcp(segment: &[u8]) -> Option<(u16, u16, u8, usize)> {
    if segment.len() < TCP_HDR_MIN {
        return None;
    }
    let src = u16::from_be_bytes([segment[0], segment[1]]);
    let dst = u16::from_be_bytes([segment[2], segment[3]]);
    let data_off = ((segment[12] >> 4) as usize) * 4;
    if data_off < TCP_HDR_MIN || data_off > segment.len() {
        return None;
    }
    Some((src, dst, segment[13], data_off))
}

pub fn set_tcp_ports(segment: &mut [u8], src: u16, dst: u16) {
    segment[0..2].copy_from_slice(&src.to_be_bytes());
    segment[2..4].copy_from_slice(&dst.to_be_bytes());
}

pub fn update_tcp_checksum(packet: &mut [u8], ip_hdr_len: usize, src: Ipv4Addr, dst: Ipv4Addr) {
    let mut total_len = packet.len();
    let hdr_total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if hdr_total >= ip_hdr_len && hdr_total <= packet.len() {
        total_len = hdr_total;
    }
    let tcp_len = total_len - ip_hdr_len;
    if tcp_len < TCP_HDR_MIN {
        return;
    }
    packet[ip_hdr_len + 16] = 0;
    packet[ip_hdr_len + 17] = 0;
    let mut sum = 0u32;
    add_ip(&mut sum, src);
    add_ip(&mut sum, dst);
    sum += PROTO_TCP as u32;
    sum += tcp_len as u32;
    sum += sum_words(&packet[ip_hdr_len..ip_hdr_len + tcp_len]);
    let csum = fold(sum);
    packet[ip_hdr_len + 16..ip_hdr_len + 18].copy_from_slice(&csum.to_be_bytes());
}

fn add_ip(sum: &mut u32, ip: Ipv4Addr) {
    let b = ip.octets();
    *sum += ((b[0] as u32) << 8) | b[1] as u32;
    *sum += ((b[2] as u32) << 8) | b[3] as u32;
}

fn sum_words(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn udp_checksum_nonzero() {
        let payload = b"hello";
        let mut seg = vec![0u8; UDP_HDR + payload.len()];
        let src = Ipv4Addr::new(198, 18, 0, 2);
        let dst = Ipv4Addr::new(172, 19, 0, 2);
        write_udp(&mut seg, 53, 12345, payload, src, dst);
        assert_ne!(&seg[6..8], &[0, 0]);
    }
}
