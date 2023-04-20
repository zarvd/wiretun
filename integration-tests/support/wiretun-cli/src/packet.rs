use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, MutableIpv4Packet};
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket};
use pnet::packet::Packet;
use tracing::debug;

/// Returns a new packet with the source and destination IP addresses swapped.
/// # Arguments
/// * `buf` - IP packet to be echoed, and the payload should be UDP packet.
///
/// # Panics
/// This function will panic if the packet is not an IP packet.
pub fn echo_udp_packet(mut buf: Vec<u8>) -> Vec<u8> {
    let mut ipv4 = MutableIpv4Packet::new(&mut buf).unwrap();
    let src_ip = ipv4.get_source();
    let dst_ip = ipv4.get_destination();
    ipv4.set_source(dst_ip);
    ipv4.set_destination(src_ip);

    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Udp => {
            let mut udp = MutableUdpPacket::owned(ipv4.payload().to_vec()).unwrap();
            let src_port = udp.get_source();
            let dst_port = udp.get_destination();
            udp.set_source(dst_port);
            udp.set_destination(src_port);
            udp.set_checksum(ipv4_checksum(&udp.to_immutable(), &dst_ip, &src_ip));
            let mut payload = vec![];
            payload.extend_from_slice(b"from-peer2->");
            payload.extend_from_slice(udp.packet());
            ipv4.set_payload(&payload);
        }
        _ => {
            debug!("Unknown packet type!");
        }
    }

    ipv4.set_checksum(checksum(&ipv4.to_immutable()));

    ipv4.packet().to_vec()
}
