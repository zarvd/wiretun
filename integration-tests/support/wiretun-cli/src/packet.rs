use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use tracing::debug;

/// Returns a new packet with the source and destination IP addresses swapped.
/// # Arguments
/// * `buf` - IP packet to be echoed, and the payload should be UDP packet.
///
/// # Panics
/// This function will panic if the packet is not an IP packet.
pub fn echo_udp_packet(buf: Vec<u8>, prefix: &[u8]) -> Vec<u8> {
    let mut output_ipv4 = MutableIpv4Packet::owned(vec![0; buf.len() + prefix.len()]).unwrap();
    let input_ipv4 = Ipv4Packet::owned(buf).unwrap();

    output_ipv4.set_source(input_ipv4.get_destination());
    output_ipv4.set_destination(input_ipv4.get_source());
    output_ipv4.set_version(input_ipv4.get_version());
    output_ipv4.set_dscp(input_ipv4.get_dscp());
    output_ipv4.set_flags(input_ipv4.get_flags());
    output_ipv4.set_ecn(input_ipv4.get_ecn());
    output_ipv4.set_header_length(input_ipv4.get_header_length());
    output_ipv4.set_total_length(input_ipv4.get_total_length() + prefix.len() as u16);
    output_ipv4.set_identification(input_ipv4.get_identification());
    output_ipv4.set_fragment_offset(input_ipv4.get_fragment_offset());
    output_ipv4.set_next_level_protocol(input_ipv4.get_next_level_protocol());
    output_ipv4.set_options(&input_ipv4.get_options());

    match output_ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Udp => {
            let input_udp = UdpPacket::owned(input_ipv4.payload().to_vec()).unwrap();
            let mut output_udp =
                MutableUdpPacket::owned(vec![0; input_ipv4.payload().len() + prefix.len()])
                    .unwrap();

            output_udp.set_source(input_udp.get_destination());
            output_udp.set_destination(input_udp.get_source());
            output_udp.set_payload(&{
                let mut p = prefix.to_vec();
                p.extend_from_slice(input_udp.payload());
                p
            });
            output_udp.set_length(input_udp.get_length() + prefix.len() as u16);
            output_udp.set_checksum(ipv4_checksum(
                &output_udp.to_immutable(),
                &output_ipv4.get_source(),
                &output_ipv4.get_destination(),
            ));

            output_ipv4.set_payload(output_udp.packet());
        }
        _ => {
            debug!("Unknown packet type!");
        }
    }

    output_ipv4.set_checksum(checksum(&output_ipv4.to_immutable()));

    output_ipv4.packet().to_vec()
}
