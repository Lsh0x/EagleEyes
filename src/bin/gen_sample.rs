use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() -> std::io::Result<()> {
    let samples_dir = Path::new("samples");
    std::fs::create_dir_all(samples_dir)?;
    let path = samples_dir.join("http.cap");
    let mut f = File::create(&path)?;

    // pcap global header (little-endian)
    f.write_all(&0xa1b2c3d4u32.to_le_bytes())?; // magic
    f.write_all(&2u16.to_le_bytes())?; // major
    f.write_all(&4u16.to_le_bytes())?; // minor
    f.write_all(&0i32.to_le_bytes())?; // thiszone
    f.write_all(&0u32.to_le_bytes())?; // sigfigs
    f.write_all(&65535u32.to_le_bytes())?; // snaplen
    f.write_all(&1u32.to_le_bytes())?; // linktype: DLT_EN10MB

    // Build a minimal Ethernet(IPv4/TCP) frame
    let eth: [u8; 14] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src
        0x08, 0x00, // EtherType IPv4
    ];

    let ipv4: [u8; 20] = [
        0x45, 0x00, // version=4, IHL=5; TOS
        0x00, 0x36, // total length = 54 bytes (IP + TCP)
        0x12, 0x34, // identification
        0x00, 0x00, // flags+frag offset
        0x40, // TTL
        0x06, // protocol TCP
        0x00, 0x00, // checksum (0 for demo)
        0xC0, 0xA8, 0x00, 0x01, // src 192.168.0.1
        0xC0, 0xA8, 0x00, 0x02, // dst 192.168.0.2
    ];

    // 34 bytes per this project's TCP header struct size
    let tcp: [u8; 34] = [
        0x00, 0x50, // src port 80
        0x01, 0xbb, // dst port 443
        0x00, 0x00, 0x00, 0x00, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x00, 0x00, 0x00, // data_offset (dummy 4 bytes)
        0x00, 0x00, 0x00, // reserved
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, // control_flag (dummy, set SYN bit in last byte)
        0x10, 0x00, // win size
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent ptr
    ];

    let mut pkt = Vec::with_capacity(eth.len() + ipv4.len() + tcp.len());
    pkt.extend_from_slice(&eth);
    pkt.extend_from_slice(&ipv4);
    pkt.extend_from_slice(&tcp);

    // pcap packet header
    f.write_all(&0u32.to_le_bytes())?; // ts_sec
    f.write_all(&0u32.to_le_bytes())?; // ts_usec
    f.write_all(&(pkt.len() as u32).to_le_bytes())?; // incl_len
    f.write_all(&(pkt.len() as u32).to_le_bytes())?; // orig_len

    // packet data
    f.write_all(&pkt)?;

    eprintln!("Wrote {} bytes to {}", pkt.len(), path.display());
    Ok(())
}
