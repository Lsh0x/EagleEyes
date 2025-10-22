use std::fs::File;
use std::io::Write;
use std::path::Path;

fn pcap_global(f: &mut File) -> std::io::Result<()> {
    f.write_all(&0xa1b2c3d4u32.to_le_bytes())?; // magic (LE)
    f.write_all(&2u16.to_le_bytes())?;
    f.write_all(&4u16.to_le_bytes())?;
    f.write_all(&0i32.to_le_bytes())?;
    f.write_all(&0u32.to_le_bytes())?;
    f.write_all(&65535u32.to_le_bytes())?;
    f.write_all(&1u32.to_le_bytes())?; // DLT_EN10MB
    Ok(())
}

fn emit_pkt(f: &mut File, payload: &[u8]) -> std::io::Result<()> {
    f.write_all(&0u32.to_le_bytes())?; // ts_sec
    f.write_all(&0u32.to_le_bytes())?; // ts_usec
    f.write_all(&(payload.len() as u32).to_le_bytes())?;
    f.write_all(&(payload.len() as u32).to_le_bytes())?;
    f.write_all(payload)?;
    Ok(())
}

fn eth_ipv4_udp(sport: u16, dport: u16, upayload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    let eth = [
        0,1,2,3,4,5, // dst
        6,7,8,9,10,11, // src
        0x08,0x00 // IPv4
    ];
    v.extend_from_slice(&eth);
    let ip_header_len = 20u16;
    let udp_len = 8 + upayload.len() as u16;
    let total_len = ip_header_len + udp_len;
    let ipv4 = [
        0x45, 0x00, // ver/ihl, tos
        (total_len>>8) as u8, (total_len&0xff) as u8,
        0,1, 0,0, // id, flags/frag
        64, 17, // ttl, proto=UDP
        0,0, // checksum (zero)
        192,168,0,1,
        192,168,0,2,
    ];
    v.extend_from_slice(&ipv4);
    v.extend_from_slice(&[(sport>>8) as u8,(sport&0xff) as u8, (dport>>8) as u8,(dport&0xff) as u8]);
    v.extend_from_slice(&[(udp_len>>8) as u8,(udp_len&0xff) as u8, 0,0]);
    v.extend_from_slice(upayload);
    v
}

fn eth_ipv4_tcp(sport: u16, dport: u16, tpayload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    let eth = [0,1,2,3,4,5, 6,7,8,9,10,11, 0x08,0x00];
    v.extend_from_slice(&eth);
    let ip_len = 20u16;
    let tcp_hdr_len = 34u16; // our struct size
    let total_len = ip_len + tcp_hdr_len + tpayload.len() as u16;
    let ipv4 = [
        0x45,0x00,
        (total_len>>8) as u8,(total_len&0xff) as u8,
        0,2, 0,0,
        64, 6, // TCP
        0,0,
        192,168,0,1,
        192,168,0,2,
    ];
    v.extend_from_slice(&ipv4);
    // TCP header (34 bytes per project)
    let mut tcp = vec![0u8;34];
    tcp[0]=(sport>>8) as u8; tcp[1]=(sport&0xff) as u8;
    tcp[2]=(dport>>8) as u8; tcp[3]=(dport&0xff) as u8;
    tcp[12]=0x50; // data offset nibble in first byte of this 4-byte field
    tcp[33]=0x02; // SYN in last byte of control_flag array
    v.extend_from_slice(&tcp);
    v.extend_from_slice(tpayload);
    v
}

fn main() -> std::io::Result<()> {
    let samples_dir = Path::new("samples");
    std::fs::create_dir_all(samples_dir)?;
    let path = samples_dir.join("proto.cap");
    let mut f = File::create(&path)?;
    pcap_global(&mut f)?;

    // SIP over UDP 5060
    let sip = b"INVITE sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP host\r\n\r\n";
    let pkt = eth_ipv4_udp(40000, 5060, sip);
    emit_pkt(&mut f, &pkt)?;

    // RTP (UDP) port 40002
    let rtp = vec![0x80, 96, 0x12, 0x34, 0,0,0,1, 0,0,0,1];
    let pkt = eth_ipv4_udp(40000, 40002, &rtp);
    emit_pkt(&mut f, &pkt)?;

    // RTCP (SR) PT=200
    let rtcp = vec![0x80, 200, 0x00, 0x06, 0,0,0,1];
    let pkt = eth_ipv4_udp(40000, 40003, &rtcp);
    emit_pkt(&mut f, &pkt)?;

    // SMB over TCP/445
    let smb = b"\xFFSMB";
    let pkt = eth_ipv4_tcp(50000, 445, smb);
    emit_pkt(&mut f, &pkt)?;

    // Syslog UDP/514
    let syslog = b"<13>Oct  1 12:00:00 host app: test";
    let pkt = eth_ipv4_udp(40000, 514, syslog);
    emit_pkt(&mut f, &pkt)?;

    // SNMP UDP/161
    let snmp = [0x30, 0x10, 0x02, 0x01, 0x01];
    let pkt = eth_ipv4_udp(40000, 161, &snmp);
    emit_pkt(&mut f, &pkt)?;

    eprintln!("Wrote {}", path.display());
    Ok(())
}