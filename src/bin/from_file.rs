use eagleeyes::protocols::{ethernet, ip, loopback};
use eagleeyes::utils::cow_struct;
use pcap::Capture;
use std::env;
use std::fs::File;
use std::io::Read;
use std::process;

fn sniff_format(path: &str) -> std::io::Result<Option<&'static str>> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    if n < 4 {
        return Ok(None);
    }
    let m_be = u32::from_be_bytes(magic);
    let m_le = u32::from_le_bytes(magic);
    // Classic pcap
    if m_be == 0xA1B2C3D4 || m_le == 0xA1B2C3D4 {
        return Ok(Some("pcap"));
    }
    // Nanosecond-resolution pcap
    if m_be == 0xA1B23C4D || m_le == 0xA1B23C4D {
        return Ok(Some("pcap (ns)"));
    }
    // pcapng
    if m_be == 0x0A0D0D0A {
        return Ok(Some("pcapng"));
    }
    Ok(None)
}

fn looks_like_pcap_or_pcapng(path: &str) -> std::io::Result<bool> {
    Ok(sniff_format(path)?.is_some())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("usage: {:?} <pcap_file>", args[0]);
        process::exit(1);
    }

    match Capture::from_file(args[1].as_str()) {
        Ok(mut cap) => {
            // Basic capture metadata
            let dl = cap.get_datalink();
            println!("input: {}", args[1]);
            match sniff_format(&args[1]) {
                Ok(Some(fmt)) => println!("format: {}", fmt),
                Ok(None) => println!("format: unknown"),
                Err(_) => {}
            }
            println!("datalink: {:?}", dl);

            // Stats while decoding
            let mut packets: u64 = 0;
            let mut bytes: u64 = 0;
            let mut first_ts: Option<(i64, i64)> = None;
            let mut last_ts: Option<(i64, i64)> = None;

            let dlt = cap.get_datalink().0 as i32;
            while let Ok(packet) = cap.next() {
                let ts_sec = packet.header.ts.tv_sec as i64;
                let ts_usec = packet.header.ts.tv_usec as i64;
                let caplen = packet.header.caplen as u32;
                let plen = packet.header.len as u32;
                if first_ts.is_none() {
                    first_ts = Some((ts_sec, ts_usec));
                }
                last_ts = Some((ts_sec, ts_usec));
                bytes += plen as u64;
                packets += 1;

                // Per-packet summary
                print!(
                    "pkt {} ts={}.{} caplen={} len={} ",
                    packets, ts_sec, ts_usec, caplen, plen
                );

                // Minimal L2/L3/L4 insight
                if packet.data.len() >= ethernet::Header::SIZE {
                    let (eth_hdr_bytes, eth_payload) = packet.data.split_at(ethernet::Header::SIZE);
                    if let Some(eth_hdr) = cow_struct::<ethernet::Header>(eth_hdr_bytes) {
                        let et = eth_hdr.ether_type.to_be();
                        print!("eth_type={} ", ethernet::ether_type_as_str(et));
                        if et == ethernet::PROTO::IPV4
                            && eth_payload.len() >= eagleeyes::protocols::ipv4::Header::SIZE
                        {
                            let (ip_hdr_bytes, ip_payload) =
                                eth_payload.split_at(eagleeyes::protocols::ipv4::Header::SIZE);
                            if let Some(ip_hdr) =
                                cow_struct::<eagleeyes::protocols::ipv4::Header>(ip_hdr_bytes)
                            {
                                let ihl_bytes: usize =
                                    ((ip_hdr.version_and_header_len & 0xF) * 4) as usize;
                                let total_len = ip_hdr.total_len.to_be();
                                // IPv4 addr formatting
                                let src = ip_hdr.src.to_be_bytes();
                                let dst = ip_hdr.dst.to_be_bytes();
                                let proto = ip_hdr.protocol;
                                print!(
                                    "ipv4 {}.{}.{}.{} -> {}.{}.{}.{} proto={} total_len={} ",
                                    src[0],
                                    src[1],
                                    src[2],
                                    src[3],
                                    dst[0],
                                    dst[1],
                                    dst[2],
                                    dst[3],
                                    ip::protocol_as_str(proto),
                                    total_len
                                );
                                // L4: TCP ports if present
                                if proto == ip::PROTO::TCP
                                    && ip_payload.len()
                                        >= ihl_bytes + eagleeyes::protocols::tcp::Header::SIZE
                                {
                                    let l4 = &ip_payload[ihl_bytes..];
                                    let (tcp_hdr_bytes, _rest) =
                                        l4.split_at(eagleeyes::protocols::tcp::Header::SIZE);
                                    if let Some(tcp_hdr) =
                                        cow_struct::<eagleeyes::protocols::tcp::Header>(
                                            tcp_hdr_bytes,
                                        )
                                    {
                                        print!(
                                            "tcp {} -> {} ",
                                            tcp_hdr.src_port.to_be(),
                                            tcp_hdr.dest_port.to_be()
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                println!("");

                // Dispatch by datalink
                match dlt {
                    1 => ethernet::decode(packet.data),       // EN10MB
                    0 | 108 => loopback::decode(packet.data), // NULL/LOOP
                    101 => {
                        // RAW IP
                        if packet.data.len() >= 1 {
                            let v = (packet.data[0] & 0xF0) >> 4;
                            if v == 4 {
                                eagleeyes::protocols::ipv4::decode(packet.data);
                            } else if v == 6 {
                                eagleeyes::protocols::ipv6::decode(packet.data);
                            } else {
                                println!("RAW ({}B)", packet.data.len());
                            }
                        }
                    }
                    227 => eagleeyes::protocols::can::decode(packet.data),
                    239 => eagleeyes::protocols::nflog::decode(packet.data),
                    187 | 201 => eagleeyes::protocols::bluetooth::decode(packet.data),
                    189 | 220 => eagleeyes::protocols::usb::decode(packet.data),
                    212 => eagleeyes::protocols::lin::decode(packet.data),
                    _ => ethernet::decode(packet.data),
                }
            }

            println!("summary: packets={}, bytes={}", packets, bytes);
            if let Some((s, us)) = first_ts {
                println!("first_ts: {}.{}", s, us);
            }
            if let Some((s, us)) = last_ts {
                println!("last_ts: {}.{}", s, us);
            }
        }
        Err(e) => {
            // Provide a clearer hint if the input does not look like a pcap/pcapng file
            let hint = looks_like_pcap_or_pcapng(&args[1])
                .map(|ok| !ok)
                .unwrap_or(true);
            if hint {
                eprintln!(
                    "file does not look like a pcap/pcapng: {}\n- Pass a real capture file (e.g., tcpdump -i <iface> -w out.pcap)\n- Or try the sample: cargo run --bin from_file samples/http.cap\nOriginal error: {:?}",
                    args[1], e
                );
            } else {
                eprintln!("error opening pcap: {:?}", e);
            }
            process::exit(2);
        }
    }
}
