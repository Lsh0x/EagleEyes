use wasm_bindgen::prelude::*;
use serde::Serialize;

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct L2 {
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub ether_type: Option<u16>,
    pub ether_type_name: Option<String>,
    pub vlan: Option<u16>,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct L3 {
    pub proto: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
    // IPv4 specific fields
    pub version: Option<u8>,
    pub header_len: Option<u8>,
    pub tos: Option<u8>,
    pub total_len: Option<u16>,
    pub identification: Option<u16>,
    pub flags: Option<u8>,
    pub fragment_offset: Option<u16>,
    pub ttl: Option<u8>,
    pub protocol: Option<u8>,
    pub checksum: Option<u16>,
    // IPv6 specific fields
    pub traffic_class: Option<u8>,
    pub flow_label: Option<u32>,
    pub payload_len: Option<u16>,
    pub next_header: Option<u8>,
    pub hop_limit: Option<u8>,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct L4 {
    pub proto: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    // TCP specific fields
    pub tcp_flags: Option<String>,
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub tcp_window: Option<u16>,
    pub tcp_checksum: Option<u16>,
    pub tcp_urgent: Option<u16>,
    pub tcp_data_offset: Option<u8>,
    // UDP specific fields
    pub udp_len: Option<u16>,
    pub udp_checksum: Option<u16>,
    // ICMP specific fields
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub icmp_checksum: Option<u16>,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Decoded {
    pub l2: Option<L2>,
    pub l3: Option<L3>,
    pub l4: Option<L4>,
    pub summary: String,
    pub protocol_tag: String,
    pub app_tag: Option<String>,
    pub description: Option<String>,
}

fn mac_to_str(m: &[u8]) -> String {
    m.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}
fn ipv4_to_str(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn ether_type_as_str(ether_type: u16) -> &'static str {
    match ether_type {
        0x0200 => "PUP",
        0x0500 => "SPRITE",
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x8035 => "REVARP",
        0x809B => "AT",
        0x80F3 => "AARP",
        0x8100 => "VLAN",
        0x8137 => "IPX",
        0x86dd => "IPv6",
        0x88cc => "LLDP",
        0x8847 => "MPLS_U",
        0x8848 => "MPLS_M",
        0x8863 => "PPPoE-Discovery",
        0x8864 => "PPPoE-Session",
        0x9000 => "LOOPBACK",
        _ => "UNKNOWN",
    }
}

#[wasm_bindgen]
pub fn decode_packet(bytes: &[u8]) -> Result<JsValue, JsValue> {
    use eagleeyes::protocols::{ethernet, ip as ipm};

    if bytes.len() < ethernet::Header::SIZE {
        let out = Decoded { summary: format!("Truncated frame ({}B)", bytes.len()), protocol_tag: "FRAME".into(), ..Default::default() };
        return serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()));
    }

    // Ethernet II
    let (eth_hdr_bytes, rest) = bytes.split_at(ethernet::Header::SIZE);
    let mut l2 = L2::default();
    if let Some(h) = eagleeyes::utils::cow_struct::<ethernet::Header>(eth_hdr_bytes) {
        l2.src_mac = Some(mac_to_str(&h.shost));
        l2.dst_mac = Some(mac_to_str(&h.dhost));
        let mut ether_type = u16::from_be(h.ether_type);
        let mut off = ethernet::Header::SIZE;
        // VLAN (802.1Q)
        if ether_type == ethernet::PROTO::VLAN && bytes.len() >= off + 4 {
            let tci = u16::from_be_bytes([bytes[off], bytes[off + 1]]);
            l2.vlan = Some(tci & 0x0fff);
            ether_type = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]);
            off += 4;
        }
        l2.ether_type = Some(ether_type);
        l2.ether_type_name = Some(ether_type_as_str(ether_type).to_string());

        // L3
        if ether_type == ethernet::PROTO::IPV4 && bytes.len() >= off + 20 {
            // IPv4 header
            let version = (bytes[off] & 0xf0) >> 4;
            let ihl = (bytes[off] & 0x0f) as usize * 4;
            if ihl >= 20 && bytes.len() >= off + ihl {
                let proto = bytes[off + 9];
                let src = ipv4_to_str(&bytes[off + 12..off + 16]);
                let dst = ipv4_to_str(&bytes[off + 16..off + 20]);
                let tos = bytes[off + 1];
                let total_len = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]);
                let identification = u16::from_be_bytes([bytes[off + 4], bytes[off + 5]]);
                let flags_and_offset = u16::from_be_bytes([bytes[off + 6], bytes[off + 7]]);
                let flags = ((flags_and_offset >> 13) & 0x07) as u8;
                let fragment_offset = flags_and_offset & 0x1fff;
                let ttl = bytes[off + 8];
                let checksum = u16::from_be_bytes([bytes[off + 10], bytes[off + 11]]);
                let l3 = L3 {
                    proto: Some("IPv4".into()),
                    src: Some(src),
                    dst: Some(dst),
                    version: Some(version),
                    header_len: Some((ihl / 4) as u8),
                    tos: Some(tos),
                    total_len: Some(total_len),
                    identification: Some(identification),
                    flags: Some(flags),
                    fragment_offset: Some(fragment_offset),
                    ttl: Some(ttl),
                    protocol: Some(proto),
                    checksum: Some(checksum),
                    ..Default::default()
                };
                // L4
                let l4_start = off + ihl;
                let mut l4 = L4::default();
                let mut summary = String::new();
                let mut tag = String::from("IPv4");
                if proto == ipm::PROTO::TCP && bytes.len() >= l4_start + 20 {
                    let sp = u16::from_be_bytes([bytes[l4_start], bytes[l4_start + 1]]);
                    let dp = u16::from_be_bytes([bytes[l4_start + 2], bytes[l4_start + 3]]);
                    let seq = u32::from_be_bytes([bytes[l4_start + 4], bytes[l4_start + 5], bytes[l4_start + 6], bytes[l4_start + 7]]);
                    let ack = u32::from_be_bytes([bytes[l4_start + 8], bytes[l4_start + 9], bytes[l4_start + 10], bytes[l4_start + 11]]);
                    let data_offset = (bytes[l4_start + 12] >> 4) as usize * 4;
                    let flags = bytes[l4_start + 13];
                    let window = u16::from_be_bytes([bytes[l4_start + 14], bytes[l4_start + 15]]);
                    let checksum = u16::from_be_bytes([bytes[l4_start + 16], bytes[l4_start + 17]]);
                    let urgent = u16::from_be_bytes([bytes[l4_start + 18], bytes[l4_start + 19]]);
                    l4 = L4 {
                        proto: Some("TCP".into()),
                        src_port: Some(sp),
                        dst_port: Some(dp),
                        tcp_flags: Some(tcp_flags(flags)),
                        tcp_seq: Some(seq),
                        tcp_ack: Some(ack),
                        tcp_window: Some(window),
                        tcp_checksum: Some(checksum),
                        tcp_urgent: Some(urgent),
                        tcp_data_offset: Some((data_offset / 4) as u8),
                        ..Default::default()
                    };
                    summary = format!("TCP {} → {}", sp, dp);
                    tag = "TCP".into();
                    // heuristics examples (HTTP/1 start-line, TLS record)
                    let payload = if bytes.len() >= l4_start + data_offset { &bytes[l4_start + data_offset..] } else { &[] };
                    if let Some(sni) = sniff_tls_client_hello(payload) {
                        summary = if let Some(sni) = sni { format!("TLS ClientHello SNI={}", sni) } else { "TLS".into() };
                        tag = "TLS".into();
                    } else if let Some(line) = sniff_http1_first_line(payload) {
                        summary = line;
                        tag = "HTTP".into();
                    }
                } else if proto == ipm::PROTO::UDP && bytes.len() >= l4_start + 8 {
                    let sp = u16::from_be_bytes([bytes[l4_start], bytes[l4_start + 1]]);
                    let dp = u16::from_be_bytes([bytes[l4_start + 2], bytes[l4_start + 3]]);
                    let len = u16::from_be_bytes([bytes[l4_start + 4], bytes[l4_start + 5]]);
                    let checksum = u16::from_be_bytes([bytes[l4_start + 6], bytes[l4_start + 7]]);
                    l4 = L4 {
                        proto: Some("UDP".into()),
                        src_port: Some(sp),
                        dst_port: Some(dp),
                        udp_len: Some(len),
                        udp_checksum: Some(checksum),
                        ..Default::default()
                    };
                    summary = format!("UDP {} → {}", sp, dp);
                    tag = "UDP".into();
                } else if proto == ipm::PROTO::ICMP && bytes.len() >= l4_start + 8 {
                    let icmp_type = bytes[l4_start];
                    let icmp_code = bytes[l4_start + 1];
                    let checksum = u16::from_be_bytes([bytes[l4_start + 2], bytes[l4_start + 3]]);
                    l4 = L4 {
                        proto: Some("ICMP".into()),
                        icmp_type: Some(icmp_type),
                        icmp_code: Some(icmp_code),
                        icmp_checksum: Some(checksum),
                        ..Default::default()
                    };
                    summary = format!("ICMP type {} code {}", icmp_type, icmp_code);
                    tag = "ICMP".into();
                }
                let description = build_description(bytes, &l2, &l3, &l4);
                let out = Decoded { l2: Some(l2), l3: Some(l3), l4: if l4.proto.is_some() { Some(l4) } else { None }, summary, protocol_tag: tag, app_tag: None, description: Some(description) };
                return serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()));
            }
        }
        if ether_type == ethernet::PROTO::ARP {
            let out = Decoded { l2: Some(l2), summary: "ARP".into(), protocol_tag: "ARP".into(), ..Default::default() };
            return serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()));
        }
        // Fallback
        let out = Decoded { l2: Some(l2), summary: format!("Ethertype 0x{:04x}", ether_type), protocol_tag: "ETH".into(), ..Default::default() };
        return serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()));
    }

    let out = Decoded { summary: "Frame".into(), protocol_tag: "ETH".into(), ..Default::default() };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn decode_and_log(bytes: &[u8]) -> Result<(), JsValue> {
    let v = decode_packet(bytes)?;
    web_sys::console::log_1(&v);
    Ok(())
}

fn build_description(bytes: &[u8], l2: &L2, l3: &L3, l4: &L4) -> String {
    let mut lines = Vec::new();
    
    // Frame info
    let bits = bytes.len() * 8;
    lines.push(format!("Frame: Packet, {} bytes on wire ({} bits), {} bytes captured ({} bits)",
        bytes.len(), bits, bytes.len(), bits));
    
    // Ethernet II
    if let (Some(src_mac), Some(dst_mac)) = (&l2.src_mac, &l2.dst_mac) {
        let eth_line = if let Some(vlan) = l2.vlan {
            format!("Ethernet II, Src: {} ({}), Dst: {} ({}), VLAN: {}",
                src_mac, src_mac, dst_mac, dst_mac, vlan)
        } else {
            format!("Ethernet II, Src: {} ({}), Dst: {} ({})",
                src_mac, src_mac, dst_mac, dst_mac)
        };
        lines.push(eth_line);
    }
    
    // Layer 3
    if let Some(proto_name) = &l3.proto {
        match proto_name.as_str() {
            "IPv4" => {
                if let (Some(src), Some(dst)) = (&l3.src, &l3.dst) {
                    lines.push(format!("Internet Protocol Version {}, Src: {}, Dst: {}",
                        l3.version.unwrap_or(4), src, dst));
                }
            },
            "IPv6" => {
                if let (Some(src), Some(dst)) = (&l3.src, &l3.dst) {
                    lines.push(format!("Internet Protocol Version 6, Src: {}, Dst: {}",
                        src, dst));
                }
            },
            _ => {}
        }
    }
    
    // Layer 4
    if let Some(proto) = &l4.proto {
        match proto.as_str() {
            "TCP" => {
                if let (Some(sp), Some(dp)) = (l4.src_port, l4.dst_port) {
                    lines.push(format!("Transmission Control Protocol, Src Port: {}, Dst Port: {}",
                        sp, dp));
                }
            },
            "UDP" => {
                if let (Some(sp), Some(dp)) = (l4.src_port, l4.dst_port) {
                    lines.push(format!("User Datagram Protocol, Src Port: {}, Dst Port: {}",
                        sp, dp));
                }
            },
            "ICMP" => {
                if let (Some(t), Some(c)) = (l4.icmp_type, l4.icmp_code) {
                    lines.push(format!("Internet Control Message Protocol, Type: {}, Code: {}",
                        t, c));
                }
            },
            _ => {}
        }
    }
    
    // Check for DNS (port 53)
    if let (Some(sp), Some(dp)) = (l4.src_port, l4.dst_port) {
        if sp == 53 || dp == 53 {
            lines.push("Domain Name System (query)".to_string());
        }
    }
    
    lines.join("\n")
}

fn tcp_flags(b: u8) -> String {
    let mut v = Vec::new();
    if b & 0x01 != 0 { v.push("FIN"); }
    if b & 0x02 != 0 { v.push("SYN"); }
    if b & 0x04 != 0 { v.push("RST"); }
    if b & 0x08 != 0 { v.push("PSH"); }
    if b & 0x10 != 0 { v.push("ACK"); }
    if b & 0x20 != 0 { v.push("URG"); }
    if b & 0x40 != 0 { v.push("ECE"); }
    if b & 0x80 != 0 { v.push("CWR"); }
    if v.is_empty() { "NONE".into() } else { v.join(",") }
}

fn sniff_http1_first_line(payload: &[u8]) -> Option<String> {
    if payload.len() < 5 { return None; }
    let max = payload.len().min(256);
    let s = payload[0..max].iter().map(|&b| b as char).collect::<String>();
    let line = s.split(|c| c == '\n' || c == '\r').next().unwrap_or("").trim().to_string();
    if line.is_empty() { return None; }
    const METHODS: [&str; 8] = ["GET","POST","PUT","DELETE","HEAD","OPTIONS","TRACE","PATCH"];
    if METHODS.iter().any(|m| line.starts_with(&format!("{} ", m))) { return Some(format!("HTTP {}", line)); }
    if line.starts_with("HTTP/") { return Some(line); }
    None
}

fn sniff_tls_client_hello(payload: &[u8]) -> Option<Option<String>> {
    if payload.len() < 5 { return None; }
    if payload[0] != 0x16 || payload[1] != 0x03 { return None; }
    let len = ((payload[3] as usize) << 8) | payload[4] as usize;
    if payload.len() < 5 + len { return None; }
    if payload.len() < 9 { return None; }
    if payload[5] != 0x01 { return None; } // ClientHello
    let mut p = 9; // after hs header (type+len3)
    if payload.len() < p + 2 + 32 + 1 { return Some(None); }
    p += 2 + 32; // version + random
    let sid_len = payload[p] as usize; p += 1 + sid_len;
    if payload.len() < p + 2 { return Some(None); }
    let cs_len = ((payload[p] as usize) << 8) | payload[p+1] as usize; p += 2 + cs_len;
    if payload.len() < p + 1 { return Some(None); }
    let comp_len = payload[p] as usize; p += 1 + comp_len;
    if payload.len() < p + 2 { return Some(None); }
    let ext_len = ((payload[p] as usize) << 8) | payload[p+1] as usize; p += 2;
    let end = p + ext_len;
    while p + 4 <= payload.len().min(end) {
        let et = ((payload[p] as usize) << 8) | payload[p+1] as usize;
        let el = ((payload[p+2] as usize) << 8) | payload[p+3] as usize; p += 4;
        if p + el > end { break; }
        if et == 0x0000 && el >= 5 { // server_name
            let mut q = p + 2; // list len
            while q + 3 <= p + el {
                let name_type = payload[q]; q += 1;
                let nl = ((payload[q] as usize) << 8) | payload[q+1] as usize; q += 2;
                if name_type == 0 && q + nl <= p + el {
                    let sni = std::str::from_utf8(&payload[q..q+nl]).ok().map(|s| s.to_string());
                    return Some(sni);
                }
                q += nl;
            }
        }
        p += el;
    }
    Some(None)
}
