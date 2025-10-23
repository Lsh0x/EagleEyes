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

fn ipv6_to_str(b: &[u8]) -> String {
    if b.len() != 16 { return String::new(); }
    let mut parts = [0u16; 8];
    for i in 0..8 {
        parts[i] = u16::from_be_bytes([b[2 * i], b[2 * i + 1]]);
    }
    format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]
    )
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
                let mut app_tag: Option<String> = None;
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
                        app_tag = Some("TLS".into());
                    } else if let Some(line) = sniff_http1_first_line(payload) {
                        summary = line;
                        tag = "HTTP".into();
                        app_tag = Some("HTTP".into());
                    } else {
                        app_tag = tcp_app_tag(sp, dp, payload);
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
                    app_tag = udp_app_tag(sp, dp);
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
                let out = Decoded { l2: Some(l2), l3: Some(l3), l4: if l4.proto.is_some() { Some(l4) } else { None }, summary, protocol_tag: tag, app_tag, description: Some(description) };
                return serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()));
            }
        }
        // IPv6
        if ether_type == ethernet::PROTO::IPV6 && bytes.len() >= off + 40 {
            // IPv6 fixed header
            let ver_tc_fl = u32::from_be_bytes([bytes[off], bytes[off+1], bytes[off+2], bytes[off+3]]);
            let version = ((ver_tc_fl & 0xF0000000) >> 28) as u8;
            let traffic_class = ((ver_tc_fl & 0x0FF00000) >> 20) as u8;
            let flow_label = ver_tc_fl & 0x000FFFFF;
            let payload_len = u16::from_be_bytes([bytes[off+4], bytes[off+5]]);
            let next_header = bytes[off+6];
            let hop_limit = bytes[off+7];
            let src = ipv6_to_str(&bytes[off+8..off+24]);
            let dst = ipv6_to_str(&bytes[off+24..off+40]);
            let l3 = L3 {
                proto: Some("IPv6".into()),
                src: Some(src),
                dst: Some(dst),
                traffic_class: Some(traffic_class),
                flow_label: Some(flow_label),
                payload_len: Some(payload_len),
                next_header: Some(next_header),
                hop_limit: Some(hop_limit),
                version: Some(version),
                ..Default::default()
            };
            let l4_start = off + 40; // ignoring extension headers for now
            let mut l4 = L4::default();
            let mut summary = String::from("IPv6");
            let mut tag = String::from("IPv6");
            let mut app_tag: Option<String> = None;
            if next_header == ipm::PROTO::TCP && bytes.len() >= l4_start + 20 {
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
                let payload = if bytes.len() >= l4_start + data_offset { &bytes[l4_start + data_offset..] } else { &[] };
                if let Some(sni) = sniff_tls_client_hello(payload) {
                    summary = if let Some(sni) = sni { format!("TLS ClientHello SNI={}", sni) } else { "TLS".into() };
                    tag = "TLS".into();
                    app_tag = Some("TLS".into());
                } else if let Some(line) = sniff_http1_first_line(payload) {
                    summary = line;
                    tag = "HTTP".into();
                    app_tag = Some("HTTP".into());
                } else {
                    app_tag = tcp_app_tag(sp, dp, payload);
                }
            } else if next_header == ipm::PROTO::UDP && bytes.len() >= l4_start + 8 {
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
                app_tag = udp_app_tag(sp, dp);
            } else if next_header == ipm::PROTO::IPV6ICMP && bytes.len() >= l4_start + 4 {
                let icmp_type = bytes[l4_start];
                let icmp_code = bytes[l4_start + 1];
                let checksum = u16::from_be_bytes([bytes[l4_start + 2], bytes[l4_start + 3]]);
                l4 = L4 {
                    proto: Some("ICMPv6".into()),
                    icmp_type: Some(icmp_type),
                    icmp_code: Some(icmp_code),
                    icmp_checksum: Some(checksum),
                    ..Default::default()
                };
                summary = format!("ICMPv6 type {} code {}", icmp_type, icmp_code);
                tag = "ICMPv6".into();
            }
            let description = build_description(bytes, &l2, &l3, &l4);
            let out = Decoded { l2: Some(l2), l3: Some(l3), l4: if l4.proto.is_some() { Some(l4) } else { None }, summary, protocol_tag: tag, app_tag, description: Some(description) };
            return serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()));
        }
        if ether_type == ethernet::PROTO::LLDP {
            let out = Decoded { l2: Some(l2), summary: "LLDP".into(), protocol_tag: "LLDP".into(), ..Default::default() };
            return serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()));
        }
        if ether_type == ethernet::PROTO::MPLS_U || ether_type == ethernet::PROTO::MPLS_M {
            let out = Decoded { l2: Some(l2), summary: "MPLS".into(), protocol_tag: "MPLS".into(), ..Default::default() };
            return serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()));
        }
        if ether_type == ethernet::PROTO::PPPOE_DISC || ether_type == ethernet::PROTO::PPPOE_SESS {
            let out = Decoded { l2: Some(l2), summary: "PPPoE".into(), protocol_tag: "PPPoE".into(), ..Default::default() };
            return serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()));
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
            format!("Ethernet II, VLAN: {}", vlan)
        } else {
            "Ethernet II".to_string()
        };
        lines.push(eth_line);
        lines.push(format!("    Source: {}", src_mac));
        lines.push(format!("    Destination: {}", dst_mac));
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
            "ICMPv6" => {
                if let (Some(t), Some(c)) = (l4.icmp_type, l4.icmp_code) {
                    lines.push(format!("Internet Control Message Protocol v6, Type: {}, Code: {}",
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

fn udp_app_tag(sp: u16, dp: u16) -> Option<String> {
    let a = sp; let b = dp;
    let port = |p| a == p || b == p;
    if port(53) { return Some("DNS".into()); }
    if port(5353) { return Some("mDNS".into()); }
    if port(67) || port(68) { return Some("DHCP".into()); }
    if port(123) { return Some("NTP".into()); }
    if port(161) || port(162) { return Some("SNMP".into()); }
    if port(514) { return Some("Syslog".into()); }
    if port(69) { return Some("TFTP".into()); }
    if port(137) || port(138) { return Some("NetBIOS".into()); }
    if port(546) || port(547) { return Some("DHCPv6".into()); }
    if port(520) { return Some("RIP".into()); }
    if port(5060) { return Some("SIP".into()); }
    if port(443) { return Some("QUIC".into()); }
    if port(5683) { return Some("CoAP".into()); }
    if port(1900) { return Some("SSDP".into()); }
    if port(5355) { return Some("LLMNR".into()); }
    if port(88) { return Some("Kerberos".into()); }
    if port(3478) || port(5349) { return Some("STUN/TURN".into()); }
    None
}

fn tcp_app_tag(sp: u16, dp: u16, payload: &[u8]) -> Option<String> {
    let a = sp; let b = dp;
    let port = |p| a == p || b == p;
    if port(179) { return Some("BGP".into()); }
    if port(22) { return Some("SSH".into()); }
    if port(23) { return Some("Telnet".into()); }
    if port(21) { return Some("FTP".into()); }
    if port(990) {
        if sniff_tls_client_hello(payload).is_some() { return Some("FTPS".into()); }
        return Some("FTP".into());
    }
    if port(25) || port(587) { return Some("SMTP".into()); }
    if port(465) { return Some("SMTPS".into()); }
    if port(110) { return Some("POP3".into()); }
    if port(143) { return Some("IMAP".into()); }
    if port(993) {
        if sniff_tls_client_hello(payload).is_some() { return Some("IMAPS".into()); }
        return Some("IMAP".into());
    }
    if port(389) { return Some("LDAP".into()); }
    if port(636) { return Some("LDAPS".into()); }
    if port(853) { return Some("DoT".into()); }
    if port(3389) { return Some("RDP".into()); }
    if port(139) || port(445) { return Some("SMB".into()); }
    if port(554) { return Some("RTSP".into()); }
    if port(5060) { return Some("SIP".into()); }
    if port(443) || port(8443) {
        if sniff_tls_client_hello(payload).is_some() { return Some("TLS/HTTPS".into()); }
        return Some("HTTP".into());
    }
    if port(80) || port(8080) || port(8000) { return Some("HTTP".into()); }
    if port(1883) { return Some("MQTT".into()); }
    if port(8883) {
        if sniff_tls_client_hello(payload).is_some() { return Some("MQTTS".into()); }
        return Some("MQTT".into());
    }
    if port(5672) { return Some("AMQP".into()); }
    if port(5671) {
        if sniff_tls_client_hello(payload).is_some() { return Some("AMQPS".into()); }
        return Some("AMQP".into());
    }
    if port(61613) || port(61614) { return Some("STOMP".into()); }
    if port(6379) { return Some("Redis".into()); }
    if port(11211) { return Some("Memcached".into()); }
    if port(3478) { return Some("STUN".into()); }
    if port(5349) {
        if sniff_tls_client_hello(payload).is_some() { return Some("STUN/TURN over TLS".into()); }
        return Some("STUN/TURN".into());
    }
    if port(5355) { return Some("LLMNR".into()); }
    None
}
