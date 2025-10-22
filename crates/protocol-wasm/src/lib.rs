use wasm_bindgen::prelude::*;
use serde::Serialize;

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct L2 {
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub ether_type: Option<u16>,
    pub vlan: Option<u16>,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct L3 {
    pub proto: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct L4 {
    pub proto: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<String>,
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
}

fn mac_to_str(m: &[u8]) -> String {
    m.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}
fn ipv4_to_str(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
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

        // L3
        if ether_type == ethernet::PROTO::IPV4 && bytes.len() >= off + 20 {
            // IPv4 header length
            let ihl = (bytes[off] & 0x0f) as usize * 4;
            if ihl >= 20 && bytes.len() >= off + ihl {
                let proto = bytes[off + 9];
                let src = ipv4_to_str(&bytes[off + 12..off + 16]);
                let dst = ipv4_to_str(&bytes[off + 16..off + 20]);
                let l3 = L3 { proto: Some("IPv4".into()), src: Some(src), dst: Some(dst) };
                // L4
                let l4_start = off + ihl;
                let mut l4 = L4::default();
                let mut summary = String::new();
                let mut tag = String::from("IPv4");
                if proto == ipm::PROTO::TCP && bytes.len() >= l4_start + 20 {
                    let sp = u16::from_be_bytes([bytes[l4_start], bytes[l4_start + 1]]);
                    let dp = u16::from_be_bytes([bytes[l4_start + 2], bytes[l4_start + 3]]);
                    let data_offset = (bytes[l4_start + 12] >> 4) as usize * 4;
                    let flags = bytes[l4_start + 13];
                    l4 = L4 { proto: Some("TCP".into()), src_port: Some(sp), dst_port: Some(dp), tcp_flags: Some(tcp_flags(flags)) };
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
                    l4 = L4 { proto: Some("UDP".into()), src_port: Some(sp), dst_port: Some(dp), tcp_flags: None };
                    summary = format!("UDP {} → {}", sp, dp);
                    tag = "UDP".into();
                } else if proto == ipm::PROTO::ICMP {
                    summary = "ICMP".into();
                    tag = "ICMP".into();
                }
                let out = Decoded { l2: Some(l2), l3: Some(l3), l4: if l4.proto.is_some() { Some(l4) } else { None }, summary, protocol_tag: tag, app_tag: None };
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
