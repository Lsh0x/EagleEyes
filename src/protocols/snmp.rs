// SNMP BER peek: version, community, PDU type
fn ber_len(bytes: &[u8], i: &mut usize) -> Option<usize> {
    if *i >= bytes.len() {
        return None;
    }
    let b = bytes[*i];
    *i += 1;
    if b & 0x80 == 0 {
        return Some(b as usize);
    }
    let n = (b & 0x7F) as usize;
    if n == 0 || *i + n > bytes.len() || n > 4 {
        return None;
    }
    let mut v = 0usize;
    for _ in 0..n {
        v = (v << 8) | (bytes[*i] as usize);
        *i += 1;
    }
    Some(v)
}

pub fn decode(data: &[u8]) {
    let mut i = 0usize;
    if i >= data.len() || data[i] != 0x30 {
        println!("SNMP ({}B)", data.len());
        return;
    }
    i += 1;
    let _seq_len = match ber_len(data, &mut i) {
        Some(v) => v,
        None => {
            println!("SNMP (bad len)");
            return;
        }
    };
    // version: INTEGER
    if i >= data.len() || data[i] != 0x02 {
        println!("SNMP (no version)");
        return;
    }
    i += 1;
    let vlen = match ber_len(data, &mut i) {
        Some(v) => v,
        None => {
            println!("SNMP (bad ver)");
            return;
        }
    };
    if i + vlen > data.len() {
        println!("SNMP (trunc ver)");
        return;
    }
    let version = if vlen == 1 { data[i] as u64 } else { 0 };
    i += vlen;
    // community: OCTET STRING
    if i >= data.len() || data[i] != 0x04 {
        println!("SNMP v{} (no community)", version);
        return;
    }
    i += 1;
    let clen = match ber_len(data, &mut i) {
        Some(v) => v,
        None => {
            println!("SNMP v{} (bad comm)", version);
            return;
        }
    };
    if i + clen > data.len() {
        println!("SNMP v{} (trunc comm)", version);
        return;
    }
    let community = std::str::from_utf8(&data[i..i + clen]).unwrap_or("");
    i += clen;
    // PDU type: context-specific (0xA0..)
    let pdu = data.get(i).copied().unwrap_or(0);
    println!(
        "SNMP v{} community={} pdu=0x{:02x}",
        version, community, pdu
    );
}
