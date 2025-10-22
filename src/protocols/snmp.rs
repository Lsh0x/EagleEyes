// SNMP minimal decoder: print version/community if possible
pub fn decode(data: &[u8]) {
    if data.len() < 2 {
        println!("SNMP ({}B)", data.len());
        return;
    }
    // Best-effort ASN.1 BER: SEQUENCE 0x30 len
    if data[0] == 0x30 {
        println!("SNMP BER seq len~{}", data[1]);
    } else {
        println!("SNMP ({}B)", data.len());
    }
}
