// Minimal Memcached decoder (binary header detection + text command preview)
// Binary protocol header (request):
//  0: magic (0x80 req, 0x81 resp)
//  1: opcode
//  2-3: key length
//  4: extras length
//  5: data type
//  6-7: vbucket / status
//  8-11: total body length
//  12-15: opaque
//  16-23: CAS

pub fn decode(data: &[u8]) {
    if data.len() >= 24 && (data[0] == 0x80 || data[0] == 0x81) {
        let magic = data[0];
        let opcode = data[1];
        let keylen = u16::from_be_bytes([data[2], data[3]]);
        let extlen = data[4];
        let total = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        println!(
            "Memcached bin magic=0x{:02x} opcode=0x{:02x} keylen={} extlen={} body={}",
            magic, opcode, keylen, extlen, total
        );
        return;
    }
    // text protocol: print first token
    let max = core::cmp::min(64, data.len());
    if let Ok(s) = std::str::from_utf8(&data[..max]) {
        let cmd = s.split_whitespace().next().unwrap_or("");
        println!("Memcached text cmd={}", cmd);
    } else {
        println!("Memcached ({}B)", data.len());
    }
}
