// Minimal Kerberos decoder (very coarse ASN.1/BER peek)
// Kerberos uses ASN.1 DER; we just detect SEQUENCE (0x30) and print length

pub fn decode(data: &[u8]) {
    if data.len() >= 2 && data[0] == 0x30 {
        // DER length: short form if bit7=0
        let len = if data[1] & 0x80 == 0 {
            data[1] as usize
        } else {
            let n = (data[1] & 0x7F) as usize;
            if 2 + n <= data.len() {
                let mut v: usize = 0;
                for i in 0..n {
                    v = (v << 8) | data[2 + i] as usize;
                }
                v
            } else {
                0
            }
        };
        println!("Kerberos ASN.1 SEQUENCE len~{} ({}B)", len, data.len());
        return;
    }
    println!("Kerberos ({}B)", data.len());
}
