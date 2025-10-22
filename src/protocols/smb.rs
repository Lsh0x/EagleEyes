// SMB minimal signature check
pub fn decode(data: &[u8]) {
    if data.len() >= 4 {
        if &data[0..4] == b"\xffSMB" {
            println!("SMB1");
            return;
        }
        if data.len() >= 4 && data[0] == 0xfe && &data[1..4] == b"SMB" {
            println!("SMB2/3");
            return;
        }
    }
    println!("SMB/CIFS ({}B)", data.len());
}
