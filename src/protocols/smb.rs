// SMB decoder: differentiate SMB1 and SMB2/3 and show command
pub fn decode(data: &[u8]) {
    if data.len() >= 4 {
        if &data[0..4] == b"\xffSMB" {
            let cmd = data.get(4).copied().unwrap_or(0);
            println!("SMB1 cmd=0x{:02x}", cmd);
            return;
        }
        if data[0] == 0xfe && &data[1..4] == b"SMB" {
            if data.len() >= 16 {
                let cmd = u16::from_le_bytes([data[12], data[13]]);
                println!("SMB2/3 cmd=0x{:04x}", cmd);
            } else {
                println!("SMB2/3");
            }
            return;
        }
    }
    println!("SMB/CIFS ({}B)", data.len());
}
