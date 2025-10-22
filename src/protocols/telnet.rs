// Minimal Telnet decoder (IAC negotiation awareness)
pub fn decode(data: &[u8]) {
    let iac = data.iter().filter(|&&b| b == 0xff).count();
    println!("Telnet bytes={} IAC_count={}", data.len(), iac);
}
