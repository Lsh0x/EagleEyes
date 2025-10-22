// Minimal USB Linux decoder
// We don't parse full usbmon header; just show direction if recognizable.
pub fn decode(data: &[u8]) {
    // usbmon v1/v2 headers vary; just print size and first bytes
    let n = core::cmp::min(16, data.len());
    println!("USB ({}B) head={:02x?}", data.len(), &data[..n]);
}
