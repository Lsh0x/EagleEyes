// Minimal NFLOG decoder
// Linux Netfilter NFLOG TLVs; we just print the first few bytes
pub fn decode(data: &[u8]) {
    let show = core::cmp::min(16, data.len());
    println!("NFLOG ({}B) head={:02x?}", data.len(), &data[..show]);
}
