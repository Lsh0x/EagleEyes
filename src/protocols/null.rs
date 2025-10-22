// Minimal Null decoder: delegate to loopback
pub fn decode(data: &[u8]) {
    super::loopback::decode(data);
}
