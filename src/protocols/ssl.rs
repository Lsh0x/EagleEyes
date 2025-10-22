// SSL alias module: reuse TLS decoder
// Returns true if it looked like TLS ClientHello.
pub fn decode(data: &[u8]) -> bool {
    super::tls::decode(data)
}
