// Minimal SMTPS decoder: try TLS first
pub fn decode(data: &[u8]) {
    if !super::tls::decode(data) {
        super::smtp::decode(data);
    }
}
