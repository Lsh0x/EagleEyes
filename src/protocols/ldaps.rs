// LDAPS: try TLS first
pub fn decode(data: &[u8]) {
    if !super::tls::decode(data) {
        super::ldap::decode(data);
    }
}
