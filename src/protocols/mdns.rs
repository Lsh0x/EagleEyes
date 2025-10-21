use super::dns;

// mDNS uses standard DNS format on UDP/5353
pub fn decode(data: &[u8]) {
    dns::decode(data);
}
