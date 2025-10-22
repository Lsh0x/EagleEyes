// Minimal LLMNR decoder (same wire format as DNS)
// RFC 4795: typically UDP/TCP 5355

pub fn decode(data: &[u8]) {
    super::dns::decode(data);
}
