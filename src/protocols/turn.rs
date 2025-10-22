// Minimal TURN decoder using STUN format
pub fn decode(data: &[u8]) {
    if !super::stun::decode(data) {
        println!("TURN (non-STUN payload) {}B", data.len());
    }
}
