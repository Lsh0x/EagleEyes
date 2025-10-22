// Minimal AMQP header detector (0-9-1 and 1.0)
// AMQP 0-9-1: "AMQP\x00\x00\x09\x01"
// AMQP 1.0:   "AMQP\x00\x01\x00\x00"

pub fn decode(data: &[u8]) {
    if data.len() >= 8 && &data[0..4] == b"AMQP" {
        let v = &data[4..8];
        let desc = if v == [0, 0, 9, 1] {
            "0-9-1"
        } else if v == [0, 1, 0, 0] {
            "1.0"
        } else {
            "unknown"
        };
        println!("AMQP header {} ({}B)", desc, data.len());
        return;
    }
    println!("AMQP frame ({}B)", data.len());
}
