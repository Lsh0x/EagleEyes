// Minimal MQTT decoder (fixed header)
// Spec: MQTT v3.1.1/5.0 fixed header byte 1 = type(4) | flags(4)
// Remaining Length is variable-length (1..4 bytes).

fn mqtt_type_name(t: u8) -> &'static str {
    match t {
        1 => "CONNECT",
        2 => "CONNACK",
        3 => "PUBLISH",
        4 => "PUBACK",
        5 => "PUBREC",
        6 => "PUBREL",
        7 => "PUBCOMP",
        8 => "SUBSCRIBE",
        9 => "SUBACK",
        10 => "UNSUBSCRIBE",
        11 => "UNSUBACK",
        12 => "PINGREQ",
        13 => "PINGRESP",
        14 => "DISCONNECT",
        15 => "AUTH",
        _ => "UNKNOWN",
    }
}

pub fn decode(data: &[u8]) {
    if data.len() < 2 {
        println!("MQTT (truncated) {}B", data.len());
        return;
    }
    let byte1 = data[0];
    let pkt_type = byte1 >> 4;
    let flags = byte1 & 0x0F;
    // Decode Remaining Length (variable length)
    let mut multiplier: usize = 1;
    let mut value: usize = 0;
    let mut i = 1usize;
    while i < data.len() {
        let enc = data[i] as usize;
        value += (enc & 0x7F) * multiplier;
        multiplier *= 128;
        i += 1;
        if (enc & 0x80) == 0 {
            break;
        }
        if i > 4 {
            break;
        } // at most 4 bytes
    }
    println!(
        "MQTT {} flags=0x{:x} remaining_len={}",
        mqtt_type_name(pkt_type),
        flags,
        value
    );
}
