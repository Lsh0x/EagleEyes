// Minimal Bluetooth HCI H4 decoder
// First byte is packet type: 1=CMD,2=ACL,3=SYNC,4=EVENT
pub fn decode(data: &[u8]) {
    if data.is_empty() {
        println!("BT HCI (empty)");
        return;
    }
    let t = data[0];
    let name = match t {
        1 => "CMD",
        2 => "ACL",
        3 => "SYNC",
        4 => "EVENT",
        _ => "?",
    };
    println!("Bluetooth HCI {} ({}B)", name, data.len());
}
