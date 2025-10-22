use crate::utils::cow_struct;

// LLDP TLV header: 2 bytes => T(7 bits) | L(9 bits)
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct TlvHdr {
    pub t: u16, // raw
}

fn tlv_type_len(v: u16) -> (u16, u16) {
    let t = (v >> 9) & 0x7f;
    let l = v & 0x01ff;
    (t, l)
}

pub fn decode(mut data: &[u8]) {
    // No fixed header; iterate TLVs
    while data.len() >= 2 {
        let (h, rest) = data.split_at(2);
        let raw = u16::from_be_bytes([h[0], h[1]]);
        let (t, l) = tlv_type_len(raw);
        if rest.len() < l as usize {
            break;
        }
        let (val, next) = rest.split_at(l as usize);
        match t {
            0 => {
                // End of LLDPDU
                println!("LLDP End");
                break;
            }
            1 => {
                // Chassis ID
                println!("LLDP ChassisID len={}", l);
            }
            2 => {
                // Port ID
                println!("LLDP PortID len={}", l);
            }
            3 => {
                // TTL
                if val.len() >= 2 {
                    let ttl = u16::from_be_bytes([val[0], val[1]]);
                    println!("LLDP TTL {}s", ttl);
                }
            }
            5 => println!("LLDP System Description ({}B)", l),
            6 => println!("LLDP System Name ({}B)", l),
            7 => println!("LLDP System Capabilities ({}B)", l),
            8 => println!("LLDP Management Address ({}B)", l),
            _ => println!("LLDP TLV type={} len={}", t, l),
        }
        data = next;
    }
}
