use eagleeyes::protocols::{ethernet, ip, loopback};
use pcap::Capture;
use std::env;

fn decode_by_datalink(dlt: i32, data: &[u8]) {
    match dlt {
        1 => ethernet::decode(data),       // LINKTYPE_EN10MB
        0 | 108 => loopback::decode(data), // LINKTYPE_NULL or LOOP
        101 => {
            // LINKTYPE_RAW (raw IP)
            if data.len() >= 1 {
                let v = (data[0] & 0xF0) >> 4;
                if v == 4 {
                    eagleeyes::protocols::ipv4::decode(data);
                } else if v == 6 {
                    eagleeyes::protocols::ipv6::decode(data);
                } else {
                    println!("RAW ({}B)", data.len());
                }
            }
        }
        227 => eagleeyes::protocols::can::decode(data), // CAN_SOCKETCAN
        239 => eagleeyes::protocols::nflog::decode(data), // NFLOG
        187 | 201 => eagleeyes::protocols::bluetooth::decode(data), // BT HCI H4 (with/without phdr)
        189 | 220 => eagleeyes::protocols::usb::decode(data), // USB Linux
        212 => eagleeyes::protocols::lin::decode(data), // LIN (if supported)
        9 | 16 => eagleeyes::protocols::ppp::decode(data), // PPP / PPP_BSDOS
        _ => ethernet::decode(data),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        2 => {
            let device_name = &args[1];
            match Capture::from_device(device_name.as_str()).unwrap().open() {
                Ok(mut cap) => {
                    let dlt = cap.get_datalink().0 as i32;
                    while let Ok(packet) = cap.next() {
                        decode_by_datalink(dlt, packet.data);
                    }
                }
                Err(msg) => {
                    println!("error: {:?}", msg);
                }
            }
        }
        _ => {
            println!("usage: {:?} <device name>", args[0]);
        }
    }
}
