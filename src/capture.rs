use pcap::Capture;
use std::env;

use protocol::EthernetHeader;

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        2 => {
            let device_name = &args[1];
            match Capture::from_device(device_name.as_str()).unwrap().open() {
                Ok(mut cap) => {
                    while let Ok(packet) = cap.next() {
                        let header = unsafe { &*(packet.data.as_ptr() as *const EthernetHeader) };
                        let t = header.ether_type.to_be();
                        match t {
                            0x0806 => println!("arp"),
                            _ => println!("unknow: {:?}", t),
                        }
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
