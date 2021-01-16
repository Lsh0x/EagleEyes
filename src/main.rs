use pcap::{Device, Capture};
use std::env;

#[repr(C, packed)]
#[derive(Debug)]
struct EthernetHeader {
	dhost: [u8; 6],
	shost: [u8; 6],
	ether_type: u16
}

fn main() {
	let args: Vec<String> = env::args().collect();

	if args.len() != 2 {
		println!("usage: {:?} <pcap_file>", args[0]);
	}
	let mut cap = Capture::from_file(args[1].as_str()).unwrap();
    while let Ok(packet) = cap.next() {
        let mut ether_header;
    	unsafe {
            ether_header = std::mem::transmute::<* const u8, * const EthernetHeader>(packet.data.as_ptr()).as_ref();
    	}
        match ether_header {
            None => assert!(true, "ohhhhhhhhhhhhhhhhhhhhhh"),
            Some(header) => {
                let t = header.ether_type.to_be();
                match t {
                    0x0806 => println!("arp"),
                    _ => println!("unknow: {:?}", t)
                }
            }
        }
        //println!("received packet! {:?}", packet);
    }
}
