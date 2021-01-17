use pcap::{Capture};
use std::env;

#[repr(C, packed)]
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
      let header = unsafe {  &*(packet.data.as_ptr() as *const EthernetHeader) };
      let t = header.ether_type.to_be();
      match t {
          0x0806 => println!("arp"),
          _ => println!("unknow: {:?}", t)
      }
    }
}
