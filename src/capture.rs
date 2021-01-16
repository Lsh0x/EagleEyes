use pcap::Capture;
use std::env;
use std::mem::transmute;

#[repr(C, packed)]
#[derive(Debug)]
struct EthernetHeader {
	dhost: [u8; 6],
	shost: [u8; 6],
	ether_type: u16
}

fn main() {
  let args: Vec<String> = env::args().collect();

  match args.len() {
    2 => {
      let device_name = &args[1];
      match Capture::from_device(device_name.as_str()).unwrap().open(){
        Ok(mut cap) => {
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
          }
        }
        Err(msg) => {
        	println!("error: {:?}", msg);
        }
      }
    }
    _ => {
      println!("usage: <device name>")
    }
  }
}
