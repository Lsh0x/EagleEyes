use pcap::Capture;
use std::env;
use std::mem::transmute;


#[repr(C)]
struct ether {
  ether_dhost: u8,
  ether_shost: u8,
  ether_type: u16,
}

fn main() {
  let args: Vec<String> = env::args().collect();

  match args.len() {
    2 => {
      let device_name = &args[1];
      match Capture::from_device(device_name.as_str()).unwrap().open(){
        Ok(mut cap) => {
          while let Ok(packet) = cap.next() {
            unsafe {
              let eth = transmute::<&[u8], ether>(&packet.data[0..4]);
              println!("ether_dhost {:?}", eth.ether_dhost);
              println!("ether_shost {:?}", eth.ether_shost);
              println!("ether_type {:?}", eth.ether_type);
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
