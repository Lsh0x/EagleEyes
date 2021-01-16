use pcap::Capture;
use std::env;


fn main() {
  let args: Vec<String> = env::args().collect();

  match args.len() {
    2 => {
      let device_name = &args[1];
      match Capture::from_device(device_name.as_str()).unwrap().open(){
        Ok(mut cap) => {
          while let Ok(packet) = cap.next() {
              println!("received packet! {:?}", packet);
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
