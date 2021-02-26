use eagleeyes::protocols::ethernet;
use pcap::Capture;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("usage: {:?} <pcap_file>", args[0]);
    }
    let mut cap = Capture::from_file(args[1].as_str()).unwrap();
    while let Ok(packet) = cap.next() {
        ethernet::decode(packet.data);
    }
}
