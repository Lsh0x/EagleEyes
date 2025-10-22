use pcap::Capture;
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args.len() > 4 {
        eprintln!("usage: {} <device> <out.pcap> [packet_count]", args[0]);
        process::exit(1);
    }

    let device = &args[1];
    let out = &args[2];
    let mut remaining = args
        .get(3)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(usize::MAX);

    let mut cap = match Capture::from_device(device.as_str()).and_then(|d| d.open()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error opening device {}: {:?}", device, e);
            process::exit(2);
        }
    };

    let mut dump = match cap.savefile(out) {
        Ok(sf) => sf,
        Err(e) => {
            eprintln!("error creating savefile {}: {:?}", out, e);
            process::exit(3);
        }
    };

    let mut written = 0usize;
    while remaining > 0 {
        match cap.next() {
            Ok(pkt) => {
                dump.write(&pkt);
                written += 1;
                remaining -= 1;
            }
            Err(e) => {
                eprintln!("capture finished or error: {:?}", e);
                break;
            }
        }
    }

    eprintln!("wrote {} packets to {}", written, out);
}
