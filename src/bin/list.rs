use pcap::Device;

fn main() {
    match Device::list() {
        Ok(devs) => {
            for d in devs {
                println!("{}", d.name);
            }
        }
        Err(e) => eprintln!("error listing devices: {:?}", e),
    }
}
