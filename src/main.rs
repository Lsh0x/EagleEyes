use pcap::Device;

fn main() {
	let res_devices = Device::list();

	match res_devices {
		Ok(devices) => {
			for device in devices.iter() {
				println!("Device: {:?}", device.name);
			}
		}
		Err(msg) => {
			println!("error: {:?}", msg);
		}
	}
	
}