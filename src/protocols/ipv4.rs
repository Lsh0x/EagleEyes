use super::super::utils;

#[repr(C, packed)]
pub struct IPV4Header {
	pub version_and_header_len: u8,
	pub type_of_service: u8,
	pub total_len: u16,
	pub identification: u16,
	pub fragment_offset: u16,
	pub time_to_live: u8,
	pub protocol: u8,
	pub checksum: u16,
	pub src: u32,
	pub dst: u32,
}

pub fn decode(data: &[u8]) {
	match utils::cast::cast_slice_to_reference::<IPV4Header>(data) {
		Ok(header) => {
			let version = (header.version_and_header_len & 0xF0) >> 4;
			if version != 4 {
				println!("Invalid ip version: {:?}", version);
			} else {
				let _len_bytes = (header.version_and_header_len & 0xF) * 32 / 8;
				println!("protocol: {}", format!("{:#X}", header.protocol));
			}
		},
		Err(msg) => {
			println!("ip decode error: {:?}", msg);
		}
	}
}
