// SCTP minimal common header (RFC 4960)
use crate::utils::cow_struct;

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub src_port: u16,
    pub dst_port: u16,
    pub vtag: u32,
    pub checksum: u32,
}

impl Header {
    pub const SIZE: usize = core::mem::size_of::<Header>();
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        println!("SCTP (truncated) {}B", data.len());
        return;
    }
    let (hdr, _) = data.split_at(Header::SIZE);
    if let Some(h) = cow_struct::<Header>(hdr) {
        println!(
            "SCTP {} -> {} vtag=0x{:08x}",
            u16::from_be(h.src_port),
            u16::from_be(h.dst_port),
            u32::from_be(h.vtag)
        );
    } else {
        println!("SCTP (truncated) {}B", data.len());
    }
}
