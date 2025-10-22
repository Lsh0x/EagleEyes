// RIP v2 minimal decoder (UDP/520)
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub cmd: u8,
    pub ver: u8,
    pub zero: u16,
}

impl Header {
    pub const SIZE: usize = 4;
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        return;
    }
    let h = unsafe { &*(data.as_ptr() as *const Header) };
    println!("RIP cmd={} ver={}", h.cmd, h.ver);
}
