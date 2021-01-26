use std::{slice, mem};

/// Gives a mutable slice of the bytes of the given element.
#[inline]
pub fn bytes_of_mut<T: 'static + Copy>(elem: &mut T) -> &mut [u8] {
    let slice = slice::from_mut(elem);
    let new_len = mem::size_of_val(slice);
    unsafe { slice::from_raw_parts_mut(slice.as_ptr() as *mut u8, new_len) }
}
