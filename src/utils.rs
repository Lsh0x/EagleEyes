use std::borrow::Cow;
use std::{slice, mem};

/// Gives a mutable slice of the bytes of the given element.
#[inline]
pub fn bytes_of_mut<T: 'static + Copy>(elem: &mut T) -> &mut [u8] {
    let slice = slice::from_mut(elem);
    let new_len = mem::size_of_val(slice);
    unsafe { slice::from_raw_parts_mut(slice.as_ptr() as *mut u8, new_len) }
}

/// Returns either a borrowed version of the struct if target bytes are well aligned
/// and backups on an owned version that involves copying the bytes.
///
/// Returns None in case the number of bytes doesn't match the struct size.
#[inline]
pub fn cow_struct<T: 'static + Copy + Default>(bytes: &[u8]) -> Option<Cow<T>> {
    if bytes.len() != mem::size_of::<T>() {
        None
    } else if (bytes.as_ptr() as usize) % mem::align_of::<T>() != 0 {
        let mut elem = T::default();
        bytes_of_mut(&mut elem).copy_from_slice(bytes);
        Some(Cow::Owned(elem))
    } else {
        Some(Cow::Borrowed(unsafe { &*(bytes.as_ptr() as *const T) }))
    }
}
