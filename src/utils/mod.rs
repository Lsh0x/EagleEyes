use std::borrow::Cow;
use std::{mem, slice};

/// Gives a mutable slice of the bytes of the given element.
#[inline]
pub fn bytes_of_mut<T: 'static + Copy>(elem: &mut T) -> &mut [u8] {
    let slice = slice::from_mut(elem);
    let new_len = mem::size_of_val(slice);
    unsafe { slice::from_raw_parts_mut(slice.as_ptr() as *mut u8, new_len) }
}

/// Returns either a borrowed version of the struct if target bytes are well aligned
/// (zero-copy, avoiding unsafe on the decode path via slice::align_to),
/// and falls back to an owned version that involves copying the bytes.
///
/// Returns None in case the number of bytes doesn't match the struct size.
#[inline]
pub fn cow_struct<T: 'static + Copy + Default>(bytes: &[u8]) -> Option<Cow<'_, T>> {
    if bytes.len() != mem::size_of::<T>() {
        return None;
    }

    // Zero-copy path when the input is properly aligned for T.
    // align_to is unsafe to call; we immediately validate perfect alignment and element count.
    let (head, body, tail) = unsafe { bytes.align_to::<T>() };
    if head.is_empty() && tail.is_empty() && body.len() == 1 {
        return Some(Cow::Borrowed(&body[0]));
    }

    // Fallback: copy into an owned T when alignment doesn't permit zero-copy.
    let mut elem = T::default();
    bytes_of_mut(&mut elem).copy_from_slice(bytes);
    Some(Cow::Owned(elem))
}
