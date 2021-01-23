pub fn cast_slice_to_reference<T>(data: &[u8]) -> &T {
    unsafe { &*(data.as_ptr() as *const T) }
}
