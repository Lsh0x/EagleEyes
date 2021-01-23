pub fn cast_slice_to_reference<T>(data: &[u8]) -> std::result::Result::<&T, &str> {
	if data.len() < std::mem::size_of::<T>() {
		Err("Truncated payload")
	} else {
		Ok(unsafe { &*(data.as_ptr() as *const T) })
	}   
}
