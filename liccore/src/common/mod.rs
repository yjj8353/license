use std::ffi::CStr;
use std::os::raw::c_char;

pub fn to_str(p: *const c_char) -> Option<String> {
    if p.is_null() {
    return None;
    }

    Some(unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() })
}