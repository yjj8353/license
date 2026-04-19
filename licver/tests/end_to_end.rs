use std::ffi::CString;
use std::os::raw::c_char;

#[test]
fn end_to_end_flow_generates_signs_and_verifies_license() {
    let mut public_key_buf = vec![0u8; 4096];
    let mut private_key_buf = vec![0u8; 4096];
    let mut public_written = 0usize;
    let mut private_written = 0usize;

    let keygen_rc = unsafe {
        keygen::keypair_generate(
            public_key_buf.as_mut_ptr(),
            public_key_buf.len(),
            &mut public_written,
            private_key_buf.as_mut_ptr(),
            private_key_buf.len(),
            &mut private_written,
        )
    };

    assert_eq!(keygen_rc, 0, "keygen failed with code {keygen_rc}");
    assert!(public_written > 0, "public key should not be empty");
    assert!(private_written > 0, "private key should not be empty");

    let public_key_pem = String::from_utf8(public_key_buf[..public_written].to_vec())
        .expect("public key should be valid UTF-8 PEM");
    let private_key_pem = String::from_utf8(private_key_buf[..private_written].to_vec())
        .expect("private key should be valid UTF-8 PEM");

    let product_name = CString::new("Dashboard").unwrap();
    let issuance_type = CString::new("initial").unwrap();
    let reissue_reason = CString::new("").unwrap();
    let license_key = CString::new("E2E-TEST-KEY-0001").unwrap();
    let domain = CString::new("example.com").unwrap();
    let issued_at = CString::new("2026-04-20T00:00:00Z").unwrap();
    let expires_at = CString::new("2027-04-20T00:00:00Z").unwrap();
    let license_version = CString::new("1.0").unwrap();
    let private_key = CString::new(private_key_pem).unwrap();

    let mut license_buf = vec![0 as c_char; 8192];
    let mut license_written = 0usize;

    let licgen_rc = unsafe {
        licgen::license_generate(
            product_name.as_ptr(),
            issuance_type.as_ptr(),
            reissue_reason.as_ptr(),
            license_key.as_ptr(),
            domain.as_ptr(),
            issued_at.as_ptr(),
            expires_at.as_ptr(),
            license_version.as_ptr(),
            private_key.as_ptr(),
            license_buf.as_mut_ptr(),
            license_buf.len(),
            &mut license_written,
        )
    };

    assert_eq!(licgen_rc, 0, "licgen failed with code {licgen_rc}");
    assert!(license_written > 0, "generated license should not be empty");

    let generated_license = unsafe { std::ffi::CStr::from_ptr(license_buf.as_ptr()) }
        .to_str()
        .expect("license output should be valid UTF-8")
        .to_owned();

    let generated_license = CString::new(generated_license).unwrap();
    let public_key = CString::new(public_key_pem).unwrap();

    let licver_rc = unsafe {
        licver::license_verify(generated_license.as_ptr(), public_key.as_ptr())
    };

    assert_eq!(licver_rc, 0, "licver failed with code {licver_rc}");
}
