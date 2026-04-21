use std::os::raw::c_char;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use liccore::base::Base;
use liccore::base::base64::Base64;
use liccore::ffi_utils::to_str;
use liccore::signature::DigitalSignature;
use liccore::signature::ed25519::Ed25519KeyPair;
use liccore::license::License;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn license_verify(
    license_data: *const c_char, // base64(encoded license json)
    public_key: *const c_char,   // PEM public key
) -> i32 {
    // -1: null/invalid input pointer
    // -2: license_data base64 decode fail
    // -3: license json parse fail
    // -4: signature missing or signature base64 decode fail
    // -5: payload rebuild fail
    // -6: public key parse fail
    // -7: signature verify fail

    let encoded_license = match unsafe { to_str(license_data) } {
        Some(v) => v,
        None => return -1,
    };
    let public_key_pem = match unsafe { to_str(public_key) } {
        Some(v) => v,
        None => return -1,
    };

    let license_json = match Base64::decode_str(&encoded_license) {
        Ok(v) => v,
        Err(_) => return -2,
    };

    let mut license = match License::from_json(&license_json) {
        Ok(v) => v,
        Err(_) => return -3,
    };

    let signature_b64 = match license.signature.take() {
        Some(v) if !v.is_empty() => v,
        _ => return -4,
    };

    let signature_bytes = match BASE64_STANDARD.decode(signature_b64.as_bytes()) {
        Ok(v) => v,
        Err(_) => return -4,
    };

    // NOTE: 이 payload 재구성 방식은 licgen의 서명 대상과 정확히 일치해야 함
    license.signature = None;
    let payload_json = match license.to_json() {
        Ok(v) => v,
        Err(_) => return -5,
    };

    let mut key_pair = Ed25519KeyPair::new();
    key_pair.set_public_key_pem(&public_key_pem);
    if key_pair.verify(payload_json.as_bytes(), &signature_bytes) {
        return 0;
    } else {
        return -7;
    }
}
