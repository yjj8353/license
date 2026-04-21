use std::os::raw::c_char;

use liccore::base::Base;
use liccore::base::base64::Base64;
use liccore::ffi_utils::to_str;
use liccore::signature::DigitalSignature;
use liccore::signature::ed25519::Ed25519KeyPair;
use liccore::license::License;

const OK: i32 = 0;

// 라이선스 검증 함수
const ERR_INVALID_ARG: i32 = -1;

// Base64 디코딩 실패
const ERR_BASE64_DECODE_FAIL: i32 = -2;

// JSON 파싱 실패
const ERR_JSON_PARSE_FAIL: i32 = -3;

// 서명 추출 실패
const ERR_SIGNATURE_FAIL: i32 = -4;

// payload 재구성 실패
const ERR_PAYLOAD_REBUILD_FAIL: i32 = -5;

// 공개키 PEM 파싱 실패
const ERR_PUBLIC_KEY_PARSE_FAIL: i32 = -6;

// 서명 검증 실패
const ERR_SIGNATURE_VERIFY_FAIL: i32 = -7;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn license_verify(
    license_data: *const c_char, // base64(encoded license json)
    public_key: *const c_char,   // PEM public key
) -> i32 {

    // 입력 문자열을 Rust 문자열로 변환
    let (encoded_license, public_key_pem) = match (unsafe { to_str(license_data) }, unsafe { to_str(public_key) }) {
        (Some(lic), Some(key)) => (lic, key),
        _ => return ERR_INVALID_ARG,
    };

    // Base64로 인코딩된 라이선스 JSON 디코딩
    let license_json = match Base64::decode_str(&encoded_license) {
        Ok(v) => v,
        Err(_) => return ERR_BASE64_DECODE_FAIL,
    };

    // 라이선스 JSON 파싱
    let mut license = match License::from_json(&license_json) {
        Ok(v) => v,
        Err(_) => return ERR_JSON_PARSE_FAIL,
    };

    // 서명 추출
    let signature_b64 = match license.signature.take() {
        Some(v) if !v.is_empty() => v,
        _ => return ERR_SIGNATURE_FAIL,
    };

    // 서명 Base64 디코딩
    let signature_bytes = match Base64::decode(signature_b64.as_bytes().to_vec()) {
        Ok(v) => v,
        Err(_) => return ERR_BASE64_DECODE_FAIL,
    };

    // payload 재구성 (licgen에서 서명할 때 payload와 동일해야 함)
    license.signature = None;
    let payload_json = match license.to_json() {
        Ok(v) => v,
        Err(_) => return ERR_PAYLOAD_REBUILD_FAIL,
    };

    // PEM 공개키로 서명 검증
    let mut key_pair = Ed25519KeyPair::new();
    if let Err(_) = key_pair.set_public_key_pem(&public_key_pem) {
        return ERR_PUBLIC_KEY_PARSE_FAIL;
    }

    // 서명 검증
    if key_pair.verify(&payload_json, &signature_bytes) {
        return OK;
    } else {
        return ERR_SIGNATURE_VERIFY_FAIL;
    }
}
