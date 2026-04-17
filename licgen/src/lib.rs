use std::os::raw::c_char;
use std::ptr;
use liccore::base::Base;
use liccore::common::to_str;
use liccore::keypair::SignatureAlgorithm;
use liccore::keypair::ed25519::Ed25519KeyPair;
use liccore::license::{IssuanceType, License, ReissueReason};
use liccore::base::base64::Base64;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn license_generate(
    product_name: *const c_char,
    issuance_type: *const c_char,
    reissue_reason: *const c_char,
    license_key: *const c_char,
    domain: *const c_char,
    issued_at: *const c_char,
    expires_at: *const c_char,
    license_version: *const c_char,
    private_key: *const c_char,
    out_buf: *mut c_char,
    out_buf_len: usize,
    out_written: *mut usize,
) -> i32 {
    // 에러코드
    // -1: out_buf,  out_written, out_buf_len이 유효하지 않음
    // -2: 유효하지 않은 issuance_type
    // -3: 유효하지 않은 reissue_reason
    // -4: 유효하지 않은 License 정보
    // -5: 입력 값을 License 구조체로 변환하는 과정에서 실패
    // -6: License 정보를 JSON 형식으로 변환하는 과정에서 실패
    // -7: out_buf 길이 부족
    // -8: 유효하지 않은 private_key

    // 값을 입력받을 포인터가 유효한지 확인
    if out_buf.is_null() || out_written.is_null() || out_buf_len == 0 {
        return -1;
    }

    if private_key.is_null() {
        return -8;
    }

    let private_key_pem = match to_str(private_key) {
        Some(value) if !value.trim().is_empty() => value,
        _ => return -8,
    };

    // 외부에서 받은 reissue_reason을 ReissueReason enum으로 변환하는 클로저
    let parse_reissue_reason = |value: Option<String>| -> Result<Option<ReissueReason>, i32> {
        match value {
            Some(reason) if !reason.trim().is_empty() => reason
                .parse::<ReissueReason>()
                .map(Some)
                .map_err(|_| -3),
            _ => Ok(None),
        }
    };

    // 외부로부터 입력받은 값으로 License 구조체 생성
    let mut info = match (
        to_str(product_name),
        to_str(issuance_type),
        to_str(license_key),
        to_str(domain),
        to_str(issued_at),
        to_str(expires_at),
        to_str(license_version),
    ) {
        (
            Some(product_name),
            Some(issuance_type),
            Some(license_key),
            Some(domain),
            Some(issued_at),
            Some(expires_at),
            Some(license_version),
        ) => {

            // issuance_type 파싱
            let issuance_type = match issuance_type.parse::<IssuanceType>() {
                Ok(value) => value,
                Err(_) => return -2,
            };

            // reissue_reason 파싱
            let reissue_reason = match parse_reissue_reason(to_str(reissue_reason)) {
                Ok(value) => value,
                Err(code) => return code,
            };

            let license = License::new(
                product_name,
                issuance_type,
                reissue_reason,
                license_key,
                domain,
                issued_at,
                expires_at,
                None,
                license_version,
            );

            if license.validate().is_err() {
                return -4;
            }

            license
        }
        _ => return -5,
    };

    // JSON 형식으로 변환
    let mut license_json = match info.to_json() {
        Ok(json) => json,
        Err(_) => return -6,
    };
    let key_pair = match Ed25519KeyPair::from_private_pem(&private_key_pem) {
        Ok(value) => value,
        Err(_) => return -8,
    };
    let signature_bytes = key_pair.sign(license_json.as_bytes());

    // signature 필드 값을 설정 한 새로운 json 문자열 생성
    let signature_b64 = Base64::encode(signature_bytes);
    info.signature = Some(signature_b64);
    license_json = match info.to_json() {
        Ok(json) => json,
        Err(_) => return -6,
    };

    let encoded_license_json = Base64::encode_str(license_json.as_str());
    let bytes = encoded_license_json.as_bytes();
    let need = bytes.len() + 1;

    if need > out_buf_len {
        unsafe { *out_written = bytes.len() };
        return -7;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf as *mut u8, bytes.len());
        *out_buf.add(bytes.len()) = 0;
        *out_written = bytes.len();
    }

    0
}

#[cfg(test)]
mod tests {
    use super::license_generate;
    use std::ffi::{CString};
    use std::os::raw::c_char;

    struct Inputs {
        product_name: CString,
        issuance_type: CString,
        reissue_reason: CString,
        license_key: CString,
        domain: CString,
        issued_at: CString,
        expires_at: CString,
        license_version: CString,
        private_key: CString,
    }

    fn make_inputs(private_key: &str) -> Inputs {
        Inputs {
            product_name: CString::new("Dashboard").unwrap(),
            issuance_type: CString::new("initial").unwrap(),
            reissue_reason: CString::new("").unwrap(),
            license_key: CString::new("XXXX-YYYY-ZZZZ-AAAA").unwrap(),
            domain: CString::new("example.com").unwrap(),
            issued_at: CString::new("2026-04-12T00:00:00Z").unwrap(),
            expires_at: CString::new("2027-04-12T00:00:00Z").unwrap(),
            license_version: CString::new("1.0").unwrap(),
            private_key: CString::new(private_key).unwrap(),
        }
    }

    unsafe fn call_license_generate(inputs: &Inputs, out_buf: *mut c_char, out_len: usize, out_written: *mut usize) -> i32 {
        unsafe {
            license_generate(
                inputs.product_name.as_ptr(),
                inputs.issuance_type.as_ptr(),
                inputs.reissue_reason.as_ptr(),
                inputs.license_key.as_ptr(),
                inputs.domain.as_ptr(),
                inputs.issued_at.as_ptr(),
                inputs.expires_at.as_ptr(),
                inputs.license_version.as_ptr(),
                inputs.private_key.as_ptr(),
                out_buf,
                out_len,
                out_written,
            )
        }
    }

    #[test]
    fn license_generate_rejects_invalid_private_key() {
        let inputs = make_inputs("not a valid pem");
        let mut buffer = vec![0 as c_char; 512];
        let mut written = 123usize;

        let rc = unsafe {
            call_license_generate(&inputs, buffer.as_mut_ptr(), buffer.len(), &mut written)
        };

        assert_eq!(rc, -8);
    }
}
