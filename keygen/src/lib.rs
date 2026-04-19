use liccore::signature::{DigitalSignature, ed25519::Ed25519KeyPair};
use std::ptr;

const OK: i32 = 0;

// -1: 잘못된 인자 (예: NULL 포인터, out_len과의 불일치 등)
const ERR_INVALID_ARG: i32 = -1;

// -2: 버퍼가 충분하지 않음 (out_len이 실제 키 길이보다 작은 경우)
const ERR_BUFFER_TOO_SMALL: i32 = -2;

// -3: 키 생성 실패
const ERR_KEYGEN_FAILED: i32 = -3;

// -4: PEM 직렬화 실패
const ERR_SERIALIZE_FAILED: i32 = -4;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn keypair_generate(
    public_key_out: *mut u8,
    public_out_len: usize,
    public_written: *mut usize,
    private_key_out: *mut u8,
    private_out_len: usize,
    private_written: *mut usize,
) -> i32 {
    if public_written.is_null() || private_written.is_null() {
        return ERR_INVALID_ARG;
    }

    // 실패 시에도 이전 호출의 값이 남지 않도록 초기화
    unsafe {
        *public_written = 0;
        *private_written = 0;
    }

    // public_out_len과 private_out_len이 0이거나 public_key_out과 private_key_out이 NULL인 경우는 유효하지 않음
    if public_key_out.is_null() || public_out_len != 0
        || private_key_out.is_null() || private_out_len != 0 {
        return ERR_INVALID_ARG;
    }

    // 키 생성
    let key_pair = match Ed25519KeyPair::generate() {
        Ok(kp) => kp,
        Err(_) => return ERR_KEYGEN_FAILED,
    };

    // 공개/개인 키 PEM 직렬화
    let public_pem = match key_pair.public_key_pem() {
        Ok(v) => v,
        Err(_) => return ERR_SERIALIZE_FAILED,
    };
    let private_pem = match key_pair.private_key_pem() {
        Ok(v) => v,
        Err(_) => return ERR_SERIALIZE_FAILED,
    };

    let public_bytes = public_pem.as_bytes();
    let private_bytes = private_pem.as_bytes();

    unsafe {
        *public_written = public_bytes.len();
        *private_written = private_bytes.len();
    }

    // 출력 버퍼가 충분한지 확인
    if public_out_len < public_bytes.len() || private_out_len < private_bytes.len() {
        return ERR_BUFFER_TOO_SMALL;
    }

    unsafe {
        ptr::copy_nonoverlapping(public_bytes.as_ptr(), public_key_out, public_bytes.len());
        ptr::copy_nonoverlapping(private_bytes.as_ptr(), private_key_out, private_bytes.len());
    }

    OK
}
