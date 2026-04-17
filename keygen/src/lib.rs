use liccore::keypair::{SignatureAlgorithm, ed25519::Ed25519KeyPair};
use std::ptr;

const OK: i32 = 0;
const ERR_INVALID_ARG: i32 = -1;
const ERR_BUFFER_TOO_SMALL: i32 = -3;
const ERR_KEYGEN_FAILED: i32 = -4;
const ERR_SERIALIZE_FAILED: i32 = -5;

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

    let public_query_mode = public_key_out.is_null();
    let private_query_mode = private_key_out.is_null();

    // 공개키/개인키는 같은 모드(둘 다 조회 or 둘 다 복사)로 처리
    if public_query_mode != private_query_mode {
        return ERR_INVALID_ARG;
    }

    // NULL 포인터는 out_len이 0일 때만 허용
    if (public_query_mode && public_out_len != 0)
        || (private_query_mode && private_out_len != 0)
        || (!public_query_mode && public_out_len == 0)
        || (!private_query_mode && private_out_len == 0)
    {
        return ERR_INVALID_ARG;
    }

    let key_pair = match Ed25519KeyPair::generate() {
        Ok(kp) => kp,
        Err(_) => return ERR_KEYGEN_FAILED,
    };

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

    if public_query_mode {
        return OK;
    }

    if public_out_len < public_bytes.len() || private_out_len < private_bytes.len() {
        return ERR_BUFFER_TOO_SMALL;
    }

    unsafe {
        ptr::copy_nonoverlapping(public_bytes.as_ptr(), public_key_out, public_bytes.len());
        ptr::copy_nonoverlapping(private_bytes.as_ptr(), private_key_out, private_bytes.len());
    }

    OK
}
