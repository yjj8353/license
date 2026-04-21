use std::error::Error;

pub struct KeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub trait DigitalSignature: Sized {

    /// 생성자
    fn new() -> Self;

    /// 키 생성
    fn generate() -> Result<Self, Box<dyn Error>>;

    /// 데이터 서명
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;

    /// 서명 검증
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool;

    /// 개인키 PEM 내보내기
    fn private_key_pem(&self) -> Result<String, Box<dyn Error>>;

    /// 공개키 PEM 내보내기
    fn public_key_pem(&self) -> Result<String, Box<dyn Error>>;

    /// 개인키 PEM에서 키 쌍 복원
    fn from_private_pem(pem: &str) -> Result<Self, Box<dyn Error>>;

    /// 공개키 설정
    fn set_public_key_pem(&mut self, public_key_pem: &str);
}

pub mod ed25519;
pub mod rsa;
