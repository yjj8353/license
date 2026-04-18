use rand_core::OsRng;
use rsa::sha2::Sha256;
use rsa::{
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    pkcs8::{
        DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
    },
    signature::{SignatureEncoding, Signer, Verifier},
    RsaPrivateKey, RsaPublicKey,
};

use crate::signature::{KeyPair, DigitalSignature};

const DEFAULT_KEY_BITS: usize = 2048;

pub struct RsaKeyPair {
    key_pair: KeyPair,
}

impl RsaKeyPair {
    fn private_key(&self) -> Result<RsaPrivateKey, Box<dyn std::error::Error>> {
        Ok(RsaPrivateKey::from_pkcs8_der(&self.key_pair.private_key)?)
    }

    fn public_key(&self) -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
        Ok(RsaPublicKey::from_public_key_der(&self.key_pair.public_key)?)
    }

    /// 지정한 비트 길이로 RSA 키 쌍 생성
    pub fn generate_with_bits(bits: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let private_key = RsaPrivateKey::new(&mut OsRng, bits)?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            key_pair: KeyPair {
                private_key: private_key.to_pkcs8_der()?.as_bytes().to_vec(),
                public_key: public_key.to_public_key_der()?.as_bytes().to_vec(),
            },
        })
    }
}

impl DigitalSignature for RsaKeyPair {
    fn new() -> Self {
        Self {
            key_pair: KeyPair {
                private_key: Vec::new(),
                public_key: Vec::new(),
            },
        }
    }

    /// 2048비트 RSA 키 쌍 생성
    fn generate() -> Result<Self, Box<dyn std::error::Error>> {
        Self::generate_with_bits(DEFAULT_KEY_BITS)
    }

    /// 데이터를 PKCS1v15 + SHA-256으로 서명 → 서명 바이트 반환
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.private_key()
            .map(|private_key| {
                SigningKey::<Sha256>::new(private_key)
                    .sign(data)
                    .to_bytes()
                    .to_vec()
            })
            .unwrap_or_default()
    }

    /// 자신의 공개키로 서명 검증
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        self.public_key()
            .map(|public_key| verify_with_public_key(&public_key, data, signature))
            .unwrap_or(false)
    }

    /// 개인키 → PKCS#8 PEM 문자열로 내보내기
    fn private_key_pem(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(self.private_key()?.to_pkcs8_pem(LineEnding::LF)?.to_string())
    }

    /// 공개키 → SPKI PEM 문자열로 내보내기
    fn public_key_pem(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(self.public_key()?.to_public_key_pem(LineEnding::LF)?)
    }

    /// PKCS#8 PEM 개인키 문자열에서 키 쌍 복원
    fn from_private_pem(pem: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            key_pair: KeyPair {
                private_key: private_key.to_pkcs8_der()?.as_bytes().to_vec(),
                public_key: public_key.to_public_key_der()?.as_bytes().to_vec(),
            },
        })
    }

    fn set_public_key_pem(&mut self, public_key_pem: &str) {
        self.key_pair.public_key = public_key_pem.as_bytes().to_vec();
    }
}

/// 공개키(참조)로 서명 검증 — 공개키만 보유한 쪽에서 호출
pub fn verify_with_public_key(
    public_key: &RsaPublicKey,
    data: &[u8],
    signature: &[u8],
) -> bool {
    let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());
    Signature::try_from(signature)
        .map(|sig| verifying_key.verify(data, &sig).is_ok())
        .unwrap_or(false)
}

// #[cfg(test)]
// mod tests {
//     use crate::keypair::KeyPair;
//     use super::{verify_with_public_key, RsaKeyPair};

//     /// 공통 테스트 픽스처
//     fn kp() -> RsaKeyPair {
//         <RsaKeyPair as KeyPair>::generate().expect("키 쌍 생성 실패")
//     }

//     #[test]
//     fn generate_keypair_succeeds() {
//         assert!(<RsaKeyPair as KeyPair>::generate().is_ok());
//     }

//     #[test]
//     fn sign_and_verify_succeeds() {
//         let kp = kp();
//         let sig = kp.sign(b"hello license");
//         assert!(kp.verify(b"hello license", &sig));
//     }

//     #[test]
//     fn verify_with_tampered_data_fails() {
//         let kp = kp();
//         let sig = kp.sign(b"original data");
//         assert!(!kp.verify(b"tampered data", &sig));
//     }

//     #[test]
//     fn verify_with_tampered_signature_fails() {
//         let kp = kp();
//         let mut sig = kp.sign(b"data");
//         sig[0] ^= 0xFF; // 첫 바이트 변조
//         assert!(!kp.verify(b"data", &sig));
//     }

//     #[test]
//     fn verify_with_wrong_keypair_fails() {
//         let kp1 = kp();
//         let kp2 = kp();
//         let sig = kp1.sign(b"data");
//         // kp1으로 서명한 것을 kp2로 검증 → 실패해야 함
//         assert!(!kp2.verify(b"data", &sig));
//     }

//     #[test]
//     fn pem_round_trip_preserves_signing_ability() {
//         let kp = kp();
//         let pem = kp.private_key_pem().expect("PEM 내보내기 실패");

//         let kp2 = <RsaKeyPair as KeyPair>::from_private_pem(&pem).expect("PEM 복원 실패");
//         let sig = kp.sign(b"round trip");

//         // 원본 키 서명 → 복원된 키로 검증
//         assert!(kp2.verify(b"round trip", &sig));
//     }

//     #[test]
//     fn public_key_pem_and_standalone_verify() {
//         let kp = kp();
//         let pub_pem = kp.public_key_pem().expect("공개키 PEM 내보내기 실패");

//         // 공개키 PEM에서 RsaPublicKey 복원
//         use rsa::pkcs8::DecodePublicKey;
//         let pub_key = rsa::RsaPublicKey::from_public_key_pem(&pub_pem)
//             .expect("공개키 PEM 복원 실패");

//         let sig = kp.sign(b"standalone verify");
//         assert!(verify_with_public_key(&pub_key, b"standalone verify", &sig));
//     }

//     #[test]
//     fn sign_is_deterministic() {
//         // PKCS1v15는 결정론적 서명 — 같은 입력이면 서명이 동일해야 함
//         let kp = kp();
//         let sig1 = kp.sign(b"deterministic");
//         let sig2 = kp.sign(b"deterministic");
//         assert_eq!(sig1, sig2);
//     }
// }
