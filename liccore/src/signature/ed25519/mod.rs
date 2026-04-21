use std::error::Error;

use ed25519_dalek::{
    Signature, SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, spki::EncodePublicKey},
};
use ed25519_dalek::ed25519::signature::{Signer, Verifier};
use pkcs8::LineEnding;
use rand_core::OsRng;

use crate::signature::{KeyPair, DigitalSignature};

/// Ed25519 개인키 + 공개키 쌍
pub struct Ed25519KeyPair {
    key_pair: KeyPair,
}

impl Ed25519KeyPair {
    fn signing_key(&self) -> Result<SigningKey, Box<dyn Error>> {
        let bytes: [u8; 32] = self.key_pair.private_key.as_slice().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Ed25519 private key length",
            )
        })?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    fn verifying_key(&self) -> Result<VerifyingKey, Box<dyn Error>> {
        let bytes: [u8; 32] = self.key_pair.public_key.as_slice().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Ed25519 public key length",
            )
        })?;
        Ok(VerifyingKey::from_bytes(&bytes)?)
    }
}

impl DigitalSignature for Ed25519KeyPair {
    fn new() -> Self {
        Self {
            key_pair: KeyPair {
                private_key: Vec::new(),
                public_key: Vec::new(),
            },
        }
    }

    /// Ed25519 키 쌍 생성 (키 길이 고정: 256 bit)
    fn generate() -> Result<Self, Box<dyn Error>> {
        let signing_key = SigningKey::generate(&mut OsRng);
        Ok(Self {
            key_pair: KeyPair {
                private_key: signing_key.to_bytes().to_vec(),
                public_key: signing_key.verifying_key().to_bytes().to_vec(),
            },
        })
    }

    /// 데이터를 Ed25519로 서명 → 서명 바이트(64 bytes) 반환
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        self.signing_key()
            .map(|signing_key| {
                let sig: Signature = signing_key.sign(data);
                sig.to_bytes().to_vec()
            })
    }

    /// 자신의 공개키로 서명 검증
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let Ok(sig_bytes): Result<[u8; 64], _> = signature.try_into() else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_bytes);

        self.verifying_key()
            .map(|verifying_key| verifying_key.verify(data, &sig).is_ok())
            .unwrap_or(false)
    }

    /// 개인키 → PKCS#8 PEM 문자열로 내보내기
    fn private_key_pem(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.signing_key()?.to_pkcs8_pem(LineEnding::LF)?.to_string())
    }

    /// 공개키 → SPKI PEM 문자열로 내보내기
    fn public_key_pem(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.verifying_key()?.to_public_key_pem(LineEnding::LF)?)
    }

    /// PKCS#8 PEM 개인키 문자열에서 키 쌍 복원
    fn from_private_pem(pem: &str) -> Result<Self, Box<dyn Error>> {
        let signing_key = SigningKey::from_pkcs8_pem(pem)?;
        Ok(Self {
            key_pair: KeyPair {
                private_key: signing_key.to_bytes().to_vec(),
                public_key: signing_key.verifying_key().to_bytes().to_vec(),
            },
        })
    }

    fn set_public_key_pem(&mut self, public_key_pem: &str) -> Result<(), Box<dyn Error>> {
        self.key_pair.public_key = VerifyingKey::from_public_key_pem(public_key_pem)
            .map(|key| key.to_bytes().to_vec())?;
    
        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::keypair::KeyPair;
//     use super::Ed25519KeyPair;

//     fn kp() -> Ed25519KeyPair {
//         <Ed25519KeyPair as KeyPair>::generate().expect("키 쌍 생성 실패")
//     }

//     #[test]
//     fn generate_keypair_succeeds() {
//         let _ = <Ed25519KeyPair as KeyPair>::generate().expect("키 쌍 생성 실패");
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

//         let kp2 = <Ed25519KeyPair as KeyPair>::from_private_pem(&pem).expect("PEM 복원 실패");
//         let sig = kp.sign(b"round trip");

//         // 원본 키 서명 → 복원된 키로 검증
//         assert!(kp2.verify(b"round trip", &sig));
//     }

//     #[test]
//     fn sign_is_deterministic() {
//         // Ed25519는 결정론적 서명 — 같은 입력이면 서명이 동일해야 함
//         let kp = kp();
//         let sig1 = kp.sign(b"deterministic");
//         let sig2 = kp.sign(b"deterministic");
//         assert_eq!(sig1, sig2);
//     }

//     #[test]
//     fn signature_length_is_64_bytes() {
//         let kp = kp();
//         let sig = kp.sign(b"length check");
//         assert_eq!(sig.len(), 64);
//     }
// }
