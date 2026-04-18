use std::error::Error;
use std::str::from_utf8;

use super::Base;

pub struct Base16;

impl Base for Base16 {
    fn encode(value: Vec<u8>) -> String {
        value.iter().map(|b| format!("{:02X}", b)).collect()
    }

    fn encode_str(value: &str) -> String {
        Self::encode(value.as_bytes().to_vec())
    }

    fn decode(encoded_value: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        let s = from_utf8(&encoded_value)
            .map_err(|e| Box::<dyn Error>::from(format!("디코딩 할 수 없습니다: {}", e)))?;

        Self::decode_str(s).map(|decoded| decoded.into_bytes())
    }

    fn decode_str(encoded_value: &str) -> Result<String, Box<dyn Error>> {
        let hex = encoded_value.trim();
        if hex.len() % 2 != 0 {
            return Err(Box::<dyn Error>::from("문자열의 길이는 짝수여야 합니다."));
        }

        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|e| -> Box<dyn Error> { format!("유효하지 않은 16진수 문자 위치 {}: {}", i, e).into() })
            })
            .collect::<Result<Vec<u8>, Box<dyn Error>>>()?;
        
        String::from_utf8(bytes)
        .map_err(|e| -> Box<dyn Error> { format!("디코딩된 바이트에 유효하지 않은 UTF-8: {}", e).into() })
    }
}
