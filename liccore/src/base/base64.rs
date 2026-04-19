use std::error::Error;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use super::Base;

pub struct Base64;

impl Base for Base64 {
    fn encode(value: Vec<u8>) -> String {
        STANDARD.encode(value)
    }

    fn encode_str(value: &str) -> String {
        Self::encode(
            value.as_bytes().to_vec()
        )
    }

    fn decode(encoded_value: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(STANDARD.decode(encoded_value)?)
    }

    fn decode_str(encoded_value: &str) -> Result<String, Box<dyn Error>> {
        Self::decode(
            encoded_value.as_bytes().to_vec()
        )
        .and_then(|bytes| Ok(String::from_utf8(bytes)?))
    }
}
