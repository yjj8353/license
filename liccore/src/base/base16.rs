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
        let s = from_utf8(&encoded_value)?;
        Self::decode_str(s).map(|decoded| decoded.into_bytes())
    }

    fn decode_str(encoded_value: &str) -> Result<String, Box<dyn Error>> {
        let hex = encoded_value.trim();
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()?;
        
        Ok(String::from_utf8(bytes)?)
    }
}
