use std::error::Error;

pub trait Base {
    fn encode(value: Vec<u8>) -> String;
    fn encode_str(value: &str) -> String;
    fn decode(encoded_value: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>;
    fn decode_str(encoded_value: &str) -> Result<String, Box<dyn Error>>;
}

pub mod base16;
pub mod base64;