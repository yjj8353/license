pub trait Base {
    fn encode(value: Vec<u8>) -> String;
    fn encode_str(value: &str) -> String;
    fn decode(encoded_value: Vec<u8>) -> Result<Vec<u8>, String>;
    fn decode_str(encoded_value: &str) -> Result<String, String>;
}

pub mod base64;