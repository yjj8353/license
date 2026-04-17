use super::Base;

pub struct Base16;

impl Base for Base16 {
    fn encode(value: Vec<u8>) -> String {
        value.iter().map(|b| format!("{:02X}", b)).collect()
    }

    fn encode_str(value: &str) -> String {
        Self::encode(value.as_bytes().to_vec())
    }

    fn decode(encoded_value: Vec<u8>) -> Result<Vec<u8>, String> {
        let s = std::str::from_utf8(&encoded_value)
            .map_err(|e| format!("Invalid UTF-8: {}", e))?;
        Self::decode_str(s).map(|decoded| decoded.into_bytes())
    }

    fn decode_str(encoded_value: &str) -> Result<String, String> {
        let hex = encoded_value.trim();
        if hex.len() % 2 != 0 {
            return Err("Hex string length must be even".to_string());
        }
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|e| format!("Invalid hex character at position {}: {}", i, e))
            })
            .collect::<Result<Vec<u8>, String>>()?;
        String::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8 in decoded bytes: {}", e))
    }
}
