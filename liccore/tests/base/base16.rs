#[cfg(test)]
mod tests {
    use liccore::base::Base;
    use liccore::base::base16::Base16;

    #[test]
    fn round_trip_binary_data() {
        let text = "hello rust";
        let binary_data = text.as_bytes().to_vec();
        let encoded = Base16::encode(binary_data.clone());
        let decoded = Base16::decode(encoded.as_bytes().to_vec()).expect("encoded data should decode");

        println!("encoded: {encoded}");
        println!("decoded: {:?}", decoded);

        assert_eq!(decoded, binary_data);
    }

    #[test]
    fn round_trip_utf8_text() {
        let text = "hello rust";
        let encoded = Base16::encode_str(text);
        let decoded = Base16::decode_str(&encoded).expect("encoded text should decode");

        println!("encoded: {encoded}");
        println!("decoded: {decoded}");

        assert_eq!(decoded, text);
    }
}
