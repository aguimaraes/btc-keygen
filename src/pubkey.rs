/// Derives the compressed public key (33 bytes) from a private key.
///
/// Returns a 33-byte array where the first byte is `0x02` or `0x03`
/// (depending on the y-coordinate parity) followed by the 32-byte
/// x-coordinate. Pass the result to [`derive_address`](crate::derive_address)
/// to get the corresponding Bitcoin address.
pub fn derive_pubkey(key: &crate::keygen::PrivateKey) -> [u8; 33] {
    let secp = secp256k1::Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &key.to_secret_key());
    public_key.serialize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::PrivateKey;

    fn key_from_hex(hex: &str) -> PrivateKey {
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        PrivateKey::from_bytes(bytes)
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // Private key = 1 corresponds to the generator point G.
    // Compressed: 02 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
    #[test]
    fn test_pubkey_vector_generator_point() {
        let key = key_from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        let pubkey = derive_pubkey(&key);
        let hex = bytes_to_hex(&pubkey);
        assert_eq!(
            hex,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    // Private key = 2.
    // Compressed public key is well-known.
    #[test]
    fn test_pubkey_vector_scalar_two() {
        let key = key_from_hex("0000000000000000000000000000000000000000000000000000000000000002");
        let pubkey = derive_pubkey(&key);
        let hex = bytes_to_hex(&pubkey);
        assert_eq!(
            hex,
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        );
    }

    #[test]
    fn test_pubkey_starts_with_02_or_03() {
        let keys = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        ];
        for hex in &keys {
            let key = key_from_hex(hex);
            let pubkey = derive_pubkey(&key);
            assert!(
                pubkey[0] == 0x02 || pubkey[0] == 0x03,
                "compressed pubkey must start with 0x02 or 0x03, got: 0x{:02x}",
                pubkey[0]
            );
        }
    }

    #[test]
    fn test_pubkey_length_33_bytes() {
        let key = key_from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        let pubkey = derive_pubkey(&key);
        assert_eq!(pubkey.len(), 33);
    }
}
