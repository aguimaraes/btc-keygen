pub mod address;
pub mod entropy;
pub mod keygen;
pub mod output;
pub mod pubkey;
pub mod wif;

#[cfg(test)]
mod pipeline_tests {
    use crate::address;
    use crate::entropy::FixedEntropy;
    use crate::keygen;
    use crate::pubkey;
    use crate::wif;

    /// Full end-to-end test with private key = 1.
    ///
    /// Expected values:
    /// - Private key hex: 0000...0001
    /// - WIF: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
    /// - Compressed pubkey: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    /// - Address: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
    #[test]
    fn test_full_pipeline_deterministic() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 0x01;

        let entropy = FixedEntropy::new(key_bytes.to_vec());
        let private_key = keygen::generate(&entropy).expect("generation must succeed");

        assert_eq!(private_key.as_bytes(), &key_bytes);

        let wif_str = wif::encode_wif(private_key.as_bytes());
        assert_eq!(
            wif_str,
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        );

        let secret_key = private_key.to_secret_key();
        let compressed_pubkey = pubkey::derive_pubkey(&secret_key);
        let pubkey_hex: String = compressed_pubkey
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(
            pubkey_hex,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );

        let addr = address::derive_address(&compressed_pubkey);
        assert_eq!(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    /// Second full pipeline test with private key = 2.
    #[test]
    fn test_full_pipeline_known_vector_two() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 0x02;

        let entropy = FixedEntropy::new(key_bytes.to_vec());
        let private_key = keygen::generate(&entropy).expect("generation must succeed");

        let wif_str = wif::encode_wif(private_key.as_bytes());
        // WIF for private key = 2 (compressed, mainnet).
        assert_eq!(
            wif_str,
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4"
        );

        let secret_key = private_key.to_secret_key();
        let compressed_pubkey = pubkey::derive_pubkey(&secret_key);
        let pubkey_hex: String = compressed_pubkey
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(
            pubkey_hex,
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        );

        let addr = address::derive_address(&compressed_pubkey);
        assert_eq!(addr, "bc1qq6hag67dl53wl99vzg42z8eyzfz2xlkvxechjp");
    }

    /// Two different entropy inputs must produce entirely different outputs.
    #[test]
    fn test_pipeline_different_entropy_different_outputs() {
        let mut bytes_a = [0u8; 32];
        bytes_a[31] = 0x01;
        let mut bytes_b = [0u8; 32];
        bytes_b[31] = 0x02;

        let key_a = keygen::generate(&FixedEntropy::new(bytes_a.to_vec())).unwrap();
        let key_b = keygen::generate(&FixedEntropy::new(bytes_b.to_vec())).unwrap();

        let sk_a = key_a.to_secret_key();
        let sk_b = key_b.to_secret_key();

        let pubkey_a = pubkey::derive_pubkey(&sk_a);
        let pubkey_b = pubkey::derive_pubkey(&sk_b);

        let addr_a = address::derive_address(&pubkey_a);
        let addr_b = address::derive_address(&pubkey_b);

        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
        assert_ne!(pubkey_a, pubkey_b);
        assert_ne!(addr_a, addr_b);
        assert_ne!(
            wif::encode_wif(key_a.as_bytes()),
            wif::encode_wif(key_b.as_bytes())
        );
    }
}
