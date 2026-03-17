/// Derives a native SegWit (P2WPKH) Bech32 address from a compressed public key.
///
/// Steps:
/// 1. Hash160: RIPEMD160(SHA256(pubkey)) -> 20 bytes
/// 2. Bech32 encode with HRP "bc" and witness version 0
///
/// The resulting address starts with "bc1q" and is 42 characters long.
pub fn derive_address(compressed_pubkey: &[u8; 33]) -> String {
    use bitcoin_hashes::{hash160, Hash};

    // Step 1: Hash160 = RIPEMD160(SHA256(pubkey))
    let hash = hash160::Hash::hash(compressed_pubkey);
    let witness_program = hash.as_ref(); // 20 bytes

    // Step 2: Bech32 encode with HRP "bc", witness version 0
    let hrp = bech32::Hrp::parse("bc").expect("valid HRP");
    bech32::segwit::encode_v0(hrp, witness_program).expect("valid witness program")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_33_bytes(hex: &str) -> [u8; 33] {
        assert_eq!(hex.len(), 66);
        let mut bytes = [0u8; 33];
        for i in 0..33 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        bytes
    }

    // Compressed pubkey for private key = 1 (the generator point G).
    // The corresponding P2WPKH address is well-known.
    // pubkey: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    // Hash160: 751e76e8199196d454941c45d1b3a323f1433bd6
    // Bech32 address: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
    #[test]
    fn test_address_from_generator_point() {
        let pubkey =
            hex_to_33_bytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let address = derive_address(&pubkey);
        assert_eq!(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    // Private key = 2 compressed pubkey.
    // pubkey: 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
    // Hash160: 06afd46bcdfd22ef94ac122aa11f241244a37ecc
    // Bech32: bc1qq6hag67dl53wl99vzg42z8eyzfz2xlkvxechjp
    #[test]
    fn test_address_from_scalar_two() {
        let pubkey =
            hex_to_33_bytes("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
        let address = derive_address(&pubkey);
        assert_eq!(address, "bc1qq6hag67dl53wl99vzg42z8eyzfz2xlkvxechjp");
    }

    #[test]
    fn test_address_starts_with_bc1q() {
        let pubkey =
            hex_to_33_bytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let address = derive_address(&pubkey);
        assert!(
            address.starts_with("bc1q"),
            "P2WPKH address must start with bc1q, got: {}",
            address
        );
    }

    #[test]
    fn test_address_length_42() {
        let pubkey =
            hex_to_33_bytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let address = derive_address(&pubkey);
        assert_eq!(
            address.len(),
            42,
            "P2WPKH Bech32 address must be 42 characters, got: {}",
            address.len()
        );
    }

    #[test]
    fn test_address_is_lowercase() {
        let pubkey =
            hex_to_33_bytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let address = derive_address(&pubkey);
        assert_eq!(
            address,
            address.to_lowercase(),
            "Bech32 address must be lowercase"
        );
    }

    #[test]
    fn test_address_valid_bech32_charset() {
        let pubkey =
            hex_to_33_bytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let address = derive_address(&pubkey);

        // Bech32 valid characters (after the separator '1').
        let bech32_chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

        // Split at the separator.
        let data_part = address
            .split('1')
            .nth(1)
            .expect("must contain separator '1'");
        for ch in data_part.chars() {
            assert!(
                bech32_chars.contains(ch),
                "address contains invalid Bech32 character: '{}'",
                ch
            );
        }
    }
}
