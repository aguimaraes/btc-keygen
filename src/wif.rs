/// Encodes a 32-byte private key as a Wallet Import Format (WIF) string.
///
/// Uses mainnet prefix `0x80` and appends `0x01` compression flag.
/// The checksum is the first 4 bytes of the double SHA-256 of the payload.
/// The result is Base58 encoded.
///
/// For compressed mainnet keys, the output starts with `K` or `L` and is 52
/// characters long.
pub fn encode_wif(private_key_bytes: &[u8; 32]) -> String {
    // Build payload: 0x80 | 32 key bytes | 0x01 (compressed flag)
    let mut payload = [0u8; 34];
    payload[0] = 0x80;
    payload[1..33].copy_from_slice(private_key_bytes);
    payload[33] = 0x01;

    // Checksum: first 4 bytes of SHA256(SHA256(payload))
    use bitcoin_hashes::{sha256, Hash};
    let hash1 = sha256::Hash::hash(&payload);
    let hash2 = sha256::Hash::hash(hash1.as_ref());
    let checksum = &hash2[..4];

    // Final data: payload + checksum = 38 bytes
    let mut data = [0u8; 38];
    data[..34].copy_from_slice(&payload);
    data[34..38].copy_from_slice(checksum);

    base58_encode(&data)
}

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(data: &[u8]) -> String {
    // Count leading zeros — each becomes a '1' in Base58.
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Convert bytes to a big integer (big-endian), then repeatedly divide by 58.
    let mut num: Vec<u8> = data.to_vec();
    let mut digits: Vec<u8> = Vec::new();

    while !num.is_empty() {
        let mut remainder = 0u32;
        let mut next = Vec::new();

        for &byte in &num {
            let accumulator = (remainder << 8) | byte as u32;
            let quotient = accumulator / 58;
            remainder = accumulator % 58;

            if !next.is_empty() || quotient > 0 {
                next.push(quotient as u8);
            }
        }

        digits.push(remainder as u8);
        num = next;
    }

    // Build result: leading '1's + reversed digits.
    let mut result = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        result.push('1');
    }
    for &d in digits.iter().rev() {
        result.push(BASE58_ALPHABET[d as usize] as char);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_32_bytes(hex: &str) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        bytes
    }

    // Known-answer test: private key = 1.
    // Source: Bitcoin wiki, widely published test vector.
    #[test]
    fn test_wif_vector_scalar_one() {
        let key =
            hex_to_32_bytes("0000000000000000000000000000000000000000000000000000000000000001");
        let wif = encode_wif(&key);
        assert_eq!(wif, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
    }

    // Known-answer test: Bitcoin wiki WIF example.
    // Private key: 0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
    // Compressed WIF: KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617
    #[test]
    fn test_wif_vector_two() {
        let key =
            hex_to_32_bytes("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D");
        let wif = encode_wif(&key);
        assert_eq!(wif, "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617");
    }

    #[test]
    fn test_wif_starts_with_k_or_l() {
        // A few different valid keys.
        let keys: Vec<[u8; 32]> = vec![
            hex_to_32_bytes("0000000000000000000000000000000000000000000000000000000000000001"),
            hex_to_32_bytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"),
            hex_to_32_bytes("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"),
        ];

        for key in &keys {
            let wif = encode_wif(key);
            assert!(
                wif.starts_with('K') || wif.starts_with('L'),
                "compressed mainnet WIF must start with K or L, got: {}",
                wif
            );
        }
    }

    #[test]
    fn test_wif_length_52() {
        let key =
            hex_to_32_bytes("0000000000000000000000000000000000000000000000000000000000000001");
        let wif = encode_wif(&key);
        assert_eq!(
            wif.len(),
            52,
            "compressed mainnet WIF must be 52 characters"
        );
    }

    #[test]
    fn test_wif_valid_base58_characters() {
        let key =
            hex_to_32_bytes("0000000000000000000000000000000000000000000000000000000000000001");
        let wif = encode_wif(&key);
        let base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for ch in wif.chars() {
            assert!(
                base58_alphabet.contains(ch),
                "WIF contains invalid Base58 character: '{}'",
                ch
            );
        }
    }

    /// Decodes a Base58 string back to bytes (test helper).
    fn base58_decode(s: &str) -> Vec<u8> {
        let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let leading_ones = s.chars().take_while(|&c| c == '1').count();

        let mut num: Vec<u8> = Vec::new();
        for ch in s.bytes() {
            let val = alphabet
                .iter()
                .position(|&b| b == ch)
                .expect("invalid base58 character") as u32;

            let mut carry = val;
            for byte in num.iter_mut().rev() {
                carry += *byte as u32 * 58;
                *byte = (carry & 0xFF) as u8;
                carry >>= 8;
            }
            while carry > 0 {
                num.insert(0, (carry & 0xFF) as u8);
                carry >>= 8;
            }
        }

        let mut result = vec![0u8; leading_ones];
        result.extend_from_slice(&num);
        result
    }

    #[test]
    fn test_wif_checksum_valid() {
        use bitcoin_hashes::{sha256, Hash};

        let key =
            hex_to_32_bytes("0000000000000000000000000000000000000000000000000000000000000001");
        let wif = encode_wif(&key);
        let decoded = base58_decode(&wif);

        // WIF for compressed mainnet: 1 + 32 + 1 + 4 = 38 bytes.
        assert_eq!(decoded.len(), 38, "decoded WIF must be 38 bytes");

        // Split into payload (34 bytes) and checksum (4 bytes).
        let payload = &decoded[..34];
        let checksum = &decoded[34..38];

        // Recompute checksum.
        let hash1 = sha256::Hash::hash(payload);
        let hash2 = sha256::Hash::hash(hash1.as_ref());
        let expected_checksum = &hash2[..4];

        assert_eq!(
            checksum, expected_checksum,
            "WIF checksum must match double-SHA256 of payload"
        );

        // Also verify payload structure.
        assert_eq!(payload[0], 0x80, "first byte must be mainnet prefix 0x80");
        assert_eq!(
            &payload[1..33],
            key.as_slice(),
            "bytes 1-32 must be the private key"
        );
        assert_eq!(
            payload[33], 0x01,
            "last payload byte must be 0x01 (compressed flag)"
        );
    }
}
