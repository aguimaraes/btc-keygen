use crate::secret::SecretWif;
use bitcoin_hashes::sha256;
use zeroize::Zeroizing;

/// Encodes a private key as a Wallet Import Format (WIF) string.
///
/// WIF is the standard format for importing private keys into Bitcoin wallets.
/// This function produces a compressed, mainnet WIF string that starts with
/// `K` or `L` and is 52 characters long.
///
/// The encoding applies mainnet prefix `0x80`, appends the `0x01` compression
/// flag, and checksums with double SHA-256 before Base58 encoding.
///
/// The result is a [`SecretWif`]: it erases itself on drop and redacts its
/// `Debug` output. No intermediate `String` or `Vec` ever holds the key.
#[must_use]
pub fn encode_wif(private_key: &crate::keygen::PrivateKey) -> SecretWif {
    // Payload: 0x80 | 32 key bytes | 0x01 (compressed flag) | 4 checksum bytes
    let mut payload = Zeroizing::new([0u8; 38]);
    payload[0] = 0x80;
    payload[1..33].copy_from_slice(private_key.as_bytes());
    payload[33] = 0x01;

    // Checksum: first 4 bytes of SHA256(SHA256(payload)).
    // The hashes need no erasure: SHA-256 of the payload does not reveal it.
    let hash1 = sha256::Hash::hash(&payload[..34]).to_byte_array();
    let hash2 = sha256::Hash::hash(&hash1).to_byte_array();
    payload[34..].copy_from_slice(&hash2[..4]);

    base58_encode_wif(&payload)
}

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58-encodes a 38-byte WIF payload straight into a [`SecretWif`].
///
/// Allocation-free: the repeated division by 58 happens in place in a fixed
/// stack buffer that erases itself, and each digit is written directly into the
/// secret's final resting place. Nothing here can leave a stray heap copy.
///
/// A `0x80`-prefixed 38-byte payload always encodes to exactly 52 Base58
/// digits, which is why the output length is fixed and why there are no
/// leading zeros to translate into `1` characters.
fn base58_encode_wif(payload: &[u8; 38]) -> SecretWif {
    let mut num = Zeroizing::new(*payload);
    let mut wif = SecretWif::zeroed();
    let digits = wif.bytes_mut();

    // Most significant byte that is still non-zero; the divisions shrink the
    // number from the front.
    let mut first = 0;
    // Digits come out least-significant first, so fill from the back.
    let mut next = digits.len();

    while first < num.len() {
        let mut remainder = 0u32;
        for byte in &mut num[first..] {
            let accumulator = (remainder << 8) | u32::from(*byte);
            *byte = (accumulator / 58) as u8;
            remainder = accumulator % 58;
        }

        next -= 1;
        digits[next] = BASE58_ALPHABET[remainder as usize];

        while first < num.len() && num[first] == 0 {
            first += 1;
        }
    }

    // Guarantees the invariant `expose_str` depends on: every byte was written
    // from BASE58_ALPHABET, so the buffer is printable ASCII.
    assert_eq!(next, 0, "WIF payload must encode to exactly 52 digits");
    wif
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::PrivateKey;

    fn key_from_hex(hex: &str) -> PrivateKey {
        PrivateKey::from_hex(hex).unwrap()
    }

    // Known-answer test: private key = 1.
    // Source: Bitcoin wiki, widely published test vector.
    #[test]
    fn test_wif_vector_scalar_one() {
        let key = key_from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        let wif = encode_wif(&key);
        assert_eq!(
            wif.expose_str(),
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        );
    }

    // Known-answer test: Bitcoin wiki WIF example.
    // Private key: 0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
    // Compressed WIF: KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617
    #[test]
    fn test_wif_vector_two() {
        let key = key_from_hex("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D");
        let wif = encode_wif(&key);
        assert_eq!(
            wif.expose_str(),
            "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
        );
    }

    #[test]
    fn test_wif_starts_with_k_or_l() {
        let keys = [
            key_from_hex("0000000000000000000000000000000000000000000000000000000000000001"),
            key_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"),
            key_from_hex("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"),
        ];

        for key in &keys {
            let wif = encode_wif(key);
            assert!(
                wif.expose_str().starts_with('K') || wif.expose_str().starts_with('L'),
                "compressed mainnet WIF must start with K or L, got: {}",
                wif.expose_str()
            );
        }
    }

    #[test]
    fn test_wif_length_52() {
        let key = key_from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        let wif = encode_wif(&key);
        assert_eq!(
            wif.expose_str().len(),
            52,
            "compressed mainnet WIF must be 52 characters"
        );
    }

    #[test]
    fn test_wif_valid_base58_characters() {
        let key = key_from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        let wif = encode_wif(&key);
        let base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for ch in wif.expose_str().chars() {
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
        let key = key_from_hex("0000000000000000000000000000000000000000000000000000000000000001");
        let wif = encode_wif(&key);
        let decoded = base58_decode(wif.expose_str());

        // WIF for compressed mainnet: 1 + 32 + 1 + 4 = 38 bytes.
        assert_eq!(decoded.len(), 38, "decoded WIF must be 38 bytes");

        // Split into payload (34 bytes) and checksum (4 bytes).
        let payload = &decoded[..34];
        let checksum = &decoded[34..38];

        // Recompute checksum.
        let hash1 = sha256::Hash::hash(payload).to_byte_array();
        let hash2 = sha256::Hash::hash(&hash1).to_byte_array();
        let expected_checksum = &hash2[..4];

        assert_eq!(
            checksum, expected_checksum,
            "WIF checksum must match double-SHA256 of payload"
        );

        // Also verify payload structure.
        assert_eq!(payload[0], 0x80, "first byte must be mainnet prefix 0x80");
        assert_eq!(
            &payload[1..33],
            key.as_bytes(),
            "bytes 1-32 must be the private key"
        );
        assert_eq!(
            payload[33], 0x01,
            "last payload byte must be 0x01 (compressed flag)"
        );
    }
}
