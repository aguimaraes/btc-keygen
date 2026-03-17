use secp256k1::SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::entropy::{EntropyError, EntropySource};

/// A validated secp256k1 private key that zeroizes its bytes on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    bytes: [u8; 32],
}

impl PrivateKey {
    /// Returns a reference to the raw 32-byte private key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Converts the private key into a `secp256k1::SecretKey`.
    pub fn to_secret_key(&self) -> SecretKey {
        SecretKey::from_slice(&self.bytes).expect("PrivateKey always holds a validated scalar")
    }
}

/// Checks whether 32 bytes represent a valid secp256k1 private key.
///
/// A valid key is a scalar in `[1, n-1]` where `n` is the curve order.
pub fn is_valid_key(bytes: &[u8; 32]) -> bool {
    SecretKey::from_slice(bytes).is_ok()
}

/// Generates a new private key using the provided entropy source.
///
/// Retries up to `MAX_RETRIES` times if the random bytes fall outside the
/// valid secp256k1 scalar range. This is astronomically unlikely but handled
/// for correctness.
pub fn generate(entropy: &dyn EntropySource) -> Result<PrivateKey, EntropyError> {
    for _ in 0..MAX_RETRIES {
        let mut bytes = [0u8; 32];
        entropy.fill_bytes(&mut bytes)?;

        if is_valid_key(&bytes) {
            return Ok(PrivateKey { bytes });
        }
        // Invalid scalar — zeroize and retry.
        bytes.zeroize();
    }

    Err(EntropyError(
        "failed to generate valid key after maximum retries".into(),
    ))
}

/// Maximum retry attempts for key generation. A safety net against infinite
/// loops — the probability of needing even one retry is ~10^-38.
const MAX_RETRIES: u32 = 256;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::{FailingEntropy, FixedEntropy};

    /// secp256k1 curve order n.
    const CURVE_ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    /// n - 1: the maximum valid private key.
    fn curve_order_minus_one() -> [u8; 32] {
        let mut bytes = CURVE_ORDER;
        // Subtract 1 from the last byte.
        bytes[31] -= 1;
        bytes
    }

    /// n + 1: one above the curve order.
    fn curve_order_plus_one() -> [u8; 32] {
        let mut bytes = CURVE_ORDER;
        // Add 1 to the last byte.
        bytes[31] += 1;
        bytes
    }

    // ---------------------------------------------------------------
    // 6.1 — Private key boundary validation
    // ---------------------------------------------------------------

    #[test]
    fn test_zero_key_rejected() {
        let zero = [0u8; 32];
        assert!(!is_valid_key(&zero), "zero must not be a valid private key");
    }

    #[test]
    fn test_one_key_valid() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(is_valid_key(&one), "scalar 1 must be a valid private key");
    }

    #[test]
    fn test_curve_order_minus_one_valid() {
        let n_minus_1 = curve_order_minus_one();
        assert!(
            is_valid_key(&n_minus_1),
            "n-1 must be a valid private key (maximum scalar)"
        );
    }

    #[test]
    fn test_curve_order_rejected() {
        assert!(
            !is_valid_key(&CURVE_ORDER),
            "the curve order n itself must not be a valid private key"
        );
    }

    #[test]
    fn test_curve_order_plus_one_rejected() {
        let n_plus_1 = curve_order_plus_one();
        assert!(
            !is_valid_key(&n_plus_1),
            "n+1 must not be a valid private key"
        );
    }

    #[test]
    fn test_all_ff_rejected() {
        let all_ff = [0xFF; 32];
        assert!(
            !is_valid_key(&all_ff),
            "all 0xFF bytes exceed curve order and must be rejected"
        );
    }

    #[test]
    fn test_valid_midrange_key() {
        // A known midrange value well within [1, n-1].
        let mut key = [0u8; 32];
        key[0] = 0x0A;
        key[31] = 0x0B;
        assert!(is_valid_key(&key));
    }

    // ---------------------------------------------------------------
    // 6.2 — Deterministic key generation with injectable entropy
    // ---------------------------------------------------------------

    #[test]
    fn test_fixed_entropy_produces_expected_key() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 0x01; // scalar = 1, valid
        let entropy = FixedEntropy::new(key_bytes.to_vec());

        let key = generate(&entropy).expect("generation should succeed");
        assert_eq!(key.as_bytes(), &key_bytes);
    }

    #[test]
    fn test_different_entropy_produces_different_keys() {
        let mut bytes_a = [0u8; 32];
        bytes_a[31] = 0x01;
        let mut bytes_b = [0u8; 32];
        bytes_b[31] = 0x02;

        let key_a = generate(&FixedEntropy::new(bytes_a.to_vec())).unwrap();
        let key_b = generate(&FixedEntropy::new(bytes_b.to_vec())).unwrap();

        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
    }

    #[test]
    fn test_same_entropy_produces_same_key() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 0x05;

        let key1 = generate(&FixedEntropy::new(key_bytes.to_vec())).unwrap();
        let key2 = generate(&FixedEntropy::new(key_bytes.to_vec())).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_invalid_entropy_triggers_retry() {
        // First 32 bytes: the curve order (invalid).
        // Next 32 bytes: scalar 1 (valid).
        let mut data = CURVE_ORDER.to_vec();
        let mut valid = [0u8; 32];
        valid[31] = 0x01;
        data.extend_from_slice(&valid);

        let entropy = FixedEntropy::new(data);
        let key = generate(&entropy).expect("should succeed after retry");
        assert_eq!(key.as_bytes(), &valid);
    }

    #[test]
    fn test_entropy_failure_propagates() {
        let result = generate(&FailingEntropy);
        assert!(result.is_err(), "entropy failure must propagate as error");
    }

    #[test]
    fn test_generated_key_converts_to_secret_key() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 0x01;
        let key = generate(&FixedEntropy::new(key_bytes.to_vec())).unwrap();

        // Must not panic — validates the internal invariant.
        let _sk = key.to_secret_key();
    }
}
