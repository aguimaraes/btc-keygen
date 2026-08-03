use crate::Error;
use crate::entropy::{EntropyError, EntropySource};
use crate::secret::SecretKeyHex;
use secp256k1::SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A validated secp256k1 private key that zeroizes its bytes on drop.
///
/// Created by [`generate`](crate::generate). The key is guaranteed to be a
/// valid scalar in the range `[1, n-1]` where `n` is the secp256k1 curve order.
///
/// When this value goes out of scope, the underlying bytes are securely
/// overwritten with zeros to prevent secrets from lingering in memory.
///
/// The 32 bytes live in a heap buffer behind a `Box`, so moving a `PrivateKey`
/// moves a pointer rather than memcpying the key into a fresh stack slot that
/// nothing would ever erase. Constructors fill that buffer in place for the
/// same reason: the key material is never staged in a bare `[u8; 32]` local.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    // Boxed so that moving a PrivateKey moves a pointer: the bytes are written
    // once and erased once, at the address they were born.
    bytes: Box<[u8; 32]>,
}

impl PrivateKey {
    /// A zeroed buffer for a constructor to fill in place.
    ///
    /// Private, and deliberately not `pub(crate)`: the value is not a valid key
    /// until [`Self::validated`] has approved it.
    fn zeroed() -> Self {
        Self {
            bytes: Box::new([0u8; 32]),
        }
    }

    /// Consumes a filled buffer and enforces the scalar invariant, so no
    /// unvalidated `PrivateKey` can escape this module.
    fn validated(self) -> Result<PrivateKey, Error> {
        if !is_valid_key(self.as_bytes()) {
            return Err(Error("not a valid secp256k1 scalar".into()));
        }
        Ok(self)
    }

    /// Returns a reference to the raw 32-byte private key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Converts the private key into a [`secp256k1::SecretKey`] for use with
    /// the `secp256k1` crate directly.
    ///
    /// The returned type is outside this crate's erasure guarantees:
    /// `SecretKey` is `Copy`, does not erase itself when dropped, and its
    /// `non_secure_erase` is best-effort. Keep the value short-lived, erase it
    /// by hand, and treat every copy of it as key material.
    pub fn to_secret_key(&self) -> SecretKey {
        SecretKey::from_byte_array(*self.as_bytes())
            .expect("PrivateKey always holds a validated scalar")
    }

    /// Encodes the key as 64 lowercase hexadecimal ASCII bytes.
    ///
    /// The result is a [`SecretKeyHex`]: it erases itself on drop and redacts
    /// its `Debug` output. The digits are written straight into that buffer, so
    /// encoding a key allocates nothing beyond the buffer itself and leaves no
    /// unerased temporaries on the heap.
    ///
    /// # Example
    ///
    /// ```
    /// let hex = "0000000000000000000000000000000000000000000000000000000000000001";
    /// let key = btc_keygen::PrivateKey::from_hex(hex)?;
    /// assert_eq!(key.to_hex().expose_str(), hex);
    /// # Ok::<(), btc_keygen::Error>(())
    /// ```
    #[must_use]
    pub fn to_hex(&self) -> SecretKeyHex {
        const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

        let mut hex = SecretKeyHex::zeroed();
        let digits = hex.bytes_mut();
        for (i, byte) in self.bytes.iter().enumerate() {
            digits[i * 2] = HEX_DIGITS[usize::from(byte >> 4)];
            digits[i * 2 + 1] = HEX_DIGITS[usize::from(byte & 0x0f)];
        }
        hex
    }

    /// Creates a `PrivateKey` from 32 raw bytes, validating that they form a
    /// valid secp256k1 scalar.
    ///
    /// Use this when you have your own source of private key material (for
    /// example, physical entropy like dice rolls converted to hex) and want
    /// to skip OS entropy generation.
    ///
    /// `bytes` is `Copy`, so the caller keeps its own array; erasing that copy
    /// is the caller's job. This function erases the copy it receives.
    ///
    /// # Errors
    ///
    /// Returns [`Error`](crate::Error) if `bytes` is zero or greater than or
    /// equal to the secp256k1 curve order `n`.
    ///
    /// # Example
    ///
    /// ```
    /// let mut bytes = [0u8; 32];
    /// bytes[31] = 0x01;
    /// let key = btc_keygen::PrivateKey::from_bytes(bytes)?;
    /// # Ok::<(), btc_keygen::Error>(())
    /// ```
    pub fn from_bytes(mut bytes: [u8; 32]) -> Result<PrivateKey, Error> {
        let mut key = Self::zeroed();
        key.bytes.copy_from_slice(&bytes);
        bytes.zeroize();
        key.validated()
    }

    /// Creates a `PrivateKey` from a 64-character hexadecimal string,
    /// validating that the decoded bytes form a valid secp256k1 scalar.
    ///
    /// Convenience wrapper around [`from_bytes`](Self::from_bytes) for callers
    /// that have the key material as a hex string (for example, from a CLI
    /// argument or a text file).
    ///
    /// # Errors
    ///
    /// Returns [`Error`](crate::Error) if:
    ///
    /// - `hex` is not exactly 64 characters long.
    /// - `hex` contains a character that is not a valid hexadecimal digit.
    /// - The decoded bytes are zero or greater than or equal to the secp256k1
    ///   curve order `n`.
    ///
    /// # Example
    ///
    /// ```
    /// let hex = "0000000000000000000000000000000000000000000000000000000000000001";
    /// let key = btc_keygen::PrivateKey::from_hex(hex)?;
    /// # Ok::<(), btc_keygen::Error>(())
    /// ```
    pub fn from_hex(hex: &str) -> Result<PrivateKey, Error> {
        if hex.len() != 64 {
            return Err(Error(format!(
                "expected 64 hex characters, got {}",
                hex.len()
            )));
        }

        // Decoded straight into the key's own buffer: no stack scratch array
        // holds the assembled key, not even briefly.
        let mut key = Self::zeroed();
        for i in 0..32 {
            key.bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| Error(format!("invalid hex at position {}", i * 2)))?;
        }
        key.validated()
    }
}

/// Checks whether 32 bytes represent a valid secp256k1 private key.
///
/// A valid key is a scalar in `[1, n-1]` where `n` is the curve order.
///
/// Takes a reference so that testing a candidate does not copy it, and erases
/// the `SecretKey` it builds internally.
pub fn is_valid_key(bytes: &[u8; 32]) -> bool {
    match SecretKey::from_byte_array(*bytes) {
        Ok(mut key) => {
            key.non_secure_erase();
            true
        }
        Err(_) => false,
    }
}

/// Generates a new private key using the provided entropy source.
///
/// Retries up to `MAX_RETRIES` times if the random bytes fall outside the
/// valid secp256k1 scalar range. This is astronomically unlikely but handled
/// for correctness.
pub(crate) fn generate_with_entropy(
    entropy: &dyn EntropySource,
) -> Result<PrivateKey, EntropyError> {
    for _ in 0..MAX_RETRIES {
        // Filled in place: fresh entropy never lands in a stack array.
        let mut key = PrivateKey::zeroed();
        entropy.fill_bytes(&mut key.bytes[..])?;

        if is_valid_key(key.as_bytes()) {
            return Ok(key);
        }
        // Invalid scalar: dropping `key` zeroizes the buffer before the retry.
    }

    Err(EntropyError(
        "failed to generate valid key after maximum retries".into(),
    ))
}

/// Generates a new Bitcoin private key using OS-provided cryptographic randomness.
///
/// Returns a [`PrivateKey`] containing a validated secp256k1 scalar. The
/// entropy comes from the operating system's CSPRNG: the `getrandom(2)` syscall
/// on Linux and FreeBSD, falling back to `/dev/urandom` where the syscall is
/// unavailable, `getentropy` on macOS, and `ProcessPrng` on Windows.
///
/// # Errors
///
/// Returns [`Error`](crate::Error) if the OS random number generator fails.
///
/// # Example
///
/// ```no_run
/// let key = btc_keygen::generate().expect("key generation failed");
/// ```
pub fn generate() -> Result<PrivateKey, crate::Error> {
    generate_with_entropy(&crate::entropy::OsEntropy).map_err(crate::Error::from)
}

/// Maximum retry attempts for key generation. A safety net against infinite
/// loops: the probability of needing even one retry is ~10^-38.
const MAX_RETRIES: u32 = 32;

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
        bytes[31] -= 1;
        bytes
    }

    /// n + 1: one above the curve order.
    fn curve_order_plus_one() -> [u8; 32] {
        let mut bytes = CURVE_ORDER;
        bytes[31] += 1;
        bytes
    }

    // ---------------------------------------------------------------
    // 6.1: Private key boundary validation
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
    // 6.2: Deterministic key generation with injectable entropy
    // ---------------------------------------------------------------

    #[test]
    fn test_fixed_entropy_produces_expected_key() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 0x01; // scalar = 1, valid
        let entropy = FixedEntropy::new(key_bytes.to_vec());

        let key = generate_with_entropy(&entropy).expect("generation should succeed");
        assert_eq!(key.as_bytes(), &key_bytes);
    }

    #[test]
    fn test_different_entropy_produces_different_keys() {
        let mut bytes_a = [0u8; 32];
        bytes_a[31] = 0x01;
        let mut bytes_b = [0u8; 32];
        bytes_b[31] = 0x02;

        let key_a = generate_with_entropy(&FixedEntropy::new(bytes_a.to_vec())).unwrap();
        let key_b = generate_with_entropy(&FixedEntropy::new(bytes_b.to_vec())).unwrap();

        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
    }

    #[test]
    fn test_same_entropy_produces_same_key() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 0x05;

        let key1 = generate_with_entropy(&FixedEntropy::new(key_bytes.to_vec())).unwrap();
        let key2 = generate_with_entropy(&FixedEntropy::new(key_bytes.to_vec())).unwrap();

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
        let key = generate_with_entropy(&entropy).expect("should succeed after retry");
        assert_eq!(key.as_bytes(), &valid);
    }

    #[test]
    fn test_entropy_failure_propagates() {
        let result = generate_with_entropy(&FailingEntropy);
        assert!(result.is_err(), "entropy failure must propagate as error");
    }

    #[test]
    fn test_generated_key_converts_to_secret_key() {
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 0x01;
        let key = generate_with_entropy(&FixedEntropy::new(key_bytes.to_vec())).unwrap();

        // Must not panic: validates the internal invariant.
        let _sk = key.to_secret_key();
    }

    // ---------------------------------------------------------------
    // 6.12: PrivateKey::from_bytes validation
    // ---------------------------------------------------------------

    #[test]
    fn test_from_bytes_accepts_valid_scalar() {
        let mut bytes = [0u8; 32];
        bytes[31] = 0x01;
        let key = PrivateKey::from_bytes(bytes).expect("scalar 1 must be accepted");
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_from_bytes_rejects_invalid_scalar() {
        let zero = [0u8; 32];
        assert!(
            PrivateKey::from_bytes(zero).is_err(),
            "invalid scalar must be rejected"
        );
    }

    // ---------------------------------------------------------------
    // 6.13: PrivateKey::from_hex parsing and validation
    // ---------------------------------------------------------------

    #[test]
    fn test_from_hex_accepts_valid_scalar_one() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let key = PrivateKey::from_hex(hex).expect("scalar 1 must be accepted");
        let mut expected = [0u8; 32];
        expected[31] = 0x01;
        assert_eq!(key.as_bytes(), &expected);
    }

    #[test]
    fn test_to_hex_round_trips_from_hex() {
        let hex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        let key = PrivateKey::from_hex(hex).unwrap();
        assert_eq!(key.to_hex().expose_str(), hex);
    }

    #[test]
    fn test_to_hex_is_lowercase_and_64_bytes() {
        let key = PrivateKey::from_hex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
        )
        .unwrap();
        let hex = key.to_hex();
        assert_eq!(hex.expose_bytes().len(), 64);
        assert_eq!(
            hex.expose_str(),
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        );
    }

    #[test]
    fn test_from_hex_rejects_wrong_length() {
        assert!(
            PrivateKey::from_hex("01").is_err(),
            "hex not exactly 64 chars must be rejected"
        );
    }

    #[test]
    fn test_from_hex_rejects_non_hex_characters() {
        let hex = "zz00000000000000000000000000000000000000000000000000000000000001";
        assert!(
            PrivateKey::from_hex(hex).is_err(),
            "non-hex characters must be rejected"
        );
    }

    #[test]
    fn test_from_hex_propagates_invalid_scalar() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(
            PrivateKey::from_hex(hex).is_err(),
            "invalid scalar from from_bytes must propagate"
        );
    }
}
