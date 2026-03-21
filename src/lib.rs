//! Minimal offline Bitcoin key generator for cold storage.
//!
//! Generates a secp256k1 private key from OS-provided cryptographic randomness
//! and derives the corresponding WIF, compressed public key, and native SegWit
//! (Bech32) address. Designed for air-gapped key ceremonies.
//!
//! # Library usage
//!
//! The public API is four functions and one type:
//!
//! | Function | Input | Output |
//! |---|---|---|
//! | [`generate`] | — | `Result<`[`PrivateKey`]`, `[`Error`]`>` |
//! | [`encode_wif`] | `&PrivateKey` | `String` (starts with `K` or `L`, 52 chars) |
//! | [`derive_pubkey`] | `&PrivateKey` | `[u8; 33]` (compressed public key) |
//! | [`derive_address`] | `&[u8; 33]` | `String` (Bech32 address, starts with `bc1q`) |
//!
//! ```no_run
//! // 1. Generate a private key from OS randomness
//! let key = btc_keygen::generate()?;
//!
//! // 2. Encode as WIF (for wallet import)
//! let wif = btc_keygen::encode_wif(&key);
//!
//! // 3. Derive the compressed public key
//! let pubkey = btc_keygen::derive_pubkey(&key);
//!
//! // 4. Derive the Bitcoin address
//! let address = btc_keygen::derive_address(&pubkey);
//! # Ok::<(), btc_keygen::Error>(())
//! ```
//!
//! [`PrivateKey`] zeroizes its bytes when dropped — you do not need to
//! clear it manually.
//!
//! # Security
//!
//! - Entropy comes from the OS CSPRNG via [`getrandom`](https://docs.rs/getrandom).
//! - Private key bytes are zeroized in memory when [`PrivateKey`] is dropped.
//! - No networking code — the crate cannot leak secrets over the network.
//! - Elliptic curve operations use Bitcoin Core's
//!   [`libsecp256k1`](https://docs.rs/secp256k1).

use std::fmt;

pub(crate) mod address;
pub(crate) mod entropy;
pub(crate) mod keygen;
pub(crate) mod pubkey;
pub(crate) mod wif;

pub use address::derive_address;
pub use keygen::PrivateKey;
pub use keygen::generate;
pub use pubkey::derive_pubkey;
pub use wif::encode_wif;

/// Error returned when key generation fails.
///
/// This typically indicates a problem with the operating system's random
/// number generator. In normal operation this should never occur.
#[derive(Debug)]
pub struct Error(pub(crate) String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

impl From<entropy::EntropyError> for Error {
    fn from(e: entropy::EntropyError) -> Self {
        Error(e.0)
    }
}

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
        let private_key = keygen::generate_with_entropy(&entropy).expect("generation must succeed");

        assert_eq!(private_key.as_bytes(), &key_bytes);

        let wif_str = wif::encode_wif(&private_key);
        assert_eq!(
            wif_str,
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        );

        let compressed_pubkey = pubkey::derive_pubkey(&private_key);
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
        let private_key = keygen::generate_with_entropy(&entropy).expect("generation must succeed");

        let wif_str = wif::encode_wif(&private_key);
        // WIF for private key = 2 (compressed, mainnet).
        assert_eq!(
            wif_str,
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4"
        );

        let compressed_pubkey = pubkey::derive_pubkey(&private_key);
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

        let key_a = keygen::generate_with_entropy(&FixedEntropy::new(bytes_a.to_vec())).unwrap();
        let key_b = keygen::generate_with_entropy(&FixedEntropy::new(bytes_b.to_vec())).unwrap();

        let pubkey_a = pubkey::derive_pubkey(&key_a);
        let pubkey_b = pubkey::derive_pubkey(&key_b);

        let addr_a = address::derive_address(&pubkey_a);
        let addr_b = address::derive_address(&pubkey_b);

        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
        assert_ne!(pubkey_a, pubkey_b);
        assert_ne!(addr_a, addr_b);
        assert_ne!(wif::encode_wif(&key_a), wif::encode_wif(&key_b));
    }
}
