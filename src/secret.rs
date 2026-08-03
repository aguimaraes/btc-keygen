//! Fixed-size, erase-on-drop containers for secret ASCII text.
//!
//! Producers write their output *directly* into one of these buffers, so no
//! secret-bearing `String`, `Vec`, or `format!` temporary is ever allocated on
//! the way out. The buffer lives on the heap behind a `Box` so that moving the
//! value moves a pointer, not the secret: the bytes are written once and
//! zeroized once, at the address they were born.
//!
//! There is deliberately no `Display`, `Clone`, `Copy`, or `Deref`. Reading a
//! secret is spelled `expose_bytes` or `expose_str`, and what a caller does
//! with the borrow is beyond this crate's reach: printing it, or copying it
//! into a `String`, creates copies that will not be erased.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A compressed mainnet WIF: exactly 52 Base58 ASCII bytes.
///
/// Returned by [`encode_wif`](crate::encode_wif). See [`SecretAscii`].
pub type SecretWif = SecretAscii<52>;

/// A raw private key in hexadecimal: exactly 64 lowercase ASCII bytes.
///
/// Returned by [`PrivateKey::to_hex`](crate::PrivateKey::to_hex). See
/// [`SecretAscii`].
pub type SecretKeyHex = SecretAscii<64>;

/// A fixed-length ASCII secret that zeroizes on drop and redacts its `Debug`.
///
/// Use it through the [`SecretWif`] and [`SecretKeyHex`] aliases; the length
/// parameter is what keeps them distinct types, so a hex string cannot be
/// passed where a WIF is expected.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretAscii<const N: usize> {
    // Boxed so that a move copies the pointer, never the secret.
    bytes: Box<[u8; N]>,
}

impl<const N: usize> SecretAscii<N> {
    /// A zeroed buffer for a producer to fill via [`Self::bytes_mut`].
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: Box::new([0u8; N]),
        }
    }

    /// Write access for producers inside this crate. Crate-private: it is the
    /// only way to break the "every byte is printable ASCII" invariant that
    /// [`Self::expose_str`] relies on.
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    /// Borrows the secret as raw ASCII bytes.
    ///
    /// Prefer handing this straight to
    /// [`Write::write_all`](std::io::Write::write_all). Anything that copies
    /// the bytes elsewhere creates a copy this crate cannot erase.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Borrows the secret as a string.
    ///
    /// Convenient for comparisons, but note that a `&str` slips into
    /// `format!`, `to_string`, and `String::from` without a second thought,
    /// each of which leaves an unerased copy on the heap. Reach for
    /// [`Self::expose_bytes`] at output boundaries.
    #[must_use]
    pub fn expose_str(&self) -> &str {
        // Infallible: every byte is written from a fixed ASCII alphabet, and
        // producers assert that the buffer was filled completely.
        core::str::from_utf8(self.expose_bytes()).expect("SecretAscii holds ASCII")
    }
}

/// Redacted, so that a stray `{:?}` cannot leak a key.
///
/// ```
/// # let key = btc_keygen::PrivateKey::from_hex(
/// #     "0000000000000000000000000000000000000000000000000000000000000001").unwrap();
/// let wif = btc_keygen::encode_wif(&key);
/// assert_eq!(format!("{:?}", wif), "Secret<52>([REDACTED])");
/// ```
///
/// A secret cannot be cloned:
///
/// ```compile_fail
/// # let key = btc_keygen::PrivateKey::from_hex(
/// #     "0000000000000000000000000000000000000000000000000000000000000001").unwrap();
/// let wif = btc_keygen::encode_wif(&key);
/// let copy = wif.clone();
/// ```
///
/// nor copied, so a move ends the original's life:
///
/// ```compile_fail
/// # let key = btc_keygen::PrivateKey::from_hex(
/// #     "0000000000000000000000000000000000000000000000000000000000000001").unwrap();
/// let wif = btc_keygen::encode_wif(&key);
/// let moved = wif;
/// let _ = wif.expose_bytes();
/// ```
///
/// nor formatted with `{}`:
///
/// ```compile_fail
/// # let key = btc_keygen::PrivateKey::from_hex(
/// #     "0000000000000000000000000000000000000000000000000000000000000001").unwrap();
/// let wif = btc_keygen::encode_wif(&key);
/// println!("{}", wif);
/// ```
impl<const N: usize> fmt::Debug for SecretAscii<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{N}>([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_redacts_contents() {
        let mut secret = SecretWif::zeroed();
        secret
            .bytes_mut()
            .copy_from_slice(b"KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");

        let debug = format!("{:?}", secret);
        assert_eq!(debug, "Secret<52>([REDACTED])");
        assert!(!debug.contains("KwDi"), "Debug must not leak the WIF");
    }

    #[test]
    fn test_expose_str_round_trips() {
        let mut secret = SecretKeyHex::zeroed();
        let hex = b"0000000000000000000000000000000000000000000000000000000000000001";
        secret.bytes_mut().copy_from_slice(hex);
        assert_eq!(secret.expose_str(), std::str::from_utf8(hex).unwrap());
        assert_eq!(secret.expose_bytes(), hex);
    }

    #[test]
    fn test_zeroed_starts_empty() {
        assert_eq!(SecretWif::zeroed().expose_bytes(), &[0u8; 52]);
    }
}
