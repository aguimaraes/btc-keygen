use std::fmt;

/// Error type for entropy operations.
#[derive(Debug)]
pub struct EntropyError(pub String);

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "entropy error: {}", self.0)
    }
}

impl std::error::Error for EntropyError {}

/// Trait abstracting the source of random bytes.
///
/// Production code uses `OsEntropy`. Tests use `FixedEntropy`.
pub trait EntropySource {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), EntropyError>;
}

/// Production entropy source backed by the OS CSPRNG.
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(dest).map_err(|e| EntropyError(format!("OS CSPRNG failed: {}", e)))
    }
}

#[cfg(test)]
pub struct FixedEntropy {
    data: Vec<u8>,
    cursor: std::cell::Cell<usize>,
}

#[cfg(test)]
impl FixedEntropy {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            cursor: std::cell::Cell::new(0),
        }
    }
}

#[cfg(test)]
impl EntropySource for FixedEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
        let start = self.cursor.get();
        let end = start + dest.len();
        if end > self.data.len() {
            return Err(EntropyError("fixed entropy exhausted".into()));
        }
        dest.copy_from_slice(&self.data[start..end]);
        self.cursor.set(end);
        Ok(())
    }
}

#[cfg(test)]
pub struct FailingEntropy;

#[cfg(test)]
impl EntropySource for FailingEntropy {
    fn fill_bytes(&self, _dest: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError("simulated entropy failure".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_entropy_fills_exact_bytes() {
        let data = vec![0xAA; 32];
        let source = FixedEntropy::new(data.clone());
        let mut buf = [0u8; 32];
        source.fill_bytes(&mut buf).unwrap();
        assert_eq!(buf, data.as_slice());
    }

    #[test]
    fn test_fixed_entropy_sequential_chunks() {
        let mut data = vec![0x11; 32];
        data.extend_from_slice(&[0x22; 32]);
        let source = FixedEntropy::new(data);

        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        source.fill_bytes(&mut first).unwrap();
        source.fill_bytes(&mut second).unwrap();

        assert_eq!(first, [0x11; 32]);
        assert_eq!(second, [0x22; 32]);
    }

    #[test]
    fn test_fixed_entropy_exhausted_returns_error() {
        let source = FixedEntropy::new(vec![0x00; 16]);
        let mut buf = [0u8; 32];
        let result = source.fill_bytes(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_failing_entropy_always_errors() {
        let source = FailingEntropy;
        let mut buf = [0u8; 32];
        let result = source.fill_bytes(&mut buf);
        assert!(result.is_err());
    }
}
