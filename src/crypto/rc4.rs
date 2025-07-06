//! RC4 encryption provider implementation

use rc4::{KeyInit, StreamCipher};
use crate::error::PDFCryptoError;
use super::CryptoProvider;

/// RC4 encryption provider
#[derive(Debug)]
pub struct RC4Provider {
    key_length: usize,
}

impl RC4Provider {
    /// Create new RC4 provider
    pub fn new(key_length: usize) -> Self {
        Self { key_length }
    }
}

impl CryptoProvider for RC4Provider {
    fn process_data(&self, data: &mut [u8], key: &[u8]) -> Result<(), PDFCryptoError> {
        if key.len() != self.key_length {
            return Err(PDFCryptoError::InvalidKeyLength(key.len()));
        }

        let mut cipher = rc4::Rc4::new(key.into());
        cipher.apply_keystream(data);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;
    use hex;

    #[test]
    fn test_rc4_encryption() {
        let provider = RC4Provider::new(5);
        let key = hex::decode("0102030405").unwrap();
        let mut data = b"Test RC4 encryption".to_vec();
        let original = data.clone();

        // Encrypt
        provider.process_data(&mut data, &key).unwrap();
        assert_ne!(data, original);

        // Decrypt (RC4 is symmetric)
        provider.process_data(&mut data, &key).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn test_rc4_known_vector() {
        let provider = RC4Provider::new(5);
        let key = hex::decode("0102030405").unwrap();
        let mut data = hex::decode("00112233445566778899").unwrap();
        let expected = hex::decode("7494c2e7104b0879aff5").unwrap();

        provider.process_data(&mut data, &key).unwrap();
        assert_eq!(data, expected);
    }

    #[test]
    fn test_invalid_key_length() {
        let provider = RC4Provider::new(5);
        let key = vec![1, 2, 3]; // Wrong length
        let mut data = b"Test data".to_vec();

        assert!(matches!(
            provider.process_data(&mut data, &key),
            Err(PDFCryptoError::InvalidKeyLength(3))
        ));
    }

    #[test]
    fn test_empty_data() {
        let provider = RC4Provider::new(5);
        let key = vec![1u8; 5];
        let mut data = Vec::new();

        // Should work with empty data
        assert!(provider.process_data(&mut data, &key).is_ok());
    }
