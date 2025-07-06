//! AES encryption provider implementation

use aes::{Aes128, Aes256};
use cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use crate::error::PDFCryptoError;
use super::CryptoProvider;
use rand::{thread_rng, RngCore};

pub(crate) struct AESProvider {
    key_length: usize,
}

impl AESProvider {
    pub fn new(key_length: usize) -> Self {
        Self { key_length }
    }

    fn process_aes128(&self, data: &mut [u8], key: &[u8]) -> Result<(), PDFCryptoError> {
        let cipher = Aes128::new(key.into());
        self.process_aes_cbc(data, &cipher)
    }

    fn process_aes256(&self, data: &mut [u8], key: &[u8]) -> Result<(), PDFCryptoError> {
        let cipher = Aes256::new(key.into());
        self.process_aes_cbc(data, &cipher)
    }

    fn process_aes_cbc<C>(&self, data: &mut [u8], cipher: &C) -> Result<(), PDFCryptoError> 
    where
        C: BlockEncrypt + BlockDecrypt,
    {
        if data.len() < 16 {
            return Err(PDFCryptoError::InvalidDataLength {
                operation: "AES".to_string(),
            });
        }

        // Extract IV (first 16 bytes)
        let (iv, encrypted_data) = data.split_at_mut(16);
        
        // Process data in CBC mode
        let mut prev_block = iv.to_vec();
        for chunk in encrypted_data.chunks_mut(16) {
            let saved_block = chunk.to_vec();
            
            // Create block for in-place processing
            let block = generic_array::GenericArray::from_mut_slice(chunk);
            
            // Decrypt/encrypt block
            if chunk.len() == 16 {
                cipher.decrypt_block(block);
                
                // XOR with previous block
                for (b, p) in chunk.iter_mut().zip(prev_block.iter()) {
                    *b ^= p;
                }
                
                prev_block = saved_block;
            }
        }

        Ok(())
    }
}

impl CryptoProvider for AESProvider {
    fn process_data(&self, data: &mut [u8], key: &[u8]) -> Result<(), PDFCryptoError> {
        if key.len() != self.key_length {
            return Err(PDFCryptoError::InvalidKeyLength(key.len()));
        }

        match self.key_length {
            16 => self.process_aes128(data, key),
            32 => self.process_aes256(data, key),
            _ => Err(PDFCryptoError::UnsupportedKeyLength(self.key_length)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_encryption() {
        let provider = AESProvider::new(16);
        let key = &[1u8; 16];
        let mut data = b"Test AES-128 encryption with CBC mode".to_vec();
        
        // Add space for IV
        let mut encrypted = vec![0u8; 16 + data.len()];
        thread_rng().fill_bytes(&mut encrypted[0..16]); // Random IV
        encrypted[16..].copy_from_slice(&data);
        
        // Encrypt
        provider.process_data(&mut encrypted, key).unwrap();
        assert_ne!(&encrypted[16..], &data);
        
        // Decrypt
        provider.process_data(&mut encrypted, key).unwrap();
        assert_eq!(&encrypted[16..], &data);
    }

    #[test]
    fn test_aes_256_encryption() {
        let provider = AESProvider::new(32);
        let key = &[1u8; 32];
        let mut data = b"Test AES-256 encryption with CBC mode".to_vec();
        
        // Add space for IV
        let mut encrypted = vec![0u8; 16 + data.len()];
        thread_rng().fill_bytes(&mut encrypted[0..16]); // Random IV
        encrypted[16..].copy_from_slice(&data);
        
        // Encrypt
        provider.process_data(&mut encrypted, key).unwrap();
        assert_ne!(&encrypted[16..], &data);
        
        // Decrypt
        provider.process_data(&mut encrypted, key).unwrap();
        assert_eq!(&encrypted[16..], &data);
    }

    #[test]
    fn test_invalid_key_length() {
        let provider = AESProvider::new(16);
        let key = vec![1u8; 24]; // Wrong length
        let mut data = vec![0u8; 32];

        assert!(matches!(
            provider.process_data(&mut data, &key),
            Err(PDFCryptoError::InvalidKeyLength(24))
        ));
    }

    #[test]
    fn test_invalid_data_length() {
        let provider = AESProvider::new(16);
        let key = vec![1u8; 16];
        let mut data = vec![0u8; 8]; // Too short for IV + block

        assert!(matches!(
            provider.process_data(&mut data, &key),
            Err(PDFCryptoError::InvalidDataLength { .. })
        ));
    }
}
