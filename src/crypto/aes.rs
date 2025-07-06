//! AES encryption provider implementation

use aes::{Aes128, Aes256, Block};
use cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use rand::{thread_rng, RngCore};
use zeroize::Zeroize;

use crate::error::PDFCryptoError;
use super::CryptoProvider;

/// AES encryption provider
#[derive(Debug)]
pub struct AESProvider {
    key_length: usize,
}

impl AESProvider {
    /// Create new AES provider
    pub fn new(key_length: usize) -> Self {
        Self { key_length }
    }

    /// Process data with AES-128
    fn process_aes128(&self, data: &mut [u8], key: &[u8]) -> Result<(), PDFCryptoError> {
        let cipher = Aes128::new(key.into());
        self.process_aes_cbc(data, &cipher)
    }

    /// Process data with AES-256
    fn process_aes256(&self, data: &mut [u8], key: &[u8]) -> Result<(), PDFCryptoError> {
        let cipher = Aes256::new(key.into());
        self.process_aes_cbc(data, &cipher)
    }

    /// Process data in CBC mode
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
        let mut prev_block = Block::clone_from_slice(iv);
        
        for chunk in encrypted_data.chunks_mut(16) {
            if chunk.len() != 16 {
                // Handle partial block with PKCS7 padding
                let mut padded = [0u8; 16];
                padded[..chunk.len()].copy_from_slice(chunk);
                let padding = 16 - chunk.len();
                for byte in &mut padded[chunk.len()..] {
                    *byte = padding as u8;
                }
                
                let mut block = Block::from(padded);
                cipher.decrypt_block(&mut block);
                
                // XOR with previous block
                for (b, p) in block.iter_mut().zip(prev_block.iter()) {
                    *b ^= p;
                }
                
                chunk.copy_from_slice(&block[..chunk.len()]);
                break;
            }

            let saved_block = Block::clone_from_slice(chunk);
            let block = Block::from_mut_slice(chunk);
            cipher.decrypt_block(block);
            
            // XOR with previous block
            for (b, p) in chunk.iter_mut().zip(prev_block.iter()) {
                *b ^= p;
            }
            
            prev_block = saved_block;
        }

        // Clear sensitive data
        prev_block.zeroize();

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
    use test_log::test;

    #[test]
    fn test_aes_128_encryption() {
        let provider = AESProvider::new(16);
        let key = &[1u8; 16];
        let original = b"Test AES-128 encryption with CBC mode".to_vec();
        
        // Add space for IV
        let mut data = vec![0u8; 16 + original.len()];
        thread_rng().fill_bytes(&mut data[0..16]); // Random IV
        data[16..].copy_from_slice(&original);
        
        // Encrypt
        provider.process_data(&mut data, key).unwrap();
        assert_ne!(&data[16..], &original);
        
        // Decrypt
        provider.process_data(&mut data, key).unwrap();
        assert_eq!(&data[16..], &original);
    }

    #[test]
    fn test_aes_256_encryption() {
        let provider = AESProvider::new(32);
        let key = &[1u8; 32];
        let original = b"Test AES-256 encryption with CBC mode".to_vec();
        
        // Add space for IV
        let mut data = vec![0u8; 16 + original.len()];
        thread_rng().fill_bytes(&mut data[0..16]); // Random IV
        data[16..].copy_from_slice(&original);
        
        // Encrypt
        provider.process_data(&mut data, key).unwrap();
        assert_ne!(&data[16..], &original);
        
        // Decrypt
        provider.process_data(&mut data, key).unwrap();
        assert_eq!(&data[16..], &original);
    }

    #[test]
    fn test_partial_block() {
        let provider = AESProvider::new(16);
        let key = &[1u8; 16];
        let original = b"Partial".to_vec();
        
        // Add space for IV
        let mut data = vec![0u8; 16 + original.len()];
        thread_rng().fill_bytes(&mut data[0..16]); // Random IV
        data[16..].copy_from_slice(&original);
        
        // Encrypt
        provider.process_data(&mut data, key).unwrap();
        assert_ne!(&data[16..], &original);
        
        // Decrypt
        provider.process_data(&mut data, key).unwrap();
        assert_eq!(&data[16..], &original);
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
