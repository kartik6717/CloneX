use aes::{Aes128, Aes256};
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, 
    KeyInit,
    generic_array::GenericArray
};
use rc4::Rc4;
use md5::{Md5, Digest};
use zeroize::Zeroizing;
use super::{EncryptionAlgorithm, PDFCryptoError};

pub struct PDFCryptoEngine {
    buffer_pool: crate::utils::MemoryPool,
    metrics: crate::utils::PerformanceMetrics,
}

impl PDFCryptoEngine {
    pub fn new() -> Self {
        Self {
            buffer_pool: crate::utils::MemoryPool::new(),
            metrics: crate::utils::PerformanceMetrics::new(),
        }
    }

    /// Encrypt/decrypt individual PDF objects
    pub fn process_object(
        &self,
        object_data: &mut [u8],
        object_num: u32,
        generation: u16,
        file_key: &[u8],
        algorithm: &EncryptionAlgorithm
    ) -> Result<(), PDFCryptoError> {
        self.metrics.record_operation(|| {
            // Generate object key
            let object_key = self.generate_object_key(file_key, object_num, generation, algorithm)?;
            
            match algorithm {
                EncryptionAlgorithm::RC4_40 | EncryptionAlgorithm::RC4_128 => {
                    self.process_rc4(object_data, &object_key)
                },
                EncryptionAlgorithm::AES_128 | EncryptionAlgorithm::AES_256 => {
                    self.process_aes(object_data, &object_key, algorithm)
                }
            }
        })
    }

    /// Algorithm 1: Object key generation
    fn generate_object_key(
        &self,
        file_key: &[u8],
        obj_num: u32,
        gen_num: u16,
        algorithm: &EncryptionAlgorithm
    ) -> Result<Zeroizing<Vec<u8>>, PDFCryptoError> {
        let mut hasher = Md5::new();
        
        // Step 1: File encryption key
        hasher.update(file_key);
        
        // Step 2: Object number and generation
        hasher.update(&obj_num.to_le_bytes()[0..3]);
        hasher.update(&gen_num.to_le_bytes());
        
        // Step 3: Add AES salt if needed
        match algorithm {
            EncryptionAlgorithm::AES_128 | EncryptionAlgorithm::AES_256 => {
                hasher.update(b"sAlT");
            },
            _ => {}
        }
        
        let hash = hasher.finalize();
        let key_len = match algorithm {
            EncryptionAlgorithm::RC4_40 => 5,
            EncryptionAlgorithm::RC4_128 | EncryptionAlgorithm::AES_128 => 16,
            EncryptionAlgorithm::AES_256 => 32,
        };
        
        Ok(Zeroizing::new(hash[..key_len].to_vec()))
    }

    fn process_rc4(&self, data: &mut [u8], key: &[u8]) -> Result<(), PDFCryptoError> {
        let mut cipher = Rc4::new(key.into());
        cipher.apply_keystream(data);
        Ok(())
    }

    fn process_aes(
        &self,
        data: &mut [u8],
        key: &[u8],
        algorithm: &EncryptionAlgorithm
    ) -> Result<(), PDFCryptoError> {
        if data.len() < 16 {
            return Err(PDFCryptoError::InvalidDataLength);
        }

        match algorithm {
            EncryptionAlgorithm::AES_128 => {
                self.process_aes_128(data, key)
            },
            EncryptionAlgorithm::AES_256 => {
                self.process_aes_256(data, key)
            },
            _ => Err(PDFCryptoError::UnsupportedAlgorithm)
        }
    }

    fn process_aes_128(&self, data: &mut [u8], key: &[u8]) -> Result<(), PDFCryptoError> {
        if key.len() != 16 {
            return Err(PDFCryptoError::InvalidKeyLength(key.len()));
        }

        let cipher = Aes128::new(GenericArray::from_slice(key));
        
        // Process in CBC mode
        let mut iv = GenericArray::clone_from_slice(&data[..16]);
        let chunks = data[16..].chunks_exact_mut(16);
        let remainder = chunks.remainder();
        
        if !remainder.is_empty() {
            return Err(PDFCryptoError::InvalidDataLength);
        }

        for chunk in chunks {
            let mut block = GenericArray::from_slice(chunk).clone();
            
            // Decrypt block
            cipher.decrypt_block(&mut block);
            
            // XOR with previous ciphertext (IV for first block)
            for (b, iv_b) in chunk.iter_mut().zip(iv.iter()) {
                *b ^= iv_b;
            }
            
            // Update IV for next block
            iv = GenericArray::clone_from_slice(chunk);
        }

        Ok(())
    }

    fn process_aes_256(&self, data: &mut [u8], key: &[u8]) -> Result<(), PDFCryptoError> {
        if key.len() != 32 {
            return Err(PDFCryptoError::InvalidKeyLength(key.len()));
        }

        let cipher = Aes256::new(GenericArray::from_slice(key));
        
        // Similar to AES-128 but with 256-bit key
        let mut iv = GenericArray::clone_from_slice(&data[..16]);
        let chunks = data[16..].chunks_exact_mut(16);
        let remainder = chunks.remainder();
        
        if !remainder.is_empty() {
            return Err(PDFCryptoError::InvalidDataLength);
        }

        for chunk in chunks {
            let mut block = GenericArray::from_slice(chunk).clone();
            cipher.decrypt_block(&mut block);
            
            for (b, iv_b) in chunk.iter_mut().zip(iv.iter()) {
                *b ^= iv_b;
            }
            
            iv = GenericArray::clone_from_slice(chunk);
        }

        Ok(())
    }

    /// Process PDF stream objects
    pub fn process_stream(
        &self,
        stream_data: &mut [u8],
        object_num: u32,
        generation: u16,
        file_key: &[u8],
        algorithm: &EncryptionAlgorithm
    ) -> Result<(), PDFCryptoError> {
        // For streams, we need to handle the Length parameter correctly
        if stream_data.len() < 16 && matches!(algorithm, 
            EncryptionAlgorithm::AES_128 | EncryptionAlgorithm::AES_256) {
            return Err(PDFCryptoError::InvalidDataLength);
        }

        self.process_object(stream_data, object_num, generation, file_key, algorithm)
    }

    /// Process PDF string objects
    pub fn process_string(
        &self,
        string_data: &mut [u8],
        object_num: u32,
        generation: u16,
        file_key: &[u8],
        algorithm: &EncryptionAlgorithm
    ) -> Result<(), PDFCryptoError> {
        // For strings, we need to handle padding
        let mut padded_data = match algorithm {
            EncryptionAlgorithm::AES_128 | EncryptionAlgorithm::AES_256 => {
                let padding_len = 16 - (string_data.len() % 16);
                let mut data = self.buffer_pool.acquire_buffer(string_data.len() + padding_len);
                data.extend_from_slice(string_data);
                data.extend(std::iter::repeat(padding_len as u8).take(padding_len));
                data
            },
            _ => string_data.to_vec()
        };

        self.process_object(&mut padded_data, object_num, generation, file_key, algorithm)?;
        
        string_data.copy_from_slice(&padded_data[..string_data.len()]);
        Ok(())
    }
}

#[derive(Debug)]
pub enum PDFCryptoError {
    InvalidDataLength,
    InvalidKeyLength(usize),
    UnsupportedAlgorithm,
    // ... other variants from previous implementation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_key_generation() {
        let engine = PDFCryptoEngine::new();
        let file_key = vec![0x01; 16];
        let obj_num = 1;
        let gen_num = 0;
        
        let key = engine.generate_object_key(
            &file_key,
            obj_num,
            gen_num,
            &EncryptionAlgorithm::AES_128
        ).unwrap();
        
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_rc4_processing() {
        let engine = PDFCryptoEngine::new();
        let mut data = b"Test data".to_vec();
        let key = vec![0x01; 16];
        
        // Encrypt
        engine.process_rc4(&mut data, &key).unwrap();
        
        // Decrypt (RC4 is symmetric)
        engine.process_rc4(&mut data, &key).unwrap();
        
        assert_eq!(&data, b"Test data");
    }

    #[test]
    fn test_aes_processing() {
        let engine = PDFCryptoEngine::new();
        let mut data = vec![0u8; 32]; // 16-byte IV + 16-byte data
        data[16..].copy_from_slice(b"Test data        "); // Pad to 16 bytes
        let key = vec![0x01; 16];
        
        // Encrypt
        engine.process_aes(&mut data, &key, &EncryptionAlgorithm::AES_128).unwrap();
        
        // Decrypt
        engine.process_aes(&mut data, &key, &EncryptionAlgorithm::AES_128).unwrap();
        
        assert_eq!(&data[16..], b"Test data        ");
    }
}
