//! Standard Security Handler implementation according to PDF specification

use std::convert::TryInto;
use zeroize::{Zeroize, ZeroizeOnDrop};
use sha2::{Sha256, Digest};
use md5::{Md5, Digest as Md5Digest};
use rand::{thread_rng, RngCore};

use crate::error::PDFCryptoError;
use crate::EncryptionAlgorithm;
use super::SecurityHandler;

/// Standard security handler for password-based encryption
#[derive(Clone, ZeroizeOnDrop)]
pub struct StandardSecurityHandler {
    pub(crate) algorithm: EncryptionAlgorithm,
    version: u8,
    revision: u8,
    key_length: usize,
    #[zeroize(skip)]
    permissions: u32,
    #[zeroize]
    o_value: Vec<u8>,
    #[zeroize]
    u_value: Vec<u8>,
    #[zeroize]
    oe_value: Option<Vec<u8>>,
    #[zeroize]
    ue_value: Option<Vec<u8>>,
    #[zeroize]
    perms_value: Option<Vec<u8>>,
    #[zeroize]
    encryption_key: Option<Vec<u8>>,
    file_id: Vec<u8>,
}

impl StandardSecurityHandler {
    pub fn new(
        algorithm: EncryptionAlgorithm,
        permissions: u32,
        user_password: &[u8],
        owner_password: &[u8],
    ) -> Result<Self, PDFCryptoError> {
        let (version, revision, key_length) = match algorithm {
            EncryptionAlgorithm::RC4_40 => (1, 2, 5),
            EncryptionAlgorithm::RC4_128 => (2, 3, 16),
            EncryptionAlgorithm::AES_128 => (4, 4, 16),
            EncryptionAlgorithm::AES_256 => (5, 6, 32),
        };

        let mut handler = Self {
            algorithm,
            version,
            revision,
            key_length,
            permissions,
            o_value: Vec::new(),
            u_value: Vec::new(),
            oe_value: None,
            ue_value: None,
            perms_value: None,
            encryption_key: None,
            file_id: vec![0; 16],
        };

        // Generate random file ID if not provided
        thread_rng().fill_bytes(&mut handler.file_id);

        // Generate encryption values
        handler.generate_encryption_values(user_password, owner_password)?;

        Ok(handler)
    }

    pub fn authenticate_password(&self, password: &[u8]) -> Result<Vec<u8>, PDFCryptoError> {
        if self.revision >= 5 {
            self.authenticate_password_r5(password)
        } else {
            self.authenticate_password_legacy(password)
        }
    }

    fn authenticate_password_r5(&self, password: &[u8]) -> Result<Vec<u8>, PDFCryptoError> {
        // SHA-256 based authentication for R5/R6
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(&self.u_value[32..40]); // Salt
        let hash = hasher.finalize();

        if hash[..32] == self.u_value[..32] {
            // User password authentication successful
            if let Some(ref ue) = self.ue_value {
                return self.decrypt_encryption_key(password, ue);
            }
        }

        // Try owner password
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(&self.o_value[32..40]); // Salt
        let hash = hasher.finalize();

        if hash[..32] == self.o_value[..32] {
            // Owner password authentication successful
            if let Some(ref oe) = self.oe_value {
                return self.decrypt_encryption_key(password, oe);
            }
        }

        Err(PDFCryptoError::AuthenticationFailed)
    }

    fn authenticate_password_legacy(&self, password: &[u8]) -> Result<Vec<u8>, PDFCryptoError> {
        // RC4/AES-128 authentication for R2-R4
        let padded_pass = pad_password(password);
        
        // Generate file encryption key
        let mut hasher = Md5::new();
        hasher.update(&padded_pass);
        hasher.update(&self.o_value);
        hasher.update(&self.permissions.to_le_bytes());
        hasher.update(&self.file_id);
        
        let mut key = hasher.finalize().to_vec();
        
        if self.revision >= 3 {
            // Additional hashing for R3/R4
            for _ in 0..50 {
                let mut hasher = Md5::new();
                hasher.update(&key[..self.key_length]);
                key = hasher.finalize().to_vec();
            }
        }
        
        // Verify key against U value
        if self.verify_user_key(&key)? {
            return Ok(key[..self.key_length].to_vec());
        }
        
        Err(PDFCryptoError::AuthenticationFailed)
    }

    fn verify_user_key(&self, key: &[u8]) -> Result<bool, PDFCryptoError> {
        let padding = [
            0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
            0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
            0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
            0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
        ];

        let mut test_value = padding.to_vec();
        
        if self.revision >= 3 {
            // For R3/R4, use MD5 and RC4
            let mut hasher = Md5::new();
            hasher.update(&padding);
            hasher.update(&self.file_id);
            test_value = hasher.finalize().to_vec();
            
            use rc4::{KeyInit, StreamCipher};
            let mut cipher = rc4::Rc4::new(key.into());
            cipher.apply_keystream(&mut test_value);
            
            // Additional rounds for R3/R4
            for i in 1..20 {
                let mut round_key = key.to_vec();
                for byte in &mut round_key {
                    *byte ^= i as u8;
                }
                let mut cipher = rc4::Rc4::new(&round_key.into());
                cipher.apply_keystream(&mut test_value);
            }
        } else {
            // For R2, simple RC4
            use rc4::{KeyInit, StreamCipher};
            let mut cipher = rc4::Rc4::new(key.into());
            cipher.apply_keystream(&mut test_value);
        }
        
        Ok(test_value[..16] == self.u_value[..16])
    }

    fn generate_encryption_values(
        &mut self,
        user_password: &[u8],
        owner_password: &[u8],
    ) -> Result<(), PDFCryptoError> {
        if self.revision >= 5 {
            self.generate_r5_values(user_password, owner_password)
        } else {
            self.generate_legacy_values(user_password, owner_password)
        }
    }

    fn generate_r5_values(
        &mut self,
        user_password: &[u8],
        owner_password: &[u8],
    ) -> Result<(), PDFCryptoError> {
        // Generate random encryption key
        let mut encryption_key = vec![0; 32];
        thread_rng().fill_bytes(&mut encryption_key);
        
        // Generate random salts
        let mut user_salt = vec![0; 8];
        let mut owner_salt = vec![0; 8];
        let mut user_key_salt = vec![0; 8];
        let mut owner_key_salt = vec![0; 8];
        thread_rng().fill_bytes(&mut user_salt);
        thread_rng().fill_bytes(&mut owner_salt);
        thread_rng().fill_bytes(&mut user_key_salt);
        thread_rng().fill_bytes(&mut owner_key_salt);
        
        // Generate U value
        let mut hasher = Sha256::new();
        hasher.update(user_password);
        hasher.update(&user_salt);
        let user_hash = hasher.finalize();
        
        self.u_value = user_hash[..32].to_vec();
        self.u_value.extend_from_slice(&user_salt);
        self.u_value.extend_from_slice(&user_key_salt);
        
        // Generate O value
        let mut hasher = Sha256::new();
        hasher.update(owner_password);
        hasher.update(&owner_salt);
        hasher.update(&user_hash);
        let owner_hash = hasher.finalize();
        
        self.o_value = owner_hash[..32].to_vec();
        self.o_value.extend_from_slice(&owner_salt);
        self.o_value.extend_from_slice(&owner_key_salt);
        
        // Generate UE value
        let mut ue_key = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(user_password);
        hasher.update(&user_key_salt);
        ue_key.copy_from_slice(&hasher.finalize());
        
        self.ue_value = Some(self.aes256_encrypt(&ue_key, &encryption_key)?);
        
        // Generate OE value
        let mut oe_key = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(owner_password);
        hasher.update(&owner_key_salt);
        hasher.update(&user_hash);
        oe_key.copy_from_slice(&hasher.finalize());
        
        self.oe_value = Some(self.aes256_encrypt(&oe_key, &encryption_key)?);
        
        // Generate Perms value
        let mut perms = vec![0u8; 16];
        perms[0..4].copy_from_slice(&self.permissions.to_le_bytes());
        perms[4..8].copy_from_slice(b"T\0\0\0"); // Valid permissions
        perms[8..12].copy_from_slice(if self.encrypt_metadata { b"T\0\0\0" } else { b"F\0\0\0" });
        
        self.perms_value = Some(self.aes256_encrypt(&encryption_key, &perms)?);
        
        // Store encryption key
        self.encryption_key = Some(encryption_key);
        
        Ok(())
    }

    fn generate_legacy_values(
        &mut self,
        user_password: &[u8],
        owner_password: &[u8],
    ) -> Result<(), PDFCryptoError> {
        // Generate O value first
        let padded_owner = pad_password(owner_password);
        let mut key = md5_hash(&padded_owner);
        
        if self.revision >= 3 {
            // Additional hashing for R3/R4
            for _ in 0..50 {
                key = md5_hash(&key[..self.key_length]);
            }
        }
        
        let mut o_value = pad_password(user_password);
        
        // Encrypt with RC4
        use rc4::{KeyInit, StreamCipher};
        let mut cipher = rc4::Rc4::new(&key.into());
        cipher.apply_keystream(&mut o_value);
        
        if self.revision >= 3 {
            // Additional encryption rounds
            for i in 1..20 {
                let mut round_key = key.clone();
                for byte in &mut round_key {
                    *byte ^= i as u8;
                }
                let mut cipher = rc4::Rc4::new(&round_key.into());
                cipher.apply_keystream(&mut o_value);
            }
        }
        
        self.o_value = o_value;
        
        // Generate encryption key and U value
        let encryption_key = self.compute_encryption_key(user_password)?;
        self.u_value = self.compute_u_value(&encryption_key)?;
        self.encryption_key = Some(encryption_key);
        
        Ok(())
    }

    fn aes256_encrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, PDFCryptoError> {
        use aes::Aes256;
        use cipher::{BlockEncrypt, KeyInit};
        
        let cipher = Aes256::new(key.into());
        let mut buf = data.to_vec();
        
        // Ensure data is padded to block size
        let padding_len = 16 - (buf.len() % 16);
        buf.extend(std::iter::repeat(padding_len as u8).take(padding_len));
        
        // Generate random IV
        let mut iv = vec![0u8; 16];
        thread_rng().fill_bytes(&mut iv);
        
        // Encrypt in CBC mode
        let mut prev_block = iv.clone();
        for chunk in buf.chunks_mut(16) {
            // XOR with previous block
            for (b, p) in chunk.iter_mut().zip(prev_block.iter()) {
                *b ^= p;
            }
            
            // Encrypt block
            let block = generic_array::GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block(block);
            
            prev_block.copy_from_slice(chunk);
        }
        
        // Prepend IV to ciphertext
        let mut result = iv;
        result.extend_from_slice(&buf);
        Ok(result)
    }

    fn decrypt_encryption_key(&self, password: &[u8], encrypted_key: &[u8]) -> Result<Vec<u8>, PDFCryptoError> {
        use aes::Aes256;
        use cipher::{BlockDecrypt, KeyInit};
        
        if encrypted_key.len() < 16 {
            return Err(PDFCryptoError::InvalidDataLength {
                operation: "decrypt_encryption_key".to_string(),
            });
        }
        
        // Generate key encryption key
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(&encrypted_key[32..40]); // Salt
        let key = hasher.finalize();
        
        let cipher = Aes256::new((&key).into());
        
        // Extract IV and ciphertext
        let (iv, ciphertext) = encrypted_key.split_at(16);
        let mut buf = ciphertext.to_vec();
        
        // Decrypt in CBC mode
        let mut prev_block = iv.to_vec();
        for chunk in buf.chunks_mut(16) {
            let saved_block = chunk.to_vec();
            let block = generic_array::GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block(block);
            
            // XOR with previous block
            for (b, p) in chunk.iter_mut().zip(prev_block.iter()) {
                *b ^= p;
            }
            
            prev_block = saved_block;
        }
        
        // Remove PKCS#7 padding
        if let Some(&padding_len) = buf.last() {
            if padding_len as usize <= buf.len() {
                buf.truncate(buf.len() - padding_len as usize);
            }
        }
        
        Ok(buf)
    }
}

// Utility functions
fn pad_password(password: &[u8]) -> Vec<u8> {
    let padding = [
        0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
        0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
        0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
        0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
    ];
    
    let mut result = password[..32.min(password.len())].to_vec();
    result.extend_from_slice(&padding[..32 - result.len()]);
    result
}

fn md5_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_padding() {
        let password = b"test";
        let padded = pad_password(password);
        assert_eq!(padded.len(), 32);
        assert_eq!(&padded[..4], password);
    }

    #[test]
    fn test_authentication_rc4_40() -> Result<(), PDFCryptoError> {
        let handler = StandardSecurityHandler::new(
            EncryptionAlgorithm::RC4_40,
            0xffffffff,
            b"user",
            b"owner",
        )?;
        
        // Test correct password
        assert!(handler.authenticate_password(b"user").is_ok());
        
        // Test incorrect password
        assert!(handler.authenticate_password(b"wrong").is_err());
        
        Ok(())
    }

    #[test]
    fn test_authentication_aes_256() -> Result<(), PDFCryptoError> {
        let handler = StandardSecurityHandler::new(
            EncryptionAlgorithm::AES_256,
            0xffffffff,
            b"user",
            b"owner",
        )?;
        
        // Test correct passwords
        assert!(handler.authenticate_password(b"user").is_ok());
        assert!(handler.authenticate_password(b"owner").is_ok());
        
        // Test incorrect password
        assert!(handler.authenticate_password(b"wrong").is_err());
        
        Ok(())
    }
}
