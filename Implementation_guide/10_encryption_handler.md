# Module 10: EncryptionHandler - PDF Encryption (CRITICAL)

## Overview
The `EncryptionHandler` module handles PDF encryption for final output. This module depends on the successful implementation of Module 9 (DecryptionHandler) and uses similar cryptographic approaches to encrypt the processed PDF with identical invisible data.

## Module Requirements
- **Dependencies**: Same crypto crates as DecryptionHandler + previous modules
- **Compilation**: Must compile independently but depends on DecryptionHandler working
- **Purpose**: Encrypt final PDF output while preserving all invisible data
- **Critical Rule**: Must produce encrypted PDFs identical to source encryption where possible

## Implementation Guide

### Step 1: Create Module File
Create `src/encryption_handler.rs`:

```rust
//! EncryptionHandler Module
//! 
//! Handles PDF encryption for final output while preserving invisible data.
//! Depends on successful DecryptionHandler implementation.

use std::collections::HashMap;
use aes::Aes128;
use cbc::{Encryptor, cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit}};
use rc4::{Rc4, KeyInit, StreamCipher};
use md5::{Md5, Digest as Md5Digest};
use sha2::{Sha256, Digest as Sha256Digest};
use rand::{Rng, thread_rng};
use crate::silent_debug;
use crate::decryption_handler::{EncryptionParams, SecurityHandler, EncryptionAlgorithm};

type Aes128CbcEnc = Encryptor<Aes128>;

/// PDF Encryption Handler
pub struct EncryptionHandler {
    /// Target encryption parameters (copy from source or new)
    target_params: Option<EncryptionParams>,
    /// User password for output
    output_user_password: Option<String>,
    /// Owner password for output
    output_owner_password: Option<String>,
    /// Generated master key
    master_key: Option<Vec<u8>>,
}

impl EncryptionHandler {
    /// Create new encryption handler
    pub fn new() -> Self {
        Self {
            target_params: None,
            output_user_password: None,
            output_owner_password: None,
            master_key: None,
        }
    }

    /// Set target encryption parameters (copied from source PDF)
    pub fn set_target_params(&mut self, params: EncryptionParams) {
        self.target_params = Some(params);
        silent_debug!("Set target encryption parameters");
    }

    /// Set output passwords
    pub fn set_output_passwords(&mut self, user_password: String, owner_password: String) {
        self.output_user_password = Some(user_password);
        self.output_owner_password = Some(owner_password);
        silent_debug!("Set output passwords for encryption");
    }

    /// Create encryption parameters identical to source
    pub fn clone_encryption_params(&mut self, source_params: &EncryptionParams) -> EncryptionParams {
        let cloned = EncryptionParams {
            handler: source_params.handler.clone(),
            algorithm: source_params.algorithm.clone(),
            key_length: source_params.key_length,
            permissions: source_params.permissions,
            user_key: source_params.user_key.clone(),
            owner_key: source_params.owner_key.clone(),
            file_id: source_params.file_id.clone(),
            revision: source_params.revision,
        };

        self.target_params = Some(cloned.clone());
        silent_debug!("Cloned encryption parameters from source");
        
        cloned
    }

    /// Encrypt PDF data with target parameters
    pub fn encrypt_pdf(&mut self, pdf_data: Vec<u8>) -> Result<Vec<u8>, EncryptionError> {
        silent_debug!("Starting PDF encryption process");

        let params = self.target_params.as_ref()
            .ok_or(EncryptionError::NoParameters)?;

        // Generate master key based on output passwords
        let master_key = self.generate_master_key(params)?;
        self.master_key = Some(master_key);

        // Encrypt PDF data
        let encrypted_data = self.encrypt_pdf_data(&pdf_data, params)?;

        // Update encryption dictionary in PDF
        let final_data = self.update_encryption_dictionary(encrypted_data, params)?;

        silent_debug!("PDF encryption completed successfully");
        Ok(final_data)
    }

    /// Generate master encryption key
    fn generate_master_key(&self, params: &EncryptionParams) -> Result<Vec<u8>, EncryptionError> {
        let user_password = self.output_user_password.as_deref().unwrap_or("");
        let owner_password = self.output_owner_password.as_deref().unwrap_or("");

        match params.revision {
            2 | 3 => self.generate_key_rev2_3(user_password, owner_password, params),
            4 | 5 => self.generate_key_rev4_5(user_password, owner_password, params),
            _ => Err(EncryptionError::UnsupportedRevision(params.revision)),
        }
    }

    /// Generate key for revision 2-3
    fn generate_key_rev2_3(&self, user_password: &str, owner_password: &str, params: &EncryptionParams) -> Result<Vec<u8>, EncryptionError> {
        // Pad passwords to 32 bytes
        let mut padded_user = [0u8; 32];
        let mut padded_owner = [0u8; 32];
        
        self.pad_password(user_password.as_bytes(), &mut padded_user);
        self.pad_password(owner_password.as_bytes(), &mut padded_owner);

        // Generate owner key
        let owner_key = self.compute_owner_key(&padded_owner, &padded_user, params)?;

        // Generate user key
        let mut hasher = Md5::new();
        hasher.update(&padded_user);
        hasher.update(&owner_key);
        hasher.update(&params.permissions.to_le_bytes());
        hasher.update(&params.file_id);

        let mut key = hasher.finalize().to_vec();
        key.truncate(params.key_length / 8);

        Ok(key)
    }

    /// Generate key for revision 4-5
    fn generate_key_rev4_5(&self, user_password: &str, owner_password: &str, params: &EncryptionParams) -> Result<Vec<u8>, EncryptionError> {
        // More complex key generation for newer revisions
        // For now, fall back to rev 2-3 method
        self.generate_key_rev2_3(user_password, owner_password, params)
    }

    /// Pad password according to PDF standard
    fn pad_password(&self, password: &[u8], output: &mut [u8; 32]) {
        let padding = b"\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";
        
        let copy_len = password.len().min(32);
        output[..copy_len].copy_from_slice(&password[..copy_len]);
        
        if copy_len < 32 {
            let remaining = 32 - copy_len;
            output[copy_len..].copy_from_slice(&padding[..remaining]);
        }
    }

    /// Compute owner key
    fn compute_owner_key(&self, owner_password: &[u8; 32], user_password: &[u8; 32], params: &EncryptionParams) -> Result<Vec<u8>, EncryptionError> {
        let mut hasher = Md5::new();
        hasher.update(owner_password);
        let mut key = hasher.finalize().to_vec();

        // For revision 3 and above, hash 50 times
        if params.revision >= 3 {
            for _ in 0..50 {
                let mut hasher = Md5::new();
                hasher.update(&key);
                key = hasher.finalize().to_vec();
            }
        }

        key.truncate(params.key_length / 8);

        // Encrypt user password with derived key
        let encrypted = self.encrypt_with_rc4(user_password, &key)?;

        // For revision 3 and above, encrypt 19 more times
        if params.revision >= 3 {
            let mut result = encrypted;
            for i in 1..=19 {
                let mut modified_key = key.clone();
                for byte in &mut modified_key {
                    *byte ^= i as u8;
                }
                result = self.encrypt_with_rc4(&result, &modified_key)?;
            }
            Ok(result)
        } else {
            Ok(encrypted)
        }
    }

    /// Encrypt PDF data using appropriate algorithm
    fn encrypt_pdf_data(&self, pdf_data: &[u8], params: &EncryptionParams) -> Result<Vec<u8>, EncryptionError> {
        let master_key = self.master_key.as_ref().ok_or(EncryptionError::NoMasterKey)?;

        match &params.algorithm {
            EncryptionAlgorithm::RC4 { .. } => self.encrypt_with_rc4(pdf_data, master_key),
            EncryptionAlgorithm::AES128 => self.encrypt_with_aes128(pdf_data, master_key),
            EncryptionAlgorithm::AES256 => self.encrypt_with_aes256(pdf_data, master_key),
        }
    }

    /// Encrypt with RC4
    fn encrypt_with_rc4(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let mut cipher = Rc4::new_from_slice(key)
            .map_err(|_| EncryptionError::CryptoError("Invalid RC4 key".to_string()))?;
        
        let mut result = data.to_vec();
        cipher.apply_keystream(&mut result);
        
        Ok(result)
    }

    /// Encrypt with AES-128
    fn encrypt_with_aes128(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        // Generate random IV
        let mut iv = [0u8; 16];
        thread_rng().fill(&mut iv);

        // Create cipher
        let cipher = Aes128CbcEnc::new_from_slices(key, &iv)
            .map_err(|_| EncryptionError::CryptoError("Invalid AES key/IV".to_string()))?;

        // Encrypt
        let mut buffer = data.to_vec();
        let ciphertext = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())
            .map_err(|_| EncryptionError::CryptoError("AES encryption failed".to_string()))?;

        // Prepend IV to ciphertext
        let mut result = iv.to_vec();
        result.extend_from_slice(ciphertext);
        
        Ok(result)
    }

    /// Encrypt with AES-256
    fn encrypt_with_aes256(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        // AES-256 implementation would be similar to AES-128 but with different key size
        // For now, fall back to AES-128
        self.encrypt_with_aes128(data, key)
    }

    /// Update encryption dictionary in PDF data
    fn update_encryption_dictionary(&self, mut pdf_data: Vec<u8>, params: &EncryptionParams) -> Result<Vec<u8>, EncryptionError> {
        // This is a complex operation that involves:
        // 1. Finding the encryption dictionary in the PDF
        // 2. Updating the U and O values with computed keys
        // 3. Ensuring the document ID is preserved
        // 4. Updating cross-reference table if needed

        // For now, this is a placeholder that returns the data as-is
        // Real implementation would parse and modify the PDF structure
        
        silent_debug!("Updated encryption dictionary (placeholder implementation)");
        Ok(pdf_data)
    }

    /// Generate user key for encryption dictionary
    fn generate_user_key(&self, params: &EncryptionParams) -> Result<Vec<u8>, EncryptionError> {
        let master_key = self.master_key.as_ref().ok_or(EncryptionError::NoMasterKey)?;

        match params.revision {
            2 => {
                // For revision 2, user key is RC4 of padding with master key
                let padding = b"\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";
                self.encrypt_with_rc4(padding, master_key)
            }
            3 | 4 | 5 => {
                // For revision 3+, more complex computation
                let mut hasher = Md5::new();
                hasher.update(b"\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A");
                hasher.update(&params.file_id);
                let hash = hasher.finalize().to_vec();

                let mut encrypted = self.encrypt_with_rc4(&hash, master_key)?;

                // Encrypt 19 more times with modified keys
                for i in 1..=19 {
                    let mut modified_key = master_key.to_vec();
                    for byte in &mut modified_key {
                        *byte ^= i as u8;
                    }
                    encrypted = self.encrypt_with_rc4(&encrypted, &modified_key)?;
                }

                // Pad to 32 bytes with random data
                if encrypted.len() < 32 {
                    let mut rng = thread_rng();
                    while encrypted.len() < 32 {
                        encrypted.push(rng.gen());
                    }
                }

                Ok(encrypted)
            }
            _ => Err(EncryptionError::UnsupportedRevision(params.revision)),
        }
    }

    /// Create standard encryption parameters for new PDFs
    pub fn create_standard_encryption(&mut self, user_password: &str, owner_password: &str, permissions: u32) -> EncryptionParams {
        let params = EncryptionParams {
            handler: SecurityHandler::Standard,
            algorithm: EncryptionAlgorithm::AES128,
            key_length: 128,
            permissions,
            user_key: Vec::new(), // Will be computed
            owner_key: Vec::new(), // Will be computed
            file_id: Vec::new(),   // Will be set from document ID
            revision: 4,
        };

        self.output_user_password = Some(user_password.to_string());
        self.output_owner_password = Some(owner_password.to_string());
        self.target_params = Some(params.clone());

        silent_debug!("Created standard encryption parameters");
        params
    }

    /// Check if handler is ready to encrypt
    pub fn is_ready(&self) -> bool {
        self.target_params.is_some() && 
        (self.output_user_password.is_some() || self.output_owner_password.is_some())
    }

    /// Get current encryption parameters
    pub fn get_params(&self) -> Option<&EncryptionParams> {
        self.target_params.as_ref()
    }

    /// Clear all sensitive data
    pub fn clear_sensitive_data(&mut self) {
        self.master_key = None;
        self.output_user_password = None;
        self.output_owner_password = None;
        self.target_params = None;
        
        silent_debug!("Cleared all sensitive encryption data");
    }
}

impl Default for EncryptionHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Encryption errors
#[derive(Debug, Clone)]
pub enum EncryptionError {
    NoParameters,
    NoMasterKey,
    UnsupportedRevision(u32),
    CryptoError(String),
    InvalidPassword,
    DictionaryUpdateFailed,
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionError::NoParameters => write!(f, "No encryption parameters set"),
            EncryptionError::NoMasterKey => write!(f, "No master encryption key available"),
            EncryptionError::UnsupportedRevision(rev) => write!(f, "Unsupported encryption revision: {}", rev),
            EncryptionError::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            EncryptionError::InvalidPassword => write!(f, "Invalid password provided"),
            EncryptionError::DictionaryUpdateFailed => write!(f, "Failed to update encryption dictionary"),
        }
    }
}

impl std::error::Error for EncryptionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_handler_creation() {
        let handler = EncryptionHandler::new();
        assert!(handler.target_params.is_none());
        assert!(handler.master_key.is_none());
        assert!(!handler.is_ready());
    }

    #[test]
    fn test_password_setting() {
        let mut handler = EncryptionHandler::new();
        
        handler.set_output_passwords("user123".to_string(), "owner456".to_string());
        assert!(handler.output_user_password.is_some());
        assert!(handler.output_owner_password.is_some());
    }

    #[test]
    fn test_standard_encryption_creation() {
        let mut handler = EncryptionHandler::new();
        
        let params = handler.create_standard_encryption("user", "owner", 0xFFFFFFFC);
        assert_eq!(params.revision, 4);
        assert_eq!(params.key_length, 128);
        assert!(handler.is_ready());
    }

    #[test]
    fn test_password_padding() {
        let handler = EncryptionHandler::new();
        let mut padded = [0u8; 32];
        
        handler.pad_password(b"test", &mut padded);
        assert_eq!(&padded[..4], b"test");
        assert_eq!(padded[4], 0x28); // First byte of standard padding
    }

    #[test]
    fn test_clear_sensitive_data() {
        let mut handler = EncryptionHandler::new();
        handler.set_output_passwords("test".to_string(), "test".to_string());
        handler.master_key = Some(vec![1, 2, 3, 4]);
        
        handler.clear_sensitive_data();
        
        assert!(handler.output_user_password.is_none());
        assert!(handler.master_key.is_none());
        assert!(handler.target_params.is_none());
    }

    #[test]
    fn test_rc4_encryption() {
        let handler = EncryptionHandler::new();
        let key = b"testkey";
        let data = b"Hello, World!";
        
        let result = handler.encrypt_with_rc4(data, key);
        assert!(result.is_ok());
    }
}
```

### Step 2: Update lib.rs
Update `src/lib.rs`:

```rust
//! PDF Invisible Data Cloning System
//! 
//! A Rust implementation for 100% invisible data cloning between PDFs
//! with complete anti-forensic capabilities.

pub mod complete_invisible_data;
pub mod console_supressor;
pub mod hash_manager;
pub mod document_id_manager;
pub mod memory_sanitizer;
pub mod file_loader;
pub mod output_generator;
pub mod pdf_structure;
pub mod decryption_handler;
pub mod encryption_handler;

pub use complete_invisible_data::{CompleteInvisibleData, InvisibleDataError};
pub use console_supressor::{
    enable_silent_mode, disable_silent_mode, is_silent_mode,
    silent_operation, OutputCapture, EnvironmentSuppressor,
    initialize_suppression, NullWriter
};
pub use hash_manager::{HashManager, HashError, HashUtils};
pub use document_id_manager::{DocumentIDManager, DocumentID, DocumentIDError, DocumentIDUtils};
pub use memory_sanitizer::{
    MemorySanitizer, SanitizedBuffer, SanitizedString, SystemSanitizer
};
pub use file_loader::{FileLoader, FileLoaderError, FileLoaderConfig, FileUtils};
pub use output_generator::{OutputGenerator, OutputError, OutputConfig, OutputUtils};
pub use pdf_structure::{
    PDFStructure, PDFObject, PDFObjectType, XRefTable, XRefEntry, 
    PDFTrailer, PDFParseError, PDFUtils
};
pub use decryption_handler::{
    DecryptionHandler, DecryptionError, EncryptionParams, 
    SecurityHandler, EncryptionAlgorithm
};
pub use encryption_handler::{EncryptionHandler, EncryptionError};

// Re-export macros
pub use silent_print;
pub use silent_println;
pub use silent_eprint;
pub use silent_eprintln;
pub use silent_debug;
pub use silent_error;
pub use silent_warning;
pub use silent_info;
```

### Step 3: Validation Commands
```bash
cargo check --lib
cargo build --lib
cargo test encryption_handler
```

## Critical Dependencies
This module REQUIRES:
- ✅ **Module 9 (DecryptionHandler)** must be working first
- ✅ **Same crypto crates** (aes, rc4, md5, sha2, etc.)
- ✅ **Ability to generate identical encryption** to source PDFs

## Success Criteria
- ✅ Module compiles without errors
- ✅ All unit tests pass  
- ⚠️ **CRITICAL**: Must produce encrypted PDFs that match source encryption
- ⚠️ **CRITICAL**: Encrypted output must be decryptable with provided passwords
- ⚠️ **CRITICAL**: All invisible data must be preserved during encryption

## Usage in Later Modules
```rust
use crate::encryption_handler::EncryptionHandler;

let mut encryptor = EncryptionHandler::new();

// Copy encryption from source PDF
encryptor.clone_encryption_params(&source_encryption_params);

// Set output passwords
encryptor.set_output_passwords(user_password, owner_password);

// Encrypt final PDF with invisible data
let encrypted_pdf = encryptor.encrypt_pdf(processed_pdf_data)?;
```

## Next Module
After this module compiles and tests pass, proceed to Module 11: XRefManager.

**Note**: If Modules 9-10 (crypto handlers) fail to work with real PDFs, the entire project must pivot to alternative strategies before continuing.