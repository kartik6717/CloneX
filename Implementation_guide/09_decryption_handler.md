# Module 9: DecryptionHandler - PDF Decryption (CRITICAL)

## Overview
The `DecryptionHandler` module is the MOST CRITICAL component of the entire system. This module must solve the fundamental Rust limitation of lacking mature PDF encryption/decryption libraries. Without this module working, the entire project fails because encrypted PDFs cannot be processed.

## Module Requirements
- **Dependencies**: External crypto crates + potential FFI bindings or external tools
- **Compilation**: Must compile independently but may require complex setup
- **Purpose**: Decrypt encrypted PDFs to access invisible data
- **Critical Rule**: This is a MAKE-OR-BREAK module - project success depends entirely on this

## CRITICAL IMPLEMENTATION DECISION REQUIRED

You MUST choose ONE of these strategies before implementing:

### Strategy A: Pure Rust Implementation
- Use `aes`, `md5`, `sha2`, `rc4` crates
- Manually implement PDF security handlers
- Pros: Pure Rust, no external dependencies
- Cons: Very complex, may not handle all encryption types

### Strategy B: FFI to C Libraries  
- Create safe Rust bindings to OpenSSL/poppler
- Use proven C encryption libraries
- Pros: Mature, handles all encryption types
- Cons: Complex FFI, platform dependencies

### Strategy C: External Tool Integration
- Shell out to `qpdf`, `pdftk`, or similar tools
- Process decrypted output in Rust
- Pros: Leverages existing tools
- Cons: Tool dependencies, harder to distribute

## Implementation Guide (Strategy A - Pure Rust)

### Step 1: Add Crypto Dependencies to Cargo.toml
Update `Cargo.toml`:

```toml
[package]
name = "pdf_invisible_cloning"
version = "0.1.0"
edition = "2021"

[dependencies]
md5 = "0.7"
sha2 = "0.10"
aes = "0.8"
cbc = "0.1"
rc4 = "0.1"
rand = "0.8"

[dev-dependencies]
hex = "0.4"
```

### Step 2: Create Module File
Create `src/decryption_handler.rs`:

```rust
//! DecryptionHandler Module
//! 
//! CRITICAL MODULE: Handles PDF decryption to enable invisible data extraction.
//! This module determines the success or failure of the entire project.

use std::collections::HashMap;
use aes::Aes128;
use cbc::{Decryptor, cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit}};
use rc4::{Rc4, KeyInit, StreamCipher};
use md5::{Md5, Digest as Md5Digest};
use sha2::{Sha256, Digest as Sha256Digest};
use crate::silent_debug;
use crate::pdf_structure::{PDFStructure, PDFObject, PDFObjectType};

type Aes128CbcDec = Decryptor<Aes128>;

/// PDF Security Handler types
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityHandler {
    Standard,           // Standard security handler
    Adobe,             // Adobe proprietary
    Unknown(Vec<u8>),  // Unknown handler
}

/// PDF Encryption algorithms
#[derive(Debug, Clone, PartialEq)]
pub enum EncryptionAlgorithm {
    RC4 { key_length: usize },
    AES128,
    AES256,
}

/// PDF Encryption parameters
#[derive(Debug, Clone)]
pub struct EncryptionParams {
    pub handler: SecurityHandler,
    pub algorithm: EncryptionAlgorithm,
    pub key_length: usize,
    pub permissions: u32,
    pub user_key: Vec<u8>,
    pub owner_key: Vec<u8>,
    pub file_id: Vec<u8>,
    pub revision: u32,
}

/// PDF Decryption Handler
pub struct DecryptionHandler {
    /// Current encryption parameters
    encryption_params: Option<EncryptionParams>,
    /// Master decryption key
    master_key: Option<Vec<u8>>,
    /// User password (if provided)
    user_password: Option<String>,
    /// Owner password (if provided) 
    owner_password: Option<String>,
}

impl DecryptionHandler {
    /// Create new decryption handler
    pub fn new() -> Self {
        Self {
            encryption_params: None,
            master_key: None,
            user_password: None,
            owner_password: None,
        }
    }

    /// Set user password for decryption
    pub fn set_user_password(&mut self, password: String) {
        self.user_password = Some(password);
        silent_debug!("User password set for decryption");
    }

    /// Set owner password for decryption
    pub fn set_owner_password(&mut self, password: String) {
        self.owner_password = Some(password);
        silent_debug!("Owner password set for decryption");
    }

    /// Analyze PDF encryption parameters
    pub fn analyze_encryption(&mut self, pdf_structure: &PDFStructure) -> Result<EncryptionParams, DecryptionError> {
        silent_debug!("Analyzing PDF encryption parameters");

        if !pdf_structure.is_encrypted() {
            return Err(DecryptionError::NotEncrypted);
        }

        // Extract encryption dictionary from PDF structure
        let encrypt_dict = self.find_encryption_dictionary(pdf_structure)?;
        
        // Parse encryption parameters
        let params = self.parse_encryption_parameters(&encrypt_dict)?;
        
        self.encryption_params = Some(params.clone());
        
        silent_debug!("Encryption analysis complete: {:?}", params.algorithm);
        Ok(params)
    }

    /// Attempt to decrypt PDF with provided passwords
    pub fn decrypt_pdf(&mut self, pdf_data: Vec<u8>) -> Result<Vec<u8>, DecryptionError> {
        silent_debug!("Starting PDF decryption process");

        // Parse PDF structure to get encryption info
        let pdf_structure = PDFStructure::parse_from_data(pdf_data.clone())
            .map_err(|e| DecryptionError::ParseError(format!("{}", e)))?;

        // Analyze encryption
        let params = self.analyze_encryption(&pdf_structure)?;

        // Try to authenticate with provided passwords
        let master_key = self.authenticate_password(&params)?;
        self.master_key = Some(master_key);

        // Decrypt the PDF data
        let decrypted_data = self.decrypt_pdf_data(&pdf_data, &params)?;

        silent_debug!("PDF decryption completed successfully");
        Ok(decrypted_data)
    }

    /// Find encryption dictionary in PDF structure
    fn find_encryption_dictionary(&self, pdf_structure: &PDFStructure) -> Result<HashMap<Vec<u8>, PDFObject>, DecryptionError> {
        // Look for /Encrypt reference in trailer
        if let Some(ref trailer) = pdf_structure.trailer {
            if let Some(encrypt_ref) = trailer.get_entry(b"Encrypt") {
                if let PDFObjectType::Reference { object_number, .. } = &encrypt_ref.object_type {
                    // Get the encryption object
                    if let Some(encrypt_obj) = pdf_structure.get_object(*object_number) {
                        if let Some(dict) = encrypt_obj.as_dictionary() {
                            return Ok(dict.clone());
                        }
                    }
                }
            }
        }

        Err(DecryptionError::EncryptionDictNotFound)
    }

    /// Parse encryption parameters from dictionary
    fn parse_encryption_parameters(&self, dict: &HashMap<Vec<u8>, PDFObject>) -> Result<EncryptionParams, DecryptionError> {
        // Extract Filter (security handler)
        let handler = if let Some(filter_obj) = dict.get(b"Filter") {
            match &filter_obj.object_type {
                PDFObjectType::Name(name) => {
                    if name == b"Standard" {
                        SecurityHandler::Standard
                    } else if name == b"Adobe.PPKLite" {
                        SecurityHandler::Adobe
                    } else {
                        SecurityHandler::Unknown(name.clone())
                    }
                }
                _ => return Err(DecryptionError::InvalidFormat("Invalid Filter type".to_string())),
            }
        } else {
            return Err(DecryptionError::MissingField("Filter".to_string()));
        };

        // Extract V (algorithm version)
        let algorithm = if let Some(v_obj) = dict.get(b"V") {
            match &v_obj.object_type {
                PDFObjectType::Integer(v) => {
                    match *v {
                        1 => EncryptionAlgorithm::RC4 { key_length: 40 },
                        2 => EncryptionAlgorithm::RC4 { key_length: 128 },
                        4 => EncryptionAlgorithm::AES128,
                        5 => EncryptionAlgorithm::AES256,
                        _ => return Err(DecryptionError::UnsupportedAlgorithm(*v as u32)),
                    }
                }
                _ => return Err(DecryptionError::InvalidFormat("Invalid V type".to_string())),
            }
        } else {
            EncryptionAlgorithm::RC4 { key_length: 40 } // Default
        };

        // Extract Length (key length)
        let key_length = if let Some(length_obj) = dict.get(b"Length") {
            match &length_obj.object_type {
                PDFObjectType::Integer(len) => *len as usize,
                _ => 40, // Default
            }
        } else {
            40 // Default
        };

        // Extract P (permissions)
        let permissions = if let Some(p_obj) = dict.get(b"P") {
            match &p_obj.object_type {
                PDFObjectType::Integer(p) => *p as u32,
                _ => 0,
            }
        } else {
            0
        };

        // Extract U (user key)
        let user_key = if let Some(u_obj) = dict.get(b"U") {
            match &u_obj.object_type {
                PDFObjectType::String(data) => data.clone(),
                _ => return Err(DecryptionError::InvalidFormat("Invalid U type".to_string())),
            }
        } else {
            return Err(DecryptionError::MissingField("U".to_string()));
        };

        // Extract O (owner key)
        let owner_key = if let Some(o_obj) = dict.get(b"O") {
            match &o_obj.object_type {
                PDFObjectType::String(data) => data.clone(),
                _ => return Err(DecryptionError::InvalidFormat("Invalid O type".to_string())),
            }
        } else {
            return Err(DecryptionError::MissingField("O".to_string()));
        };

        // Extract R (revision)
        let revision = if let Some(r_obj) = dict.get(b"R") {
            match &r_obj.object_type {
                PDFObjectType::Integer(r) => *r as u32,
                _ => 2, // Default
            }
        } else {
            2 // Default
        };

        Ok(EncryptionParams {
            handler,
            algorithm,
            key_length,
            permissions,
            user_key,
            owner_key,
            file_id: Vec::new(), // Would be extracted from document ID
            revision,
        })
    }

    /// Authenticate password and derive master key
    fn authenticate_password(&self, params: &EncryptionParams) -> Result<Vec<u8>, DecryptionError> {
        silent_debug!("Attempting password authentication");

        // Try user password first
        if let Some(ref password) = self.user_password {
            if let Ok(key) = self.try_user_password(password, params) {
                silent_debug!("User password authentication successful");
                return Ok(key);
            }
        }

        // Try owner password
        if let Some(ref password) = self.owner_password {
            if let Ok(key) = self.try_owner_password(password, params) {
                silent_debug!("Owner password authentication successful");
                return Ok(key);
            }
        }

        // Try empty password (common case)
        if let Ok(key) = self.try_user_password("", params) {
            silent_debug!("Empty password authentication successful");
            return Ok(key);
        }

        Err(DecryptionError::AuthenticationFailed)
    }

    /// Try user password authentication
    fn try_user_password(&self, password: &str, params: &EncryptionParams) -> Result<Vec<u8>, DecryptionError> {
        match params.revision {
            2 | 3 => self.authenticate_user_password_rev2_3(password, params),
            4 | 5 => self.authenticate_user_password_rev4_5(password, params),
            _ => Err(DecryptionError::UnsupportedRevision(params.revision)),
        }
    }

    /// Try owner password authentication
    fn try_owner_password(&self, password: &str, params: &EncryptionParams) -> Result<Vec<u8>, DecryptionError> {
        // Owner password authentication is more complex
        // This is a simplified implementation
        self.try_user_password(password, params)
    }

    /// Authenticate user password for revision 2-3
    fn authenticate_user_password_rev2_3(&self, password: &str, params: &EncryptionParams) -> Result<Vec<u8>, DecryptionError> {
        // Pad password to 32 bytes
        let mut padded_password = [0u8; 32];
        let password_bytes = password.as_bytes();
        let copy_len = password_bytes.len().min(32);
        padded_password[..copy_len].copy_from_slice(&password_bytes[..copy_len]);
        
        // Apply standard padding
        if copy_len < 32 {
            let padding = b"\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";
            let remaining = 32 - copy_len;
            padded_password[copy_len..].copy_from_slice(&padding[..remaining]);
        }

        // Compute encryption key
        let mut hasher = Md5::new();
        hasher.update(&padded_password);
        hasher.update(&params.owner_key);
        hasher.update(&params.permissions.to_le_bytes());
        hasher.update(&params.file_id);

        let mut key = hasher.finalize().to_vec();
        
        // Truncate to key length
        key.truncate(params.key_length / 8);

        // Verify against user key
        if self.verify_user_key(&key, params)? {
            Ok(key)
        } else {
            Err(DecryptionError::AuthenticationFailed)
        }
    }

    /// Authenticate user password for revision 4-5
    fn authenticate_user_password_rev4_5(&self, password: &str, params: &EncryptionParams) -> Result<Vec<u8>, DecryptionError> {
        // More complex authentication for newer revisions
        // This is a simplified implementation
        self.authenticate_user_password_rev2_3(password, params)
    }

    /// Verify user key matches computed key
    fn verify_user_key(&self, key: &[u8], params: &EncryptionParams) -> Result<bool, DecryptionError> {
        // Compute expected user key and compare with stored user key
        // This is a simplified verification
        Ok(true) // Placeholder - real implementation would do proper verification
    }

    /// Decrypt PDF data using master key
    fn decrypt_pdf_data(&self, pdf_data: &[u8], params: &EncryptionParams) -> Result<Vec<u8>, DecryptionError> {
        let master_key = self.master_key.as_ref().ok_or(DecryptionError::NoMasterKey)?;
        
        match &params.algorithm {
            EncryptionAlgorithm::RC4 { .. } => self.decrypt_with_rc4(pdf_data, master_key),
            EncryptionAlgorithm::AES128 => self.decrypt_with_aes128(pdf_data, master_key),
            EncryptionAlgorithm::AES256 => self.decrypt_with_aes256(pdf_data, master_key),
        }
    }

    /// Decrypt with RC4
    fn decrypt_with_rc4(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        let mut cipher = Rc4::new_from_slice(key)
            .map_err(|_| DecryptionError::CryptoError("Invalid RC4 key".to_string()))?;
        
        let mut result = data.to_vec();
        cipher.apply_keystream(&mut result);
        
        Ok(result)
    }

    /// Decrypt with AES-128
    fn decrypt_with_aes128(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        if data.len() < 16 {
            return Err(DecryptionError::CryptoError("Data too short for AES".to_string()));
        }

        // Extract IV (first 16 bytes)
        let iv = &data[..16];
        let ciphertext = &data[16..];

        // Create cipher
        let cipher = Aes128CbcDec::new_from_slices(key, iv)
            .map_err(|_| DecryptionError::CryptoError("Invalid AES key/IV".to_string()))?;

        // Decrypt
        let mut buffer = ciphertext.to_vec();
        let decrypted = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|_| DecryptionError::CryptoError("AES decryption failed".to_string()))?;

        Ok(decrypted.to_vec())
    }

    /// Decrypt with AES-256
    fn decrypt_with_aes256(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        // AES-256 implementation would be similar to AES-128 but with different key size
        // For now, fall back to AES-128
        self.decrypt_with_aes128(data, key)
    }

    /// Check if handler can decrypt this PDF
    pub fn can_decrypt(&self, pdf_structure: &PDFStructure) -> bool {
        if !pdf_structure.is_encrypted() {
            return false;
        }

        // Check if we have passwords
        self.user_password.is_some() || self.owner_password.is_some()
    }

    /// Get current encryption parameters
    pub fn get_encryption_params(&self) -> Option<&EncryptionParams> {
        self.encryption_params.as_ref()
    }

    /// Clear all sensitive data
    pub fn clear_sensitive_data(&mut self) {
        self.master_key = None;
        self.user_password = None;
        self.owner_password = None;
        self.encryption_params = None;
        
        silent_debug!("Cleared all sensitive decryption data");
    }
}

impl Default for DecryptionHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Decryption errors
#[derive(Debug, Clone)]
pub enum DecryptionError {
    NotEncrypted,
    EncryptionDictNotFound,
    MissingField(String),
    InvalidFormat(String),
    UnsupportedAlgorithm(u32),
    UnsupportedRevision(u32),
    AuthenticationFailed,
    NoMasterKey,
    CryptoError(String),
    ParseError(String),
}

impl std::fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptionError::NotEncrypted => write!(f, "PDF is not encrypted"),
            DecryptionError::EncryptionDictNotFound => write!(f, "Encryption dictionary not found"),
            DecryptionError::MissingField(field) => write!(f, "Missing encryption field: {}", field),
            DecryptionError::InvalidFormat(msg) => write!(f, "Invalid encryption format: {}", msg),
            DecryptionError::UnsupportedAlgorithm(alg) => write!(f, "Unsupported encryption algorithm: {}", alg),
            DecryptionError::UnsupportedRevision(rev) => write!(f, "Unsupported encryption revision: {}", rev),
            DecryptionError::AuthenticationFailed => write!(f, "Password authentication failed"),
            DecryptionError::NoMasterKey => write!(f, "No master decryption key available"),
            DecryptionError::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            DecryptionError::ParseError(msg) => write!(f, "PDF parse error: {}", msg),
        }
    }
}

impl std::error::Error for DecryptionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decryption_handler_creation() {
        let handler = DecryptionHandler::new();
        assert!(handler.encryption_params.is_none());
        assert!(handler.master_key.is_none());
        assert!(handler.user_password.is_none());
        assert!(handler.owner_password.is_none());
    }

    #[test]
    fn test_password_setting() {
        let mut handler = DecryptionHandler::new();
        
        handler.set_user_password("user123".to_string());
        assert!(handler.user_password.is_some());
        
        handler.set_owner_password("owner456".to_string());
        assert!(handler.owner_password.is_some());
    }

    #[test]
    fn test_clear_sensitive_data() {
        let mut handler = DecryptionHandler::new();
        handler.set_user_password("test".to_string());
        handler.master_key = Some(vec![1, 2, 3, 4]);
        
        handler.clear_sensitive_data();
        
        assert!(handler.user_password.is_none());
        assert!(handler.master_key.is_none());
        assert!(handler.encryption_params.is_none());
    }

    #[test]
    fn test_rc4_decryption() {
        let handler = DecryptionHandler::new();
        let key = b"testkey";
        let data = b"Hello, World!";
        
        // This would normally test actual RC4 decryption
        // For now, just test that the function doesn't panic
        let result = handler.decrypt_with_rc4(data, key);
        assert!(result.is_ok());
    }
}
```

### Step 3: Update lib.rs
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

### Step 4: Validation Commands
```bash
cargo check --lib
cargo build --lib
cargo test decryption_handler
```

## CRITICAL TESTING REQUIREMENTS

This module MUST be tested with real encrypted PDFs before proceeding:

1. **Create test encrypted PDFs** with known passwords
2. **Test password authentication** with various encryption types
3. **Verify decryption produces readable PDF data**
4. **Test with different PDF versions and encryption algorithms**

## Success Criteria
- ✅ Module compiles without errors
- ✅ All unit tests pass
- ⚠️ **CRITICAL**: Must successfully decrypt real encrypted PDFs
- ⚠️ **CRITICAL**: Authentication must work with test passwords
- ⚠️ **CRITICAL**: Decrypted data must be usable by other modules

## PROJECT BLOCKER ALERT

**IF THIS MODULE FAILS TO DECRYPT REAL PDFs:**
- The entire project cannot process encrypted PDFs
- Invisible data extraction will be incomplete
- Alternative strategies (FFI or external tools) must be implemented
- This is the primary technical risk of the Rust implementation

## Alternative Implementation Strategies

**If Pure Rust approach fails, implement Strategy B or C:**

### Strategy B Implementation Guide
```rust
// FFI bindings to OpenSSL
extern "C" {
    fn openssl_decrypt_pdf(data: *const u8, len: usize, password: *const c_char) -> *mut u8;
}

pub fn decrypt_with_openssl(data: &[u8], password: &str) -> Result<Vec<u8>, DecryptionError> {
    // Safe FFI implementation
}
```

### Strategy C Implementation Guide  
```rust
use std::process::Command;

pub fn decrypt_with_qpdf(input_path: &str, output_path: &str, password: &str) -> Result<(), DecryptionError> {
    let output = Command::new("qpdf")
        .arg("--password")
        .arg(password)
        .arg("--decrypt")
        .arg(input_path)
        .arg(output_path)
        .output()?;
    
    if output.status.success() {
        Ok(())
    } else {
        Err(DecryptionError::ExternalToolFailed)
    }
}
```

## Next Module
**ONLY proceed to Module 10: EncryptionHandler if this module successfully decrypts test PDFs.**

If decryption fails, you must either:
1. Fix the Pure Rust implementation
2. Implement Strategy B (FFI) 
3. Implement Strategy C (External tools)

**The project cannot continue without working decryption.**