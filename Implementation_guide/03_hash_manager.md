# Module 3: HashManager - Hash Operations

## Overview
The `HashManager` module handles MD5 and SHA-256 hash operations for PDF documents. This module maintains hash data in pure binary format and provides hash calculation, comparison, and manipulation functions critical for invisible data fidelity.

## Module Requirements
- **Dependencies**: `md5` and `sha2` crates (external dependencies)
- **Compilation**: Must compile independently
- **Purpose**: Handle all hash operations in binary format
- **Critical Rule**: Store hashes as binary Vec<u8>, never as hex strings

## File Structure
```
src/
├── lib.rs
├── complete_invisible_data.rs
├── console_supressor.rs
└── hash_manager.rs
```

## Implementation Guide

### Step 1: Add Dependencies to Cargo.toml
Create or update `Cargo.toml`:

```toml
[package]
name = "pdf_invisible_cloning"
version = "0.1.0"
edition = "2021"

[dependencies]
md5 = "0.7"
sha2 = "0.10"

[dev-dependencies]
# Add any test-specific dependencies here
```

### Step 2: Create Module File
Create `src/hash_manager.rs`:

```rust
//! HashManager Module
//! 
//! Handles MD5 and SHA-256 hash operations for PDF documents.
//! Maintains all hash data in pure binary format for exact fidelity.

use md5::{Md5, Digest as Md5Digest};
use sha2::{Sha256, Digest as Sha256Digest};
use crate::silent_debug;

/// Hash manager for PDF document hashes
#[derive(Debug, Clone)]
pub struct HashManager {
    /// Current MD5 hash in binary format (16 bytes)
    current_md5: Vec<u8>,
    /// Current SHA-256 hash in binary format (32 bytes)
    current_sha256: Vec<u8>,
}

impl HashManager {
    /// Create new hash manager
    pub fn new() -> Self {
        Self {
            current_md5: Vec::new(),
            current_sha256: Vec::new(),
        }
    }

    /// Calculate MD5 hash of data and store in binary format
    pub fn calculate_md5(&mut self, data: &[u8]) -> &[u8] {
        let mut hasher = Md5::new();
        hasher.update(data);
        self.current_md5 = hasher.finalize().to_vec();
        
        silent_debug!("Calculated MD5 hash: {} bytes", self.current_md5.len());
        &self.current_md5
    }

    /// Calculate SHA-256 hash of data and store in binary format
    pub fn calculate_sha256(&mut self, data: &[u8]) -> &[u8] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        self.current_sha256 = hasher.finalize().to_vec();
        
        silent_debug!("Calculated SHA-256 hash: {} bytes", self.current_sha256.len());
        &self.current_sha256
    }

    /// Calculate both MD5 and SHA-256 hashes
    pub fn calculate_both_hashes(&mut self, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let md5 = self.calculate_md5(data).to_vec();
        let sha256 = self.calculate_sha256(data).to_vec();
        (md5, sha256)
    }

    /// Get current MD5 hash in binary format
    pub fn get_md5_binary(&self) -> &[u8] {
        &self.current_md5
    }

    /// Get current SHA-256 hash in binary format
    pub fn get_sha256_binary(&self) -> &[u8] {
        &self.current_sha256
    }

    /// Set MD5 hash from binary data (for injection from source)
    pub fn set_md5_binary(&mut self, hash: Vec<u8>) -> Result<(), HashError> {
        if hash.len() != 16 {
            return Err(HashError::InvalidHashSize(format!(
                "MD5 hash must be exactly 16 bytes, got {}", hash.len()
            )));
        }
        self.current_md5 = hash;
        Ok(())
    }

    /// Set SHA-256 hash from binary data (for injection from source)
    pub fn set_sha256_binary(&mut self, hash: Vec<u8>) -> Result<(), HashError> {
        if hash.len() != 32 {
            return Err(HashError::InvalidHashSize(format!(
                "SHA-256 hash must be exactly 32 bytes, got {}", hash.len()
            )));
        }
        self.current_sha256 = hash;
        Ok(())
    }

    /// Compare two MD5 hashes in binary format
    pub fn compare_md5(&self, other_hash: &[u8]) -> bool {
        if other_hash.len() != 16 {
            return false;
        }
        self.current_md5 == other_hash
    }

    /// Compare two SHA-256 hashes in binary format
    pub fn compare_sha256(&self, other_hash: &[u8]) -> bool {
        if other_hash.len() != 32 {
            return false;
        }
        self.current_sha256 == other_hash
    }

    /// Verify data matches stored MD5 hash
    pub fn verify_md5(&self, data: &[u8]) -> bool {
        if self.current_md5.is_empty() {
            return false;
        }
        
        let mut hasher = Md5::new();
        hasher.update(data);
        let calculated = hasher.finalize().to_vec();
        
        calculated == self.current_md5
    }

    /// Verify data matches stored SHA-256 hash
    pub fn verify_sha256(&self, data: &[u8]) -> bool {
        if self.current_sha256.is_empty() {
            return false;
        }
        
        let mut hasher = Sha256::new();
        hasher.update(data);
        let calculated = hasher.finalize().to_vec();
        
        calculated == self.current_sha256
    }

    /// Clear all stored hashes
    pub fn clear(&mut self) {
        self.current_md5.clear();
        self.current_sha256.clear();
    }

    /// Check if any hashes are stored
    pub fn has_hashes(&self) -> bool {
        !self.current_md5.is_empty() || !self.current_sha256.is_empty()
    }

    /// Convert MD5 hash to hex string for debugging (NEVER for storage)
    #[cfg(debug_assertions)]
    pub fn md5_to_hex_debug(&self) -> String {
        if self.current_md5.is_empty() {
            return String::from("(empty)");
        }
        hex::encode(&self.current_md5)
    }

    /// Convert SHA-256 hash to hex string for debugging (NEVER for storage)
    #[cfg(debug_assertions)]
    pub fn sha256_to_hex_debug(&self) -> String {
        if self.current_sha256.is_empty() {
            return String::from("(empty)");
        }
        hex::encode(&self.current_sha256)
    }
}

impl Default for HashManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash-related errors
#[derive(Debug, Clone)]
pub enum HashError {
    InvalidHashSize(String),
    HashMismatch(String),
    EmptyData,
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashError::InvalidHashSize(msg) => write!(f, "Invalid hash size: {}", msg),
            HashError::HashMismatch(msg) => write!(f, "Hash mismatch: {}", msg),
            HashError::EmptyData => write!(f, "Cannot hash empty data"),
        }
    }
}

impl std::error::Error for HashError {}

/// Utility functions for hash operations
pub struct HashUtils;

impl HashUtils {
    /// Calculate MD5 of data without storing
    pub fn quick_md5(data: &[u8]) -> Vec<u8> {
        let mut hasher = Md5::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Calculate SHA-256 of data without storing
    pub fn quick_sha256(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Validate hash sizes
    pub fn validate_hash_sizes(md5: &[u8], sha256: &[u8]) -> Result<(), HashError> {
        if !md5.is_empty() && md5.len() != 16 {
            return Err(HashError::InvalidHashSize(format!(
                "MD5 must be 16 bytes, got {}", md5.len()
            )));
        }
        
        if !sha256.is_empty() && sha256.len() != 32 {
            return Err(HashError::InvalidHashSize(format!(
                "SHA-256 must be 32 bytes, got {}", sha256.len()
            )));
        }
        
        Ok(())
    }

    /// Secure compare two hash values (constant time)
    pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut result = 0u8;
        for (byte_a, byte_b) in a.iter().zip(b.iter()) {
            result |= byte_a ^ byte_b;
        }
        
        result == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_manager_creation() {
        let manager = HashManager::new();
        assert!(!manager.has_hashes());
        assert!(manager.get_md5_binary().is_empty());
        assert!(manager.get_sha256_binary().is_empty());
    }

    #[test]
    fn test_md5_calculation() {
        let mut manager = HashManager::new();
        let test_data = b"Hello, World!";
        
        let hash = manager.calculate_md5(test_data);
        assert_eq!(hash.len(), 16);
        assert!(manager.has_hashes());
        
        // Verify the hash is correct by recalculating
        assert!(manager.verify_md5(test_data));
    }

    #[test]
    fn test_sha256_calculation() {
        let mut manager = HashManager::new();
        let test_data = b"Hello, World!";
        
        let hash = manager.calculate_sha256(test_data);
        assert_eq!(hash.len(), 32);
        assert!(manager.has_hashes());
        
        // Verify the hash is correct by recalculating
        assert!(manager.verify_sha256(test_data));
    }

    #[test]
    fn test_both_hashes() {
        let mut manager = HashManager::new();
        let test_data = b"Test data for both hashes";
        
        let (md5, sha256) = manager.calculate_both_hashes(test_data);
        assert_eq!(md5.len(), 16);
        assert_eq!(sha256.len(), 32);
        
        assert!(manager.verify_md5(test_data));
        assert!(manager.verify_sha256(test_data));
    }

    #[test]
    fn test_hash_setting() {
        let mut manager = HashManager::new();
        
        // Valid MD5 (16 bytes)
        let md5_hash = vec![0u8; 16];
        assert!(manager.set_md5_binary(md5_hash.clone()).is_ok());
        assert_eq!(manager.get_md5_binary(), md5_hash);
        
        // Valid SHA-256 (32 bytes)
        let sha256_hash = vec![1u8; 32];
        assert!(manager.set_sha256_binary(sha256_hash.clone()).is_ok());
        assert_eq!(manager.get_sha256_binary(), sha256_hash);
        
        // Invalid sizes
        assert!(manager.set_md5_binary(vec![0u8; 15]).is_err());
        assert!(manager.set_sha256_binary(vec![0u8; 31]).is_err());
    }

    #[test]
    fn test_hash_comparison() {
        let mut manager = HashManager::new();
        let test_data = b"Comparison test data";
        
        manager.calculate_both_hashes(test_data);
        
        let md5_copy = manager.get_md5_binary().to_vec();
        let sha256_copy = manager.get_sha256_binary().to_vec();
        
        assert!(manager.compare_md5(&md5_copy));
        assert!(manager.compare_sha256(&sha256_copy));
        
        // Different hashes should not match
        let different_hash = vec![0u8; 16];
        assert!(!manager.compare_md5(&different_hash));
    }

    #[test]
    fn test_hash_verification() {
        let mut manager = HashManager::new();
        let test_data = b"Verification test data";
        let wrong_data = b"Wrong data";
        
        manager.calculate_both_hashes(test_data);
        
        // Correct data should verify
        assert!(manager.verify_md5(test_data));
        assert!(manager.verify_sha256(test_data));
        
        // Wrong data should not verify
        assert!(!manager.verify_md5(wrong_data));
        assert!(!manager.verify_sha256(wrong_data));
    }

    #[test]
    fn test_clear_hashes() {
        let mut manager = HashManager::new();
        let test_data = b"Clear test data";
        
        manager.calculate_both_hashes(test_data);
        assert!(manager.has_hashes());
        
        manager.clear();
        assert!(!manager.has_hashes());
        assert!(manager.get_md5_binary().is_empty());
        assert!(manager.get_sha256_binary().is_empty());
    }

    #[test]
    fn test_quick_hash_utils() {
        let test_data = b"Quick hash test";
        
        let md5 = HashUtils::quick_md5(test_data);
        let sha256 = HashUtils::quick_sha256(test_data);
        
        assert_eq!(md5.len(), 16);
        assert_eq!(sha256.len(), 32);
        
        // Should match hash manager results
        let mut manager = HashManager::new();
        manager.calculate_both_hashes(test_data);
        
        assert_eq!(md5, manager.get_md5_binary());
        assert_eq!(sha256, manager.get_sha256_binary());
    }

    #[test]
    fn test_hash_validation() {
        let valid_md5 = vec![0u8; 16];
        let valid_sha256 = vec![0u8; 32];
        let invalid_md5 = vec![0u8; 15];
        let invalid_sha256 = vec![0u8; 31];
        
        assert!(HashUtils::validate_hash_sizes(&valid_md5, &valid_sha256).is_ok());
        assert!(HashUtils::validate_hash_sizes(&[], &[]).is_ok()); // Empty is valid
        assert!(HashUtils::validate_hash_sizes(&invalid_md5, &valid_sha256).is_err());
        assert!(HashUtils::validate_hash_sizes(&valid_md5, &invalid_sha256).is_err());
    }

    #[test]
    fn test_secure_compare() {
        let hash1 = vec![1, 2, 3, 4, 5];
        let hash2 = vec![1, 2, 3, 4, 5];
        let hash3 = vec![1, 2, 3, 4, 6];
        let hash4 = vec![1, 2, 3, 4]; // Different length
        
        assert!(HashUtils::secure_compare(&hash1, &hash2));
        assert!(!HashUtils::secure_compare(&hash1, &hash3));
        assert!(!HashUtils::secure_compare(&hash1, &hash4));
    }
}
```

### Step 3: Update Cargo.toml for hex dependency (debug only)
Update `Cargo.toml`:

```toml
[package]
name = "pdf_invisible_cloning"
version = "0.1.0"
edition = "2021"

[dependencies]
md5 = "0.7"
sha2 = "0.10"

[dev-dependencies]
hex = "0.4"  # Only for debug hex conversion in tests
```

### Step 4: Update lib.rs
Update `src/lib.rs`:

```rust
//! PDF Invisible Data Cloning System
//! 
//! A Rust implementation for 100% invisible data cloning between PDFs
//! with complete anti-forensic capabilities.

pub mod complete_invisible_data;
pub mod console_supressor;
pub mod hash_manager;

pub use complete_invisible_data::{CompleteInvisibleData, InvisibleDataError};
pub use console_supressor::{
    enable_silent_mode, disable_silent_mode, is_silent_mode,
    silent_operation, OutputCapture, EnvironmentSuppressor,
    initialize_suppression, NullWriter
};
pub use hash_manager::{HashManager, HashError, HashUtils};

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

### Step 5: Validation Commands
```bash
cargo check --lib
cargo build --lib
cargo test hash_manager
```

## Success Criteria
- ✅ Module compiles without errors
- ✅ All unit tests pass
- ✅ MD5 and SHA-256 calculations work correctly
- ✅ Hash storage in binary format only
- ✅ Hash validation and comparison functions work
- ✅ Error handling for invalid hash sizes

## Critical Requirements Met
1. **Binary Storage**: All hashes stored as Vec<u8>, never as hex strings
2. **Exact Sizes**: MD5 = 16 bytes, SHA-256 = 32 bytes validation
3. **Independent Compilation**: Only depends on external crypto crates
4. **Secure Operations**: Constant-time comparison for security
5. **Complete Coverage**: Both MD5 and SHA-256 support
6. **Error Handling**: Proper validation and error reporting

## Usage in Later Modules
```rust
use crate::hash_manager::{HashManager, HashUtils};

let mut hash_manager = HashManager::new();

// Calculate hashes of PDF data
let (md5, sha256) = hash_manager.calculate_both_hashes(&pdf_data);

// Set hashes from source PDF (for cloning)
hash_manager.set_md5_binary(source_md5)?;
hash_manager.set_sha256_binary(source_sha256)?;

// Verify target matches source
if !hash_manager.verify_md5(&target_data) {
    // Hash mismatch - invisible data not properly cloned
}
```

## Next Module
After this module compiles and tests pass, proceed to Module 4: DocumentIDManager.