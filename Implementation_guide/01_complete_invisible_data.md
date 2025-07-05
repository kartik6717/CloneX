# Module 1: CompleteInvisibleData - Core Data Structures

## Overview
The `CompleteInvisibleData` struct is the central data structure that holds ALL invisible PDF elements in pure binary format. This module defines the single source of truth for invisible data storage with zero format conversion.

## Module Requirements
- **Dependencies**: None (pure Rust standard library)
- **Compilation**: Must compile independently
- **Purpose**: Store ALL invisible PDF data in exact binary format
- **Critical Rule**: NO TEXT CONVERSION - everything stored as `Vec<u8>`

## File Structure
```
src/
├── lib.rs
└── complete_invisible_data.rs
```

## Implementation Guide

### Step 1: Create Module File
Create `src/complete_invisible_data.rs`:

```rust
//! CompleteInvisibleData Module
//! 
//! Stores ALL invisible PDF elements in exact binary format.
//! NO format conversion allowed - pure binary preservation.

use std::collections::HashMap;

/// Complete storage for ALL invisible PDF data in binary format
#[derive(Debug, Clone, Default)]
pub struct CompleteInvisibleData {
    // Cryptographic Invisible Data (BINARY ONLY)
    /// Document ID array [ID1, ID2] in exact binary format
    pub document_id: Vec<u8>,
    /// MD5 hash of normalized PDF structure (binary, not hex string)
    pub md5_hash_raw: Vec<u8>,
    /// SHA-256 hash of complete document (binary, not hex string)
    pub sha256_hash_raw: Vec<u8>,
    
    // Structural Invisible Data (BINARY ONLY)
    /// XRef table with exact object positions and generation numbers
    pub xref_table_binary: Vec<u8>,
    /// Cross-reference streams with compressed binary data
    pub xref_streams: Vec<Vec<u8>>,
    /// Trailer dictionary with file IDs and root references
    pub trailer_binary: Vec<u8>,
    /// Object ordering and numbering sequence
    pub object_ordering: Vec<u32>,
    /// Linearization hints and optimization data
    pub linearization_data: Vec<u8>,
    /// Free object chains and deleted object markers
    pub free_object_chains: Vec<u8>,
    
    // Content Invisible Data (BINARY ONLY)
    /// Whitespace patterns (spaces, tabs, line breaks) with exact positioning
    pub whitespace_patterns: Vec<u8>,
    /// Comment blocks starting with % containing hidden data
    pub comment_blocks: Vec<Vec<u8>>,
    /// Stream padding bytes and null byte patterns
    pub stream_padding: Vec<u8>,
    /// Font metrics and character spacing data
    pub font_metrics: Vec<u8>,
    /// Color profiles and ICC data
    pub color_profiles: Vec<u8>,
    /// Compression fingerprints and deflate parameters
    pub compression_fingerprints: Vec<u8>,
    
    // Metadata Invisible Data (BINARY ONLY)
    /// XMP packets in complete XML format (binary)
    pub xmp_metadata_binary: Vec<u8>,
    /// Info dictionary with all timestamps and producer chains
    pub info_dictionary: Vec<u8>,
    /// Custom properties and non-standard metadata fields
    pub custom_properties: HashMap<String, Vec<u8>>,
    /// Usage rights and digital rights management data
    pub usage_rights: Vec<u8>,
    /// Form data and hidden form fields
    pub form_data: Vec<u8>,
    /// Annotation data and markup elements
    pub annotation_data: Vec<u8>,
    
    // Binary Invisible Data (BINARY ONLY)
    /// Stream filter chains with exact decode parameters
    pub stream_filters: Vec<u8>,
    /// JBIG2 image segments and compression data
    pub jbig2_data: Vec<u8>,
    /// JPEG2000 markers and advanced image fingerprints
    pub jpeg2000_markers: Vec<u8>,
    /// Embedded font data and font file structures
    pub embedded_fonts: Vec<u8>,
    /// JavaScript code and event handlers
    pub javascript_code: Vec<u8>,
    /// Digital signature cryptographic data
    pub digital_signatures: Vec<u8>,
    
    // Object-level Data (BINARY ONLY)
    /// All PDF objects with their complete binary data
    pub object_streams: HashMap<i32, Vec<u8>>,
    /// Object-level checksums and stream hashes
    pub object_checksums: HashMap<i32, Vec<u8>>,
    /// Encryption dictionary parameters
    pub encryption_params: Vec<u8>,
    /// Security handler signatures
    pub security_signatures: Vec<u8>,
}

impl CompleteInvisibleData {
    /// Create new empty invisible data container
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Check if container is empty (no invisible data)
    pub fn is_empty(&self) -> bool {
        self.document_id.is_empty() &&
        self.md5_hash_raw.is_empty() &&
        self.sha256_hash_raw.is_empty() &&
        self.xref_table_binary.is_empty() &&
        self.object_streams.is_empty()
    }
    
    /// Get total size of all stored invisible data in bytes
    pub fn total_size(&self) -> usize {
        let mut size = 0;
        
        // Cryptographic data
        size += self.document_id.len();
        size += self.md5_hash_raw.len();
        size += self.sha256_hash_raw.len();
        
        // Structural data
        size += self.xref_table_binary.len();
        size += self.xref_streams.iter().map(|v| v.len()).sum::<usize>();
        size += self.trailer_binary.len();
        size += self.object_ordering.len() * 4; // u32 = 4 bytes
        size += self.linearization_data.len();
        size += self.free_object_chains.len();
        
        // Content data
        size += self.whitespace_patterns.len();
        size += self.comment_blocks.iter().map(|v| v.len()).sum::<usize>();
        size += self.stream_padding.len();
        size += self.font_metrics.len();
        size += self.color_profiles.len();
        size += self.compression_fingerprints.len();
        
        // Metadata
        size += self.xmp_metadata_binary.len();
        size += self.info_dictionary.len();
        size += self.custom_properties.values().map(|v| v.len()).sum::<usize>();
        size += self.usage_rights.len();
        size += self.form_data.len();
        size += self.annotation_data.len();
        
        // Binary data
        size += self.stream_filters.len();
        size += self.jbig2_data.len();
        size += self.jpeg2000_markers.len();
        size += self.embedded_fonts.len();
        size += self.javascript_code.len();
        size += self.digital_signatures.len();
        
        // Object data
        size += self.object_streams.values().map(|v| v.len()).sum::<usize>();
        size += self.object_checksums.values().map(|v| v.len()).sum::<usize>();
        size += self.encryption_params.len();
        size += self.security_signatures.len();
        
        size
    }
    
    /// Clear all stored invisible data
    pub fn clear(&mut self) {
        *self = Self::new();
    }
    
    /// Validate that all hash data is exactly 16 bytes (MD5) or 32 bytes (SHA-256)
    pub fn validate_hashes(&self) -> Result<(), String> {
        if !self.md5_hash_raw.is_empty() && self.md5_hash_raw.len() != 16 {
            return Err(format!("MD5 hash must be exactly 16 bytes, got {}", self.md5_hash_raw.len()));
        }
        
        if !self.sha256_hash_raw.is_empty() && self.sha256_hash_raw.len() != 32 {
            return Err(format!("SHA-256 hash must be exactly 32 bytes, got {}", self.sha256_hash_raw.len()));
        }
        
        Ok(())
    }
}

/// Error types for invisible data operations
#[derive(Debug, Clone)]
pub enum InvisibleDataError {
    InvalidHashSize(String),
    CorruptedData(String),
    MissingRequiredField(String),
}

impl std::fmt::Display for InvisibleDataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvisibleDataError::InvalidHashSize(msg) => write!(f, "Invalid hash size: {}", msg),
            InvisibleDataError::CorruptedData(msg) => write!(f, "Corrupted data: {}", msg),
            InvisibleDataError::MissingRequiredField(msg) => write!(f, "Missing required field: {}", msg),
        }
    }
}

impl std::error::Error for InvisibleDataError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_invisible_data() {
        let data = CompleteInvisibleData::new();
        assert!(data.is_empty());
        assert_eq!(data.total_size(), 0);
    }

    #[test]
    fn test_document_id_storage() {
        let mut data = CompleteInvisibleData::new();
        let test_id = vec![0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x08];
        data.document_id = test_id.clone();
        
        assert_eq!(data.document_id, test_id);
        assert!(!data.is_empty());
        assert_eq!(data.total_size(), 8);
    }

    #[test]
    fn test_hash_validation() {
        let mut data = CompleteInvisibleData::new();
        
        // Valid MD5 (16 bytes)
        data.md5_hash_raw = vec![0u8; 16];
        assert!(data.validate_hashes().is_ok());
        
        // Valid SHA-256 (32 bytes)
        data.sha256_hash_raw = vec![0u8; 32];
        assert!(data.validate_hashes().is_ok());
        
        // Invalid MD5 size
        data.md5_hash_raw = vec![0u8; 15];
        assert!(data.validate_hashes().is_err());
        
        // Invalid SHA-256 size
        data.sha256_hash_raw = vec![0u8; 31];
        assert!(data.validate_hashes().is_err());
    }

    #[test]
    fn test_clear_data() {
        let mut data = CompleteInvisibleData::new();
        data.document_id = vec![1, 2, 3, 4];
        data.md5_hash_raw = vec![0u8; 16];
        
        assert!(!data.is_empty());
        
        data.clear();
        assert!(data.is_empty());
        assert_eq!(data.total_size(), 0);
    }

    #[test]
    fn test_object_streams() {
        let mut data = CompleteInvisibleData::new();
        
        data.object_streams.insert(1, vec![0x01, 0x02, 0x03]);
        data.object_streams.insert(2, vec![0x04, 0x05]);
        
        assert_eq!(data.object_streams.len(), 2);
        assert_eq!(data.object_streams[&1], vec![0x01, 0x02, 0x03]);
        assert_eq!(data.object_streams[&2], vec![0x04, 0x05]);
    }

    #[test]
    fn test_custom_properties() {
        let mut data = CompleteInvisibleData::new();
        
        data.custom_properties.insert("Producer".to_string(), b"Test Producer".to_vec());
        data.custom_properties.insert("Creator".to_string(), b"Test Creator".to_vec());
        
        assert_eq!(data.custom_properties.len(), 2);
        assert_eq!(data.custom_properties["Producer"], b"Test Producer");
        assert_eq!(data.custom_properties["Creator"], b"Test Creator");
    }
}
```

### Step 2: Update lib.rs
Add to `src/lib.rs`:

```rust
//! PDF Invisible Data Cloning System
//! 
//! A Rust implementation for 100% invisible data cloning between PDFs
//! with complete anti-forensic capabilities.

pub mod complete_invisible_data;

pub use complete_invisible_data::{CompleteInvisibleData, InvisibleDataError};
```

### Step 3: Validation Commands
```bash
cargo check --lib
cargo build --lib
cargo test complete_invisible_data
```

## Success Criteria
- ✅ Module compiles without errors
- ✅ All unit tests pass
- ✅ No external dependencies beyond std
- ✅ All data stored in binary format (Vec<u8>)
- ✅ Zero format conversion in entire module
- ✅ Complete invisible data coverage

## Critical Requirements Met
1. **Binary Preservation**: Everything stored as `Vec<u8>` - no text conversion
2. **Independent Compilation**: No dependencies on other custom modules
3. **Complete Coverage**: All invisible PDF elements represented
4. **Memory Efficient**: Uses HashMap for object-level data
5. **Validation**: Hash size validation ensures data integrity
6. **Testing**: Comprehensive unit tests for all functionality

## Next Module
After this module compiles and tests pass, proceed to Module 2: ConsoleSupressor.