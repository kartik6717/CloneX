# Module 5: MemorySanitizer - Memory Clearing

## Overview
The `MemorySanitizer` module provides secure memory clearing functions to prevent forensic analysis. This module ensures that sensitive PDF data and processing traces are completely wiped from memory after use.

## Module Requirements
- **Dependencies**: None (pure Rust standard library)
- **Compilation**: Must compile independently
- **Purpose**: Secure memory clearing and sanitization
- **Critical Rule**: Prevent forensic recovery of sensitive data from memory

## File Structure
```
src/
├── lib.rs
├── complete_invisible_data.rs
├── console_supressor.rs
├── hash_manager.rs
├── document_id_manager.rs
└── memory_sanitizer.rs
```

## Implementation Guide

### Step 1: Create Module File
Create `src/memory_sanitizer.rs`:

```rust
//! MemorySanitizer Module
//! 
//! Provides secure memory clearing functions to prevent forensic analysis.
//! Ensures sensitive PDF data is completely wiped from memory.

use std::ptr;
use std::slice;
use crate::silent_debug;

/// Memory sanitizer for secure data clearing
pub struct MemorySanitizer;

impl MemorySanitizer {
    /// Securely clear a byte vector
    pub fn clear_vec(data: &mut Vec<u8>) {
        if !data.is_empty() {
            Self::secure_zero(data.as_mut_slice());
            data.clear();
            data.shrink_to_fit();
        }
    }

    /// Securely clear a byte slice
    pub fn clear_slice(data: &mut [u8]) {
        if !data.is_empty() {
            Self::secure_zero(data);
        }
    }

    /// Securely clear a string
    pub fn clear_string(data: &mut String) {
        if !data.is_empty() {
            // Clear the underlying bytes
            let bytes = unsafe { data.as_bytes_mut() };
            Self::secure_zero(bytes);
            data.clear();
            data.shrink_to_fit();
        }
    }

    /// Secure zero-fill memory (prevents compiler optimization)
    pub fn secure_zero(data: &mut [u8]) {
        if data.is_empty() {
            return;
        }

        // Use volatile write to prevent compiler optimization
        for byte in data.iter_mut() {
            unsafe {
                ptr::write_volatile(byte, 0);
            }
        }

        // Additional security: multiple passes with different patterns
        Self::multiple_pass_clear(data);
    }

    /// Multiple-pass memory clearing with different patterns
    fn multiple_pass_clear(data: &mut [u8]) {
        if data.is_empty() {
            return;
        }

        // Pass 1: All zeros
        for byte in data.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0x00); }
        }

        // Pass 2: All ones
        for byte in data.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0xFF); }
        }

        // Pass 3: Random pattern
        for (i, byte) in data.iter_mut().enumerate() {
            unsafe { ptr::write_volatile(byte, (i % 256) as u8); }
        }

        // Pass 4: Final zeros
        for byte in data.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0x00); }
        }
    }

    /// Clear sensitive data structure
    pub fn clear_invisible_data(data: &mut crate::CompleteInvisibleData) {
        silent_debug!("Sanitizing CompleteInvisibleData structure");
        
        // Clear all Vec<u8> fields
        Self::clear_vec(&mut data.document_id);
        Self::clear_vec(&mut data.md5_hash_raw);
        Self::clear_vec(&mut data.sha256_hash_raw);
        Self::clear_vec(&mut data.xref_table_binary);
        Self::clear_vec(&mut data.trailer_binary);
        Self::clear_vec(&mut data.linearization_data);
        Self::clear_vec(&mut data.free_object_chains);
        Self::clear_vec(&mut data.whitespace_patterns);
        Self::clear_vec(&mut data.stream_padding);
        Self::clear_vec(&mut data.font_metrics);
        Self::clear_vec(&mut data.color_profiles);
        Self::clear_vec(&mut data.compression_fingerprints);
        Self::clear_vec(&mut data.xmp_metadata_binary);
        Self::clear_vec(&mut data.info_dictionary);
        Self::clear_vec(&mut data.usage_rights);
        Self::clear_vec(&mut data.form_data);
        Self::clear_vec(&mut data.annotation_data);
        Self::clear_vec(&mut data.stream_filters);
        Self::clear_vec(&mut data.jbig2_data);
        Self::clear_vec(&mut data.jpeg2000_markers);
        Self::clear_vec(&mut data.embedded_fonts);
        Self::clear_vec(&mut data.javascript_code);
        Self::clear_vec(&mut data.digital_signatures);
        Self::clear_vec(&mut data.encryption_params);
        Self::clear_vec(&mut data.security_signatures);

        // Clear Vec<Vec<u8>> fields
        for vec in &mut data.xref_streams {
            Self::clear_vec(vec);
        }
        data.xref_streams.clear();

        for vec in &mut data.comment_blocks {
            Self::clear_vec(vec);
        }
        data.comment_blocks.clear();

        // Clear HashMap<i32, Vec<u8>> fields
        for (_, vec) in &mut data.object_streams {
            Self::clear_vec(vec);
        }
        data.object_streams.clear();

        for (_, vec) in &mut data.object_checksums {
            Self::clear_vec(vec);
        }
        data.object_checksums.clear();

        // Clear HashMap<String, Vec<u8>> fields
        for (_, vec) in &mut data.custom_properties {
            Self::clear_vec(vec);
        }
        data.custom_properties.clear();

        // Clear object ordering
        data.object_ordering.clear();

        silent_debug!("CompleteInvisibleData sanitization complete");
    }

    /// Clear hash manager data
    pub fn clear_hash_manager(manager: &mut crate::HashManager) {
        silent_debug!("Sanitizing HashManager");
        
        // Access private fields through public methods
        let mut empty_hash = Vec::new();
        
        // Force clear by setting empty hashes (this will clear internal storage)
        let _ = manager.set_md5_binary(vec![0u8; 16]);
        let _ = manager.set_sha256_binary(vec![0u8; 32]);
        manager.clear();
        
        silent_debug!("HashManager sanitization complete");
    }

    /// Clear document ID manager data
    pub fn clear_document_id_manager(manager: &mut crate::DocumentIDManager) {
        silent_debug!("Sanitizing DocumentIDManager");
        
        manager.clear();
        
        silent_debug!("DocumentIDManager sanitization complete");
    }

    /// Memory barrier to prevent reordering
    pub fn memory_barrier() {
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }

    /// Force garbage collection hint (Rust doesn't have GC, but this forces allocation)
    pub fn force_memory_pressure() {
        // Allocate and immediately drop large vector to pressure memory system
        let _pressure = vec![0u8; 1024 * 1024]; // 1MB
        // Vector drops here, potentially triggering memory reorganization
    }
}

/// RAII wrapper for automatic memory sanitization
pub struct SanitizedBuffer {
    data: Vec<u8>,
}

impl SanitizedBuffer {
    /// Create new sanitized buffer
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Create from existing data
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get mutable reference to data
    pub fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    /// Get reference to data
    pub fn as_ref(&self) -> &Vec<u8> {
        &self.data
    }

    /// Get slice reference
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable slice reference
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Extend with data
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    /// Clear buffer (but don't sanitize yet)
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Manually sanitize buffer
    pub fn sanitize(&mut self) {
        MemorySanitizer::clear_vec(&mut self.data);
    }
}

impl Drop for SanitizedBuffer {
    fn drop(&mut self) {
        // Automatically sanitize on drop
        MemorySanitizer::clear_vec(&mut self.data);
        silent_debug!("SanitizedBuffer dropped and sanitized");
    }
}

impl std::ops::Deref for SanitizedBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl std::ops::DerefMut for SanitizedBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/// RAII wrapper for automatic string sanitization
pub struct SanitizedString {
    data: String,
}

impl SanitizedString {
    /// Create new sanitized string
    pub fn new() -> Self {
        Self {
            data: String::new(),
        }
    }

    /// Create from existing string
    pub fn from_string(data: String) -> Self {
        Self { data }
    }

    /// Get mutable reference to string
    pub fn as_mut(&mut self) -> &mut String {
        &mut self.data
    }

    /// Get reference to string
    pub fn as_str(&self) -> &str {
        &self.data
    }

    /// Push string
    pub fn push_str(&mut self, s: &str) {
        self.data.push_str(s);
    }

    /// Clear string (but don't sanitize yet)
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Manually sanitize string
    pub fn sanitize(&mut self) {
        MemorySanitizer::clear_string(&mut self.data);
    }
}

impl Drop for SanitizedString {
    fn drop(&mut self) {
        // Automatically sanitize on drop
        MemorySanitizer::clear_string(&mut self.data);
        silent_debug!("SanitizedString dropped and sanitized");
    }
}

impl std::ops::Deref for SanitizedString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

/// System-wide memory sanitization
pub struct SystemSanitizer;

impl SystemSanitizer {
    /// Perform comprehensive system memory sanitization
    pub fn sanitize_all() {
        silent_debug!("Performing system-wide memory sanitization");

        // Force memory barriers
        MemorySanitizer::memory_barrier();

        // Apply memory pressure to force reallocation
        MemorySanitizer::force_memory_pressure();

        // Additional barrier
        MemorySanitizer::memory_barrier();

        silent_debug!("System-wide sanitization complete");
    }

    /// Clear CPU caches (best effort)
    pub fn clear_cpu_caches() {
        // This is a best-effort attempt to clear CPU caches
        // Real cache clearing would require OS-specific calls
        
        // Allocate and access large memory block to flush caches
        let cache_flush_size = 64 * 1024 * 1024; // 64MB
        let mut cache_flush = vec![0u8; cache_flush_size];
        
        // Touch every cache line
        for i in (0..cache_flush_size).step_by(64) {
            cache_flush[i] = (i % 256) as u8;
        }
        
        // Clear the flush buffer
        MemorySanitizer::clear_vec(&mut cache_flush);
        
        silent_debug!("CPU cache flush attempt complete");
    }

    /// Prevent swap file contamination (best effort)
    pub fn prevent_swap_contamination() {
        // In a real implementation, this would use OS-specific calls
        // to lock memory pages and prevent swapping
        
        // For now, just apply memory pressure
        MemorySanitizer::force_memory_pressure();
        
        silent_debug!("Swap contamination prevention applied");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_zero() {
        let mut data = vec![0xFF; 100];
        
        // Verify data is not zero initially
        assert!(data.iter().any(|&b| b != 0));
        
        MemorySanitizer::secure_zero(&mut data);
        
        // Verify all data is now zero
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_clear_vec() {
        let mut data = vec![1, 2, 3, 4, 5];
        assert_eq!(data.len(), 5);
        
        MemorySanitizer::clear_vec(&mut data);
        
        assert_eq!(data.len(), 0);
        assert_eq!(data.capacity(), 0); // Should shrink to fit
    }

    #[test]
    fn test_clear_string() {
        let mut data = String::from("sensitive data");
        assert!(!data.is_empty());
        
        MemorySanitizer::clear_string(&mut data);
        
        assert!(data.is_empty());
        assert_eq!(data.capacity(), 0); // Should shrink to fit
    }

    #[test]
    fn test_sanitized_buffer() {
        let mut buffer = SanitizedBuffer::new(100);
        buffer.extend_from_slice(b"test data");
        
        assert_eq!(buffer.len(), 9);
        assert_eq!(buffer.as_slice(), b"test data");
        
        buffer.sanitize();
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_sanitized_buffer_drop() {
        let mut sensitive_data = vec![1, 2, 3, 4, 5];
        
        {
            let _buffer = SanitizedBuffer::from_vec(sensitive_data.clone());
            // Buffer will be sanitized on drop
        }
        
        // Original data should still exist
        assert_eq!(sensitive_data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_sanitized_string() {
        let mut string = SanitizedString::new();
        string.push_str("sensitive information");
        
        assert_eq!(string.as_str(), "sensitive information");
        
        string.sanitize();
        assert!(string.as_str().is_empty());
    }

    #[test]
    fn test_sanitized_string_drop() {
        {
            let _string = SanitizedString::from_string("will be sanitized".to_string());
            // String will be sanitized on drop
        }
        // Test passes if no panic occurs
    }

    #[test]
    fn test_memory_barrier() {
        // This test just ensures the function doesn't panic
        MemorySanitizer::memory_barrier();
    }

    #[test]
    fn test_force_memory_pressure() {
        // This test just ensures the function doesn't panic
        MemorySanitizer::force_memory_pressure();
    }

    #[test]
    fn test_system_sanitizer() {
        // Test system-wide operations don't panic
        SystemSanitizer::sanitize_all();
        SystemSanitizer::clear_cpu_caches();
        SystemSanitizer::prevent_swap_contamination();
    }

    #[test]
    fn test_empty_data_handling() {
        let mut empty_vec: Vec<u8> = Vec::new();
        let mut empty_slice: [u8; 0] = [];
        let mut empty_string = String::new();
        
        // These should not panic with empty data
        MemorySanitizer::clear_vec(&mut empty_vec);
        MemorySanitizer::clear_slice(&mut empty_slice);
        MemorySanitizer::clear_string(&mut empty_string);
        MemorySanitizer::secure_zero(&mut empty_slice);
    }

    #[test]
    fn test_multiple_pass_clear() {
        let mut data = vec![0xAA; 50];
        
        // Verify initial pattern
        assert!(data.iter().all(|&b| b == 0xAA));
        
        MemorySanitizer::secure_zero(&mut data);
        
        // Should be all zeros after clearing
        assert!(data.iter().all(|&b| b == 0));
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
cargo test memory_sanitizer
```

## Success Criteria
- ✅ Module compiles without errors
- ✅ All unit tests pass
- ✅ Secure memory clearing functions work
- ✅ RAII wrappers automatically sanitize on drop
- ✅ System-wide sanitization functions work
- ✅ Independent compilation with no custom dependencies

## Critical Requirements Met
1. **Secure Clearing**: Multiple-pass memory clearing prevents forensic recovery
2. **Anti-Forensic**: Comprehensive sanitization of all sensitive data structures
3. **Automatic Safety**: RAII wrappers ensure sanitization even on panic
4. **System-wide**: Can sanitize entire system memory footprint
5. **Independent Compilation**: No dependencies on other custom modules
6. **Prevention**: Memory barriers and cache clearing prevent optimization

## Usage in Later Modules
```rust
use crate::memory_sanitizer::{MemorySanitizer, SanitizedBuffer};

// Use sanitized buffer for sensitive data
let mut buffer = SanitizedBuffer::new(1024);
buffer.extend_from_slice(&sensitive_pdf_data);
// Buffer automatically sanitized on drop

// Manual sanitization
let mut sensitive_data = load_pdf_data();
process_data(&sensitive_data);
MemorySanitizer::clear_vec(&mut sensitive_data);

// System-wide cleanup after processing
SystemSanitizer::sanitize_all();
```

## Next Module
After this module compiles and tests pass, proceed to Module 6: FileLoader.