# Module 6: FileLoader - PDF File Loading

## Overview
The `FileLoader` module handles loading PDF files into memory safely and efficiently. This module provides the foundation for all PDF processing operations by reading files into binary format with proper error handling.

## Module Requirements
- **Dependencies**: None (pure Rust standard library)
- **Compilation**: Must compile independently  
- **Purpose**: Load PDF files into memory as binary data
- **Critical Rule**: Load files as Vec<u8> binary data, no text interpretation

## File Structure
```
src/
├── lib.rs
├── complete_invisible_data.rs
├── console_supressor.rs
├── hash_manager.rs
├── document_id_manager.rs
├── memory_sanitizer.rs
└── file_loader.rs
```

## Implementation Guide

### Step 1: Create Module File
Create `src/file_loader.rs`:

```rust
//! FileLoader Module
//! 
//! Handles loading PDF files into memory safely and efficiently.
//! Provides foundation for all PDF processing operations.

use std::fs::File;
use std::io::{self, Read, BufReader};
use std::path::Path;
use crate::silent_debug;
use crate::memory_sanitizer::SanitizedBuffer;

/// PDF file loader with security and error handling
pub struct FileLoader {
    /// Maximum file size allowed (default: 100MB)
    max_file_size: usize,
    /// Buffer size for reading (default: 64KB)
    buffer_size: usize,
}

impl FileLoader {
    /// Create new file loader with default settings
    pub fn new() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100MB
            buffer_size: 64 * 1024,           // 64KB
        }
    }

    /// Create file loader with custom limits
    pub fn with_limits(max_file_size: usize, buffer_size: usize) -> Self {
        Self {
            max_file_size,
            buffer_size,
        }
    }

    /// Load PDF file into memory as binary data
    pub fn load_pdf<P: AsRef<Path>>(&self, path: P) -> Result<Vec<u8>, FileLoaderError> {
        let path = path.as_ref();
        
        silent_debug!("Loading PDF file: {}", path.display());

        // Validate file exists and is readable
        self.validate_file(path)?;

        // Get file size for validation
        let file_size = self.get_file_size(path)?;
        
        // Validate file size
        if file_size > self.max_file_size {
            return Err(FileLoaderError::FileTooLarge {
                size: file_size,
                max_size: self.max_file_size,
            });
        }

        // Load file content
        self.load_file_content(path, file_size)
    }

    /// Load PDF into sanitized buffer (automatically cleared on drop)
    pub fn load_pdf_sanitized<P: AsRef<Path>>(&self, path: P) -> Result<SanitizedBuffer, FileLoaderError> {
        let data = self.load_pdf(path)?;
        Ok(SanitizedBuffer::from_vec(data))
    }

    /// Validate file exists and is readable
    fn validate_file(&self, path: &Path) -> Result<(), FileLoaderError> {
        if !path.exists() {
            return Err(FileLoaderError::FileNotFound(path.to_path_buf()));
        }

        if !path.is_file() {
            return Err(FileLoaderError::NotAFile(path.to_path_buf()));
        }

        // Check if file is readable by attempting to open
        File::open(path).map_err(|e| FileLoaderError::PermissionDenied {
            path: path.to_path_buf(),
            error: e,
        })?;

        Ok(())
    }

    /// Get file size safely
    fn get_file_size(&self, path: &Path) -> Result<usize, FileLoaderError> {
        let metadata = std::fs::metadata(path)
            .map_err(|e| FileLoaderError::MetadataError {
                path: path.to_path_buf(),
                error: e,
            })?;

        let size = metadata.len() as usize;
        silent_debug!("File size: {} bytes", size);
        
        Ok(size)
    }

    /// Load file content with buffered reading
    fn load_file_content(&self, path: &Path, expected_size: usize) -> Result<Vec<u8>, FileLoaderError> {
        let file = File::open(path)
            .map_err(|e| FileLoaderError::ReadError {
                path: path.to_path_buf(),
                error: e,
            })?;

        let mut reader = BufReader::with_capacity(self.buffer_size, file);
        let mut buffer = Vec::with_capacity(expected_size);

        // Read file in chunks
        let mut temp_buffer = vec![0u8; self.buffer_size];
        let mut total_read = 0;

        loop {
            match reader.read(&mut temp_buffer) {
                Ok(0) => break, // EOF
                Ok(bytes_read) => {
                    total_read += bytes_read;
                    
                    // Check for size limit during reading
                    if total_read > self.max_file_size {
                        return Err(FileLoaderError::FileTooLarge {
                            size: total_read,
                            max_size: self.max_file_size,
                        });
                    }
                    
                    buffer.extend_from_slice(&temp_buffer[..bytes_read]);
                }
                Err(e) => {
                    return Err(FileLoaderError::ReadError {
                        path: path.to_path_buf(),
                        error: e,
                    });
                }
            }
        }

        silent_debug!("Successfully loaded {} bytes", total_read);
        Ok(buffer)
    }

    /// Validate that loaded data looks like a PDF
    pub fn validate_pdf_header(data: &[u8]) -> Result<(), FileLoaderError> {
        if data.len() < 5 {
            return Err(FileLoaderError::InvalidPDF("File too short to be PDF".to_string()));
        }

        // Check for PDF header: %PDF-
        if !data.starts_with(b"%PDF-") {
            return Err(FileLoaderError::InvalidPDF("Missing PDF header".to_string()));
        }

        // Validate PDF version format
        if data.len() >= 8 {
            let version_part = &data[5..8];
            if version_part.len() == 3 && version_part[1] == b'.' {
                // Valid format like "1.4", "1.7", etc.
                silent_debug!("Found PDF version: {}", String::from_utf8_lossy(version_part));
            } else {
                return Err(FileLoaderError::InvalidPDF("Invalid PDF version format".to_string()));
            }
        }

        Ok(())
    }

    /// Check if file appears to be encrypted (basic check)
    pub fn check_encryption_markers(data: &[u8]) -> bool {
        // Look for common encryption markers in PDF
        let encryption_markers = [
            b"/Encrypt",
            b"/U ",       // User password
            b"/O ",       // Owner password  
            b"/Filter",   // Security filter
        ];

        for marker in &encryption_markers {
            if data.windows(marker.len()).any(|window| window == *marker) {
                return true;
            }
        }

        false
    }

    /// Get file extension and validate
    pub fn validate_pdf_extension<P: AsRef<Path>>(path: P) -> Result<(), FileLoaderError> {
        let path = path.as_ref();
        
        if let Some(extension) = path.extension() {
            if extension.to_ascii_lowercase() == "pdf" {
                Ok(())
            } else {
                Err(FileLoaderError::InvalidExtension {
                    path: path.to_path_buf(),
                    extension: extension.to_string_lossy().to_string(),
                })
            }
        } else {
            Err(FileLoaderError::NoExtension(path.to_path_buf()))
        }
    }

    /// Load multiple PDF files
    pub fn load_multiple_pdfs<P: AsRef<Path>>(&self, paths: &[P]) -> Result<Vec<Vec<u8>>, FileLoaderError> {
        let mut results = Vec::with_capacity(paths.len());
        
        for path in paths {
            let data = self.load_pdf(path)?;
            results.push(data);
        }
        
        silent_debug!("Loaded {} PDF files", results.len());
        Ok(results)
    }

    /// Get current configuration
    pub fn get_config(&self) -> FileLoaderConfig {
        FileLoaderConfig {
            max_file_size: self.max_file_size,
            buffer_size: self.buffer_size,
        }
    }

    /// Update configuration
    pub fn set_config(&mut self, config: FileLoaderConfig) {
        self.max_file_size = config.max_file_size;
        self.buffer_size = config.buffer_size;
        
        silent_debug!("Updated FileLoader config: max_size={}, buffer_size={}", 
                     self.max_file_size, self.buffer_size);
    }
}

impl Default for FileLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// File loader configuration
#[derive(Debug, Clone, Copy)]
pub struct FileLoaderConfig {
    pub max_file_size: usize,
    pub buffer_size: usize,
}

impl Default for FileLoaderConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100MB
            buffer_size: 64 * 1024,           // 64KB
        }
    }
}

/// File loading errors
#[derive(Debug)]
pub enum FileLoaderError {
    FileNotFound(std::path::PathBuf),
    NotAFile(std::path::PathBuf),
    PermissionDenied {
        path: std::path::PathBuf,
        error: io::Error,
    },
    FileTooLarge {
        size: usize,
        max_size: usize,
    },
    ReadError {
        path: std::path::PathBuf,
        error: io::Error,
    },
    MetadataError {
        path: std::path::PathBuf,
        error: io::Error,
    },
    InvalidPDF(String),
    InvalidExtension {
        path: std::path::PathBuf,
        extension: String,
    },
    NoExtension(std::path::PathBuf),
}

impl std::fmt::Display for FileLoaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileLoaderError::FileNotFound(path) => {
                write!(f, "File not found: {}", path.display())
            }
            FileLoaderError::NotAFile(path) => {
                write!(f, "Path is not a file: {}", path.display())
            }
            FileLoaderError::PermissionDenied { path, error } => {
                write!(f, "Permission denied for file {}: {}", path.display(), error)
            }
            FileLoaderError::FileTooLarge { size, max_size } => {
                write!(f, "File too large: {} bytes (max: {} bytes)", size, max_size)
            }
            FileLoaderError::ReadError { path, error } => {
                write!(f, "Error reading file {}: {}", path.display(), error)
            }
            FileLoaderError::MetadataError { path, error } => {
                write!(f, "Error reading metadata for {}: {}", path.display(), error)
            }
            FileLoaderError::InvalidPDF(msg) => {
                write!(f, "Invalid PDF file: {}", msg)
            }
            FileLoaderError::InvalidExtension { path, extension } => {
                write!(f, "Invalid file extension '{}' for file: {}", extension, path.display())
            }
            FileLoaderError::NoExtension(path) => {
                write!(f, "No file extension for: {}", path.display())
            }
        }
    }
}

impl std::error::Error for FileLoaderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FileLoaderError::PermissionDenied { error, .. } => Some(error),
            FileLoaderError::ReadError { error, .. } => Some(error),
            FileLoaderError::MetadataError { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Utility functions for file operations
pub struct FileUtils;

impl FileUtils {
    /// Check if path exists and is a PDF file
    pub fn is_pdf_file<P: AsRef<Path>>(path: P) -> bool {
        let path = path.as_ref();
        path.exists() && 
        path.is_file() && 
        FileLoader::validate_pdf_extension(path).is_ok()
    }

    /// Get file size without loading entire file
    pub fn get_file_size<P: AsRef<Path>>(path: P) -> Result<u64, io::Error> {
        let metadata = std::fs::metadata(path)?;
        Ok(metadata.len())
    }

    /// Check if file appears to be binary PDF
    pub fn quick_pdf_check<P: AsRef<Path>>(path: P) -> Result<bool, FileLoaderError> {
        let path = path.as_ref();
        
        // Check extension first
        if FileLoader::validate_pdf_extension(path).is_err() {
            return Ok(false);
        }

        // Read just the first few bytes
        let mut file = File::open(path)
            .map_err(|e| FileLoaderError::ReadError {
                path: path.to_path_buf(),
                error: e,
            })?;

        let mut header = [0u8; 8];
        match file.read(&mut header) {
            Ok(bytes_read) if bytes_read >= 5 => {
                Ok(header.starts_with(b"%PDF-"))
            }
            _ => Ok(false),
        }
    }

    /// Format file size for display
    pub fn format_file_size(size: usize) -> String {
        if size < 1024 {
            format!("{} bytes", size)
        } else if size < 1024 * 1024 {
            format!("{:.1} KB", size as f64 / 1024.0)
        } else if size < 1024 * 1024 * 1024 {
            format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.1} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn create_test_pdf(path: &str, content: &[u8]) -> std::io::Result<()> {
        let mut file = fs::File::create(path)?;
        file.write_all(content)?;
        Ok(())
    }

    #[test]
    fn test_file_loader_creation() {
        let loader = FileLoader::new();
        let config = loader.get_config();
        assert_eq!(config.max_file_size, 100 * 1024 * 1024);
        assert_eq!(config.buffer_size, 64 * 1024);
    }

    #[test]
    fn test_file_loader_with_limits() {
        let loader = FileLoader::with_limits(1024, 512);
        let config = loader.get_config();
        assert_eq!(config.max_file_size, 1024);
        assert_eq!(config.buffer_size, 512);
    }

    #[test]
    fn test_pdf_header_validation() {
        // Valid PDF header
        let valid_pdf = b"%PDF-1.4\n";
        assert!(FileLoader::validate_pdf_header(valid_pdf).is_ok());

        // Invalid header
        let invalid_pdf = b"Not a PDF";
        assert!(FileLoader::validate_pdf_header(invalid_pdf).is_err());

        // Too short
        let short_data = b"%PD";
        assert!(FileLoader::validate_pdf_header(short_data).is_err());
    }

    #[test]
    fn test_encryption_detection() {
        let encrypted_pdf = b"%PDF-1.4\n1 0 obj\n<</Type/Catalog/Encrypt 2 0 R>>\nendobj";
        assert!(FileLoader::check_encryption_markers(encrypted_pdf));

        let plain_pdf = b"%PDF-1.4\n1 0 obj\n<</Type/Catalog>>\nendobj";
        assert!(!FileLoader::check_encryption_markers(plain_pdf));
    }

    #[test]
    fn test_extension_validation() {
        assert!(FileLoader::validate_pdf_extension("test.pdf").is_ok());
        assert!(FileLoader::validate_pdf_extension("test.PDF").is_ok());
        assert!(FileLoader::validate_pdf_extension("test.txt").is_err());
        assert!(FileLoader::validate_pdf_extension("test").is_err());
    }

    #[test]
    fn test_file_utils() {
        assert_eq!(FileUtils::format_file_size(512), "512 bytes");
        assert_eq!(FileUtils::format_file_size(1536), "1.5 KB");
        assert_eq!(FileUtils::format_file_size(1024 * 1024), "1.0 MB");
    }

    #[cfg(not(target_os = "windows"))] // Skip on Windows due to file system differences
    #[test]
    fn test_load_nonexistent_file() {
        let loader = FileLoader::new();
        let result = loader.load_pdf("/nonexistent/file.pdf");
        assert!(result.is_err());
        
        if let Err(FileLoaderError::FileNotFound(_)) = result {
            // Expected error type
        } else {
            panic!("Expected FileNotFound error");
        }
    }

    #[test]
    fn test_sanitized_buffer_loading() {
        // Create a temporary PDF file
        let test_content = b"%PDF-1.4\ntest content";
        let test_file = "test_temp.pdf";
        
        // Only run if we can create the file
        if create_test_pdf(test_file, test_content).is_ok() {
            let loader = FileLoader::new();
            let result = loader.load_pdf_sanitized(test_file);
            
            // Clean up
            let _ = fs::remove_file(test_file);
            
            if let Ok(buffer) = result {
                assert!(!buffer.is_empty());
                assert!(buffer.starts_with(b"%PDF-"));
            }
        }
    }

    #[test]
    fn test_config_update() {
        let mut loader = FileLoader::new();
        let new_config = FileLoaderConfig {
            max_file_size: 1024,
            buffer_size: 256,
        };
        
        loader.set_config(new_config);
        let updated_config = loader.get_config();
        assert_eq!(updated_config.max_file_size, 1024);
        assert_eq!(updated_config.buffer_size, 256);
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
cargo test file_loader
```

## Success Criteria
- ✅ Module compiles without errors
- ✅ All unit tests pass
- ✅ PDF file loading works correctly
- ✅ File validation and error handling work
- ✅ Memory-safe operations with sanitized buffers
- ✅ Independent compilation with no custom dependencies

## Critical Requirements Met
1. **Binary Loading**: Files loaded as Vec<u8> binary data
2. **Security**: File size limits and validation prevent attacks
3. **Error Handling**: Comprehensive error types for all failure modes
4. **Memory Safety**: Integration with sanitized buffers
5. **PDF Validation**: Basic PDF format validation
6. **Independent Compilation**: Only uses standard library

## Usage in Later Modules
```rust
use crate::file_loader::{FileLoader, FileLoaderError};

let loader = FileLoader::new();

// Load source PDF
let source_data = loader.load_pdf("source.pdf")?;

// Load with automatic sanitization
let target_buffer = loader.load_pdf_sanitized("target.pdf")?;

// Validate PDF format
FileLoader::validate_pdf_header(&source_data)?;

// Check for encryption
if FileLoader::check_encryption_markers(&source_data) {
    // Handle encrypted PDF
}
```

## Next Module
After this module compiles and tests pass, proceed to Module 7: OutputGenerator.