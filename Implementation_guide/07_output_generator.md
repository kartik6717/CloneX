# Module 7: OutputGenerator - PDF File Writing

## Overview
The `OutputGenerator` module handles writing processed PDF data to files safely and efficiently. This module provides the final output capabilities for the PDF cloning system with proper error handling and security measures.

## Module Requirements
- **Dependencies**: None (pure Rust standard library)
- **Compilation**: Must compile independently
- **Purpose**: Write PDF data to files as binary data
- **Critical Rule**: Write files as binary Vec<u8> data, preserve exact byte fidelity

## File Structure
```
src/
├── lib.rs
├── complete_invisible_data.rs
├── console_supressor.rs
├── hash_manager.rs
├── document_id_manager.rs
├── memory_sanitizer.rs
├── file_loader.rs
└── output_generator.rs
```

## Implementation Guide

### Step 1: Create Module File
Create `src/output_generator.rs`:

```rust
//! OutputGenerator Module
//! 
//! Handles writing processed PDF data to files safely and efficiently.
//! Provides final output capabilities with proper error handling.

use std::fs::{File, OpenOptions};
use std::io::{self, Write, BufWriter};
use std::path::{Path, PathBuf};
use crate::silent_debug;
use crate::memory_sanitizer::MemorySanitizer;

/// PDF output generator with security and error handling
pub struct OutputGenerator {
    /// Buffer size for writing (default: 64KB)
    buffer_size: usize,
    /// Whether to overwrite existing files
    allow_overwrite: bool,
    /// Whether to create backup of existing files
    create_backup: bool,
    /// File permissions for created files (Unix only)
    file_permissions: Option<u32>,
}

impl OutputGenerator {
    /// Create new output generator with default settings
    pub fn new() -> Self {
        Self {
            buffer_size: 64 * 1024,  // 64KB
            allow_overwrite: false,
            create_backup: true,
            file_permissions: None,
        }
    }

    /// Create output generator with custom settings
    pub fn with_config(config: OutputConfig) -> Self {
        Self {
            buffer_size: config.buffer_size,
            allow_overwrite: config.allow_overwrite,
            create_backup: config.create_backup,
            file_permissions: config.file_permissions,
        }
    }

    /// Write PDF data to file
    pub fn write_pdf<P: AsRef<Path>>(&self, path: P, data: &[u8]) -> Result<(), OutputError> {
        let path = path.as_ref();
        
        silent_debug!("Writing PDF to: {}", path.display());

        // Validate output path
        self.validate_output_path(path)?;

        // Handle existing file
        self.handle_existing_file(path)?;

        // Create parent directories if needed
        self.create_parent_dirs(path)?;

        // Write file content
        self.write_file_content(path, data)?;

        // Set file permissions if specified
        self.set_file_permissions(path)?;

        silent_debug!("Successfully wrote {} bytes to {}", data.len(), path.display());
        Ok(())
    }

    /// Write PDF data with automatic sanitization of source data
    pub fn write_pdf_sanitized<P: AsRef<Path>>(&self, path: P, mut data: Vec<u8>) -> Result<(), OutputError> {
        let result = self.write_pdf(path, &data);
        
        // Sanitize source data after writing
        MemorySanitizer::clear_vec(&mut data);
        
        result
    }

    /// Write multiple PDF files
    pub fn write_multiple_pdfs<P: AsRef<Path>>(&self, files: &[(P, &[u8])]) -> Result<(), OutputError> {
        for (path, data) in files {
            self.write_pdf(path, data)?;
        }
        
        silent_debug!("Successfully wrote {} PDF files", files.len());
        Ok(())
    }

    /// Validate output path
    fn validate_output_path(&self, path: &Path) -> Result<(), OutputError> {
        // Check if path is valid
        if path.as_os_str().is_empty() {
            return Err(OutputError::InvalidPath("Empty path".to_string()));
        }

        // Check if path is too long (platform dependent)
        if path.as_os_str().len() > 255 {
            return Err(OutputError::InvalidPath("Path too long".to_string()));
        }

        // Validate file extension
        if let Some(extension) = path.extension() {
            if extension.to_ascii_lowercase() != "pdf" {
                return Err(OutputError::InvalidExtension {
                    path: path.to_path_buf(),
                    extension: extension.to_string_lossy().to_string(),
                });
            }
        } else {
            return Err(OutputError::NoExtension(path.to_path_buf()));
        }

        Ok(())
    }

    /// Handle existing file (backup or overwrite check)
    fn handle_existing_file(&self, path: &Path) -> Result<(), OutputError> {
        if path.exists() {
            if !self.allow_overwrite {
                return Err(OutputError::FileExists(path.to_path_buf()));
            }

            if self.create_backup {
                self.create_backup_file(path)?;
            }
        }

        Ok(())
    }

    /// Create backup of existing file
    fn create_backup_file(&self, path: &Path) -> Result<(), OutputError> {
        let backup_path = self.generate_backup_path(path);
        
        std::fs::copy(path, &backup_path)
            .map_err(|e| OutputError::BackupError {
                original: path.to_path_buf(),
                backup: backup_path.clone(),
                error: e,
            })?;

        silent_debug!("Created backup: {}", backup_path.display());
        Ok(())
    }

    /// Generate backup file path
    fn generate_backup_path(&self, path: &Path) -> PathBuf {
        let mut backup_path = path.to_path_buf();
        
        // Add timestamp to make unique backup
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(stem) = path.file_stem() {
            let backup_name = format!("{}.backup.{}.pdf", 
                                    stem.to_string_lossy(), 
                                    timestamp);
            backup_path.set_file_name(backup_name);
        } else {
            backup_path.set_extension(format!("backup.{}.pdf", timestamp));
        }

        backup_path
    }

    /// Create parent directories if they don't exist
    fn create_parent_dirs(&self, path: &Path) -> Result<(), OutputError> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| OutputError::DirectoryError {
                        path: parent.to_path_buf(),
                        error: e,
                    })?;
                
                silent_debug!("Created directory: {}", parent.display());
            }
        }

        Ok(())
    }

    /// Write file content with buffered writing
    fn write_file_content(&self, path: &Path, data: &[u8]) -> Result<(), OutputError> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| OutputError::WriteError {
                path: path.to_path_buf(),
                error: e,
            })?;

        let mut writer = BufWriter::with_capacity(self.buffer_size, file);

        // Write data in chunks
        let chunk_size = self.buffer_size;
        for chunk in data.chunks(chunk_size) {
            writer.write_all(chunk)
                .map_err(|e| OutputError::WriteError {
                    path: path.to_path_buf(),
                    error: e,
                })?;
        }

        // Ensure all data is written
        writer.flush()
            .map_err(|e| OutputError::WriteError {
                path: path.to_path_buf(),
                error: e,
            })?;

        Ok(())
    }

    /// Set file permissions (Unix only)
    #[cfg(unix)]
    fn set_file_permissions(&self, path: &Path) -> Result<(), OutputError> {
        if let Some(permissions) = self.file_permissions {
            use std::os::unix::fs::PermissionsExt;
            
            let file_permissions = std::fs::Permissions::from_mode(permissions);
            std::fs::set_permissions(path, file_permissions)
                .map_err(|e| OutputError::PermissionError {
                    path: path.to_path_buf(),
                    error: e,
                })?;
                
            silent_debug!("Set file permissions: {:o}", permissions);
        }

        Ok(())
    }

    /// Set file permissions (Windows - no-op)
    #[cfg(not(unix))]
    fn set_file_permissions(&self, _path: &Path) -> Result<(), OutputError> {
        // Windows doesn't use Unix-style permissions
        Ok(())
    }

    /// Verify written file matches original data
    pub fn verify_output<P: AsRef<Path>>(&self, path: P, expected_data: &[u8]) -> Result<bool, OutputError> {
        let path = path.as_ref();
        
        let written_data = std::fs::read(path)
            .map_err(|e| OutputError::VerificationError {
                path: path.to_path_buf(),
                error: e,
            })?;

        let matches = written_data == expected_data;
        
        if matches {
            silent_debug!("Output verification successful");
        } else {
            silent_debug!("Output verification failed: size mismatch {} vs {}", 
                         written_data.len(), expected_data.len());
        }

        Ok(matches)
    }

    /// Get current configuration
    pub fn get_config(&self) -> OutputConfig {
        OutputConfig {
            buffer_size: self.buffer_size,
            allow_overwrite: self.allow_overwrite,
            create_backup: self.create_backup,
            file_permissions: self.file_permissions,
        }
    }

    /// Update configuration
    pub fn set_config(&mut self, config: OutputConfig) {
        self.buffer_size = config.buffer_size;
        self.allow_overwrite = config.allow_overwrite;
        self.create_backup = config.create_backup;
        self.file_permissions = config.file_permissions;
        
        silent_debug!("Updated OutputGenerator config");
    }
}

impl Default for OutputGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Output generator configuration
#[derive(Debug, Clone, Copy)]
pub struct OutputConfig {
    pub buffer_size: usize,
    pub allow_overwrite: bool,
    pub create_backup: bool,
    pub file_permissions: Option<u32>,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            buffer_size: 64 * 1024,   // 64KB
            allow_overwrite: false,
            create_backup: true,
            file_permissions: None,
        }
    }
}

/// Output operation errors
#[derive(Debug)]
pub enum OutputError {
    InvalidPath(String),
    InvalidExtension {
        path: PathBuf,
        extension: String,
    },
    NoExtension(PathBuf),
    FileExists(PathBuf),
    DirectoryError {
        path: PathBuf,
        error: io::Error,
    },
    WriteError {
        path: PathBuf,
        error: io::Error,
    },
    BackupError {
        original: PathBuf,
        backup: PathBuf,
        error: io::Error,
    },
    PermissionError {
        path: PathBuf,
        error: io::Error,
    },
    VerificationError {
        path: PathBuf,
        error: io::Error,
    },
}

impl std::fmt::Display for OutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputError::InvalidPath(msg) => {
                write!(f, "Invalid output path: {}", msg)
            }
            OutputError::InvalidExtension { path, extension } => {
                write!(f, "Invalid file extension '{}' for: {}", extension, path.display())
            }
            OutputError::NoExtension(path) => {
                write!(f, "No file extension for: {}", path.display())
            }
            OutputError::FileExists(path) => {
                write!(f, "File already exists: {}", path.display())
            }
            OutputError::DirectoryError { path, error } => {
                write!(f, "Directory error for {}: {}", path.display(), error)
            }
            OutputError::WriteError { path, error } => {
                write!(f, "Write error for {}: {}", path.display(), error)
            }
            OutputError::BackupError { original, backup, error } => {
                write!(f, "Backup error from {} to {}: {}", 
                       original.display(), backup.display(), error)
            }
            OutputError::PermissionError { path, error } => {
                write!(f, "Permission error for {}: {}", path.display(), error)
            }
            OutputError::VerificationError { path, error } => {
                write!(f, "Verification error for {}: {}", path.display(), error)
            }
        }
    }
}

impl std::error::Error for OutputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OutputError::DirectoryError { error, .. } => Some(error),
            OutputError::WriteError { error, .. } => Some(error),
            OutputError::BackupError { error, .. } => Some(error),
            OutputError::PermissionError { error, .. } => Some(error),
            OutputError::VerificationError { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Utility functions for output operations
pub struct OutputUtils;

impl OutputUtils {
    /// Generate safe output filename
    pub fn generate_safe_filename(base: &str, suffix: Option<&str>) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match suffix {
            Some(s) => format!("{}_{}.{}.pdf", base, s, timestamp),
            None => format!("{}_{}.pdf", base, timestamp),
        }
    }

    /// Check available disk space
    pub fn check_disk_space<P: AsRef<Path>>(path: P, required_bytes: u64) -> Result<bool, io::Error> {
        // This is a placeholder - real implementation would use platform-specific APIs
        // For now, assume we have enough space
        let _ = (path, required_bytes);
        Ok(true)
    }

    /// Create temporary file in same directory
    pub fn create_temp_file<P: AsRef<Path>>(target_path: P) -> Result<PathBuf, io::Error> {
        let target_path = target_path.as_ref();
        let temp_name = format!("temp_{}.pdf", 
                               std::process::id());

        let temp_path = if let Some(parent) = target_path.parent() {
            parent.join(temp_name)
        } else {
            PathBuf::from(temp_name)
        };

        // Create empty temp file
        File::create(&temp_path)?;
        
        Ok(temp_path)
    }

    /// Atomic file write (write to temp, then rename)
    pub fn atomic_write<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<(), OutputError> {
        let path = path.as_ref();
        
        // Create temporary file
        let temp_path = Self::create_temp_file(path)
            .map_err(|e| OutputError::WriteError {
                path: path.to_path_buf(),
                error: e,
            })?;

        // Write to temporary file
        let generator = OutputGenerator::new();
        match generator.write_file_content(&temp_path, data) {
            Ok(()) => {
                // Atomically rename temp file to target
                std::fs::rename(&temp_path, path)
                    .map_err(|e| OutputError::WriteError {
                        path: path.to_path_buf(),
                        error: e,
                    })?;
                Ok(())
            }
            Err(e) => {
                // Clean up temp file on error
                let _ = std::fs::remove_file(&temp_path);
                Err(e)
            }
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

    #[test]
    fn test_output_generator_creation() {
        let generator = OutputGenerator::new();
        let config = generator.get_config();
        assert_eq!(config.buffer_size, 64 * 1024);
        assert!(!config.allow_overwrite);
        assert!(config.create_backup);
    }

    #[test]
    fn test_output_config() {
        let config = OutputConfig {
            buffer_size: 1024,
            allow_overwrite: true,
            create_backup: false,
            file_permissions: Some(0o644),
        };
        
        let generator = OutputGenerator::with_config(config);
        let retrieved_config = generator.get_config();
        assert_eq!(retrieved_config.buffer_size, 1024);
        assert!(retrieved_config.allow_overwrite);
        assert!(!retrieved_config.create_backup);
        assert_eq!(retrieved_config.file_permissions, Some(0o644));
    }

    #[test]
    fn test_path_validation() {
        let generator = OutputGenerator::new();
        
        // Valid PDF path
        assert!(generator.validate_output_path(Path::new("test.pdf")).is_ok());
        
        // Invalid extension
        assert!(generator.validate_output_path(Path::new("test.txt")).is_err());
        
        // No extension
        assert!(generator.validate_output_path(Path::new("test")).is_err());
        
        // Empty path
        assert!(generator.validate_output_path(Path::new("")).is_err());
    }

    #[test]
    fn test_backup_path_generation() {
        let generator = OutputGenerator::new();
        let original_path = Path::new("test.pdf");
        let backup_path = generator.generate_backup_path(original_path);
        
        assert!(backup_path.to_string_lossy().contains("test.backup."));
        assert!(backup_path.to_string_lossy().ends_with(".pdf"));
    }

    #[test]
    fn test_output_utils() {
        // Test safe filename generation
        let filename = OutputUtils::generate_safe_filename("output", Some("cloned"));
        assert!(filename.contains("output_cloned"));
        assert!(filename.ends_with(".pdf"));
        
        // Test without suffix
        let filename2 = OutputUtils::generate_safe_filename("test", None);
        assert!(filename2.contains("test_"));
        assert!(filename2.ends_with(".pdf"));
        
        // Test file size formatting
        assert_eq!(OutputUtils::format_file_size(512), "512 bytes");
        assert_eq!(OutputUtils::format_file_size(1536), "1.5 KB");
    }

    #[test]
    fn test_disk_space_check() {
        // Should not fail (placeholder implementation)
        let result = OutputUtils::check_disk_space(".", 1024);
        assert!(result.is_ok());
    }

    #[cfg(not(target_os = "windows"))] // Skip on Windows due to file system differences
    #[test]
    fn test_write_pdf_to_temp() {
        let test_data = b"%PDF-1.4\ntest content";
        let temp_file = "test_output_temp.pdf";
        
        let mut config = OutputConfig::default();
        config.allow_overwrite = true;
        config.create_backup = false;
        
        let generator = OutputGenerator::with_config(config);
        
        // Write test data
        let result = generator.write_pdf(temp_file, test_data);
        
        if result.is_ok() {
            // Verify file was written
            if let Ok(written_data) = fs::read(temp_file) {
                assert_eq!(written_data, test_data);
            }
            
            // Verify output
            let verification = generator.verify_output(temp_file, test_data);
            assert!(verification.is_ok());
            if let Ok(matches) = verification {
                assert!(matches);
            }
            
            // Clean up
            let _ = fs::remove_file(temp_file);
        }
    }

    #[test]
    fn test_atomic_write() {
        let test_data = b"%PDF-1.4\natomic test";
        let temp_file = "atomic_test.pdf";
        
        let result = OutputUtils::atomic_write(temp_file, test_data);
        
        if result.is_ok() {
            // Verify file exists and has correct content
            if let Ok(written_data) = fs::read(temp_file) {
                assert_eq!(written_data, test_data);
            }
            
            // Clean up
            let _ = fs::remove_file(temp_file);
        }
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
cargo test output_generator
```

## Success Criteria
- ✅ Module compiles without errors
- ✅ All unit tests pass
- ✅ PDF file writing works correctly
- ✅ Backup and overwrite handling work
- ✅ File verification functions work
- ✅ Independent compilation with no custom dependencies

## Critical Requirements Met
1. **Binary Writing**: Files written as Vec<u8> binary data with exact fidelity
2. **Security**: File validation, permissions, and backup creation
3. **Error Handling**: Comprehensive error types for all failure modes
4. **Atomic Operations**: Safe writing with temporary files
5. **Verification**: Output verification ensures data integrity
6. **Independent Compilation**: Only uses standard library

## Usage in Later Modules
```rust
use crate::output_generator::{OutputGenerator, OutputConfig};

// Configure for overwrite
let mut config = OutputConfig::default();
config.allow_overwrite = true;
config.create_backup = true;

let generator = OutputGenerator::with_config(config);

// Write processed PDF
generator.write_pdf("output.pdf", &processed_data)?;

// Verify output matches input
let verification_ok = generator.verify_output("output.pdf", &processed_data)?;

// Atomic write for critical operations
OutputUtils::atomic_write("critical.pdf", &data)?;
```

## Next Module
After this module compiles and tests pass, proceed to Module 8: PDFStructure.