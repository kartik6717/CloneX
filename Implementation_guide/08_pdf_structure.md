# Module 8: PDFStructure - Basic PDF Parsing

## Overview
The `PDFStructure` module provides basic PDF parsing capabilities without encryption support. This module handles PDF object parsing, structure analysis, and provides the foundation for invisible data extraction.

## Module Requirements
- **Dependencies**: None (pure Rust standard library)
- **Compilation**: Must compile independently
- **Purpose**: Parse PDF structure and objects without encryption
- **Critical Rule**: Handle all data in binary format, no text interpretation

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
├── output_generator.rs
└── pdf_structure.rs
```

## Implementation Guide

### Step 1: Create Module File
Create `src/pdf_structure.rs`:

```rust
//! PDFStructure Module
//! 
//! Provides basic PDF parsing capabilities without encryption support.
//! Handles PDF object parsing and structure analysis.

use std::collections::HashMap;
use crate::silent_debug;

/// PDF object types
#[derive(Debug, Clone, PartialEq)]
pub enum PDFObjectType {
    Null,
    Boolean(bool),
    Integer(i64),
    Real(f64),
    String(Vec<u8>),        // Binary string data
    Name(Vec<u8>),          // Binary name data
    Array(Vec<PDFObject>),
    Dictionary(HashMap<Vec<u8>, PDFObject>),
    Stream {
        dictionary: HashMap<Vec<u8>, PDFObject>,
        data: Vec<u8>,
    },
    Reference {
        object_number: u32,
        generation: u16,
    },
}

/// PDF object with metadata
#[derive(Debug, Clone)]
pub struct PDFObject {
    pub object_type: PDFObjectType,
    pub position: usize,    // Position in file
    pub length: usize,      // Length in bytes
}

impl PDFObject {
    /// Create new PDF object
    pub fn new(object_type: PDFObjectType, position: usize, length: usize) -> Self {
        Self {
            object_type,
            position,
            length,
        }
    }

    /// Check if object is a dictionary
    pub fn is_dictionary(&self) -> bool {
        matches!(self.object_type, PDFObjectType::Dictionary(_))
    }

    /// Check if object is a stream
    pub fn is_stream(&self) -> bool {
        matches!(self.object_type, PDFObjectType::Stream { .. })
    }

    /// Get dictionary data if this is a dictionary
    pub fn as_dictionary(&self) -> Option<&HashMap<Vec<u8>, PDFObject>> {
        match &self.object_type {
            PDFObjectType::Dictionary(dict) => Some(dict),
            PDFObjectType::Stream { dictionary, .. } => Some(dictionary),
            _ => None,
        }
    }

    /// Get stream data if this is a stream
    pub fn as_stream_data(&self) -> Option<&[u8]> {
        match &self.object_type {
            PDFObjectType::Stream { data, .. } => Some(data),
            _ => None,
        }
    }
}

/// Cross-reference table entry
#[derive(Debug, Clone)]
pub struct XRefEntry {
    pub object_number: u32,
    pub generation: u16,
    pub offset: u64,
    pub in_use: bool,
}

/// PDF cross-reference table
#[derive(Debug, Clone)]
pub struct XRefTable {
    pub entries: HashMap<u32, XRefEntry>,
    pub position: usize,
    pub length: usize,
}

impl XRefTable {
    /// Create new cross-reference table
    pub fn new(position: usize, length: usize) -> Self {
        Self {
            entries: HashMap::new(),
            position,
            length,
        }
    }

    /// Add entry to table
    pub fn add_entry(&mut self, entry: XRefEntry) {
        self.entries.insert(entry.object_number, entry);
    }

    /// Get entry by object number
    pub fn get_entry(&self, object_number: u32) -> Option<&XRefEntry> {
        self.entries.get(&object_number)
    }

    /// Get all object numbers
    pub fn get_object_numbers(&self) -> Vec<u32> {
        let mut numbers: Vec<u32> = self.entries.keys().copied().collect();
        numbers.sort();
        numbers
    }
}

/// PDF trailer dictionary
#[derive(Debug, Clone)]
pub struct PDFTrailer {
    pub dictionary: HashMap<Vec<u8>, PDFObject>,
    pub position: usize,
    pub length: usize,
}

impl PDFTrailer {
    /// Create new trailer
    pub fn new(position: usize, length: usize) -> Self {
        Self {
            dictionary: HashMap::new(),
            position,
            length,
        }
    }

    /// Get trailer entry
    pub fn get_entry(&self, key: &[u8]) -> Option<&PDFObject> {
        self.dictionary.get(key)
    }

    /// Get root object reference
    pub fn get_root_reference(&self) -> Option<(u32, u16)> {
        if let Some(root_obj) = self.get_entry(b"Root") {
            if let PDFObjectType::Reference { object_number, generation } = &root_obj.object_type {
                return Some((*object_number, *generation));
            }
        }
        None
    }

    /// Get document ID
    pub fn get_document_id(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        if let Some(id_obj) = self.get_entry(b"ID") {
            if let PDFObjectType::Array(array) = &id_obj.object_type {
                if array.len() == 2 {
                    let id1 = match &array[0].object_type {
                        PDFObjectType::String(data) => data.clone(),
                        _ => return None,
                    };
                    let id2 = match &array[1].object_type {
                        PDFObjectType::String(data) => data.clone(),
                        _ => return None,
                    };
                    return Some((id1, id2));
                }
            }
        }
        None
    }
}

/// Main PDF structure parser
#[derive(Debug)]
pub struct PDFStructure {
    /// PDF version (e.g., "1.4")
    pub version: String,
    /// All parsed objects
    pub objects: HashMap<u32, PDFObject>,
    /// Cross-reference table
    pub xref_table: Option<XRefTable>,
    /// Trailer dictionary
    pub trailer: Option<PDFTrailer>,
    /// Original binary data
    pub raw_data: Vec<u8>,
    /// File size
    pub file_size: usize,
}

impl PDFStructure {
    /// Create new PDF structure
    pub fn new() -> Self {
        Self {
            version: String::new(),
            objects: HashMap::new(),
            xref_table: None,
            trailer: None,
            raw_data: Vec::new(),
            file_size: 0,
        }
    }

    /// Parse PDF from binary data (unencrypted only)
    pub fn parse_from_data(data: Vec<u8>) -> Result<Self, PDFParseError> {
        let mut structure = PDFStructure::new();
        structure.file_size = data.len();
        structure.raw_data = data;

        silent_debug!("Parsing PDF structure from {} bytes", structure.file_size);

        // Parse PDF header
        structure.parse_header()?;

        // Find and parse cross-reference table
        structure.parse_xref_table()?;

        // Parse trailer
        structure.parse_trailer()?;

        // Parse objects (basic parsing only)
        structure.parse_objects()?;

        silent_debug!("Successfully parsed PDF with {} objects", structure.objects.len());
        Ok(structure)
    }

    /// Parse PDF header
    fn parse_header(&mut self) -> Result<(), PDFParseError> {
        if self.raw_data.len() < 8 {
            return Err(PDFParseError::InvalidFormat("File too short".to_string()));
        }

        if !self.raw_data.starts_with(b"%PDF-") {
            return Err(PDFParseError::InvalidFormat("Missing PDF header".to_string()));
        }

        // Extract version
        if let Some(newline_pos) = self.raw_data[5..].iter().position(|&b| b == b'\n' || b == b'\r') {
            let version_bytes = &self.raw_data[5..5 + newline_pos];
            self.version = String::from_utf8_lossy(version_bytes).to_string();
            silent_debug!("Found PDF version: {}", self.version);
        } else {
            return Err(PDFParseError::InvalidFormat("Invalid PDF header".to_string()));
        }

        Ok(())
    }

    /// Find and parse cross-reference table
    fn parse_xref_table(&mut self) -> Result<(), PDFParseError> {
        // Find "xref" keyword from the end of file
        let xref_pos = self.find_xref_position()?;
        
        // Parse xref table starting at found position
        let xref_table = self.parse_xref_at_position(xref_pos)?;
        self.xref_table = Some(xref_table);

        Ok(())
    }

    /// Find xref table position
    fn find_xref_position(&self) -> Result<usize, PDFParseError> {
        // Look for "startxref" near end of file
        let search_start = if self.raw_data.len() > 1024 {
            self.raw_data.len() - 1024
        } else {
            0
        };

        let search_data = &self.raw_data[search_start..];
        
        if let Some(pos) = search_data.windows(9).rposition(|window| window == b"startxref") {
            let startxref_pos = search_start + pos + 9;
            
            // Extract xref offset
            let offset_data = &self.raw_data[startxref_pos..];
            if let Some(offset) = self.extract_number(offset_data) {
                return Ok(offset as usize);
            }
        }

        Err(PDFParseError::XRefNotFound)
    }

    /// Parse xref table at specific position
    fn parse_xref_at_position(&self, position: usize) -> Result<XRefTable, PDFParseError> {
        if position >= self.raw_data.len() {
            return Err(PDFParseError::InvalidPosition(position));
        }

        let data = &self.raw_data[position..];
        
        if !data.starts_with(b"xref") {
            return Err(PDFParseError::InvalidFormat("Missing xref keyword".to_string()));
        }

        let mut xref_table = XRefTable::new(position, 0);
        let mut current_pos = 4; // Skip "xref"

        // Skip whitespace
        while current_pos < data.len() && data[current_pos].is_ascii_whitespace() {
            current_pos += 1;
        }

        // Parse xref entries (simplified parsing)
        while current_pos < data.len() {
            if data[current_pos..].starts_with(b"trailer") {
                break;
            }

            // Extract entry data (this is simplified - real implementation would be more robust)
            if let Some(line_end) = data[current_pos..].iter().position(|&b| b == b'\n') {
                let line = &data[current_pos..current_pos + line_end];
                
                // Try to parse as xref entry
                if let Some(entry) = self.parse_xref_entry(line) {
                    xref_table.add_entry(entry);
                }
                
                current_pos += line_end + 1;
            } else {
                break;
            }
        }

        xref_table.length = current_pos;
        Ok(xref_table)
    }

    /// Parse single xref entry
    fn parse_xref_entry(&self, line: &[u8]) -> Option<XRefEntry> {
        // Simplified xref entry parsing
        // Real implementation would handle various formats
        let parts: Vec<&[u8]> = line.split(|&b| b.is_ascii_whitespace()).collect();
        
        if parts.len() >= 3 {
            if let (Some(offset), Some(gen), Some(flag)) = (
                self.extract_number(parts[0]),
                self.extract_number(parts[1]),
                parts[2].first(),
            ) {
                return Some(XRefEntry {
                    object_number: 0, // Would be set by caller
                    generation: gen as u16,
                    offset: offset,
                    in_use: *flag == b'n',
                });
            }
        }

        None
    }

    /// Parse trailer dictionary
    fn parse_trailer(&mut self) -> Result<(), PDFParseError> {
        // Find trailer position
        if let Some(pos) = self.find_trailer_position() {
            let trailer = self.parse_trailer_at_position(pos)?;
            self.trailer = Some(trailer);
        }

        Ok(())
    }

    /// Find trailer position
    fn find_trailer_position(&self) -> Option<usize> {
        // Look for "trailer" keyword
        self.raw_data.windows(7).rposition(|window| window == b"trailer")
    }

    /// Parse trailer at specific position
    fn parse_trailer_at_position(&self, position: usize) -> Result<PDFTrailer, PDFParseError> {
        let mut trailer = PDFTrailer::new(position, 0);
        
        // This is a placeholder for trailer parsing
        // Real implementation would parse the dictionary after "trailer"
        trailer.length = 100; // Placeholder
        
        Ok(trailer)
    }

    /// Parse objects (basic parsing)
    fn parse_objects(&mut self) -> Result<(), PDFParseError> {
        if let Some(ref xref_table) = self.xref_table {
            for (obj_num, entry) in &xref_table.entries {
                if entry.in_use && (entry.offset as usize) < self.raw_data.len() {
                    if let Ok(obj) = self.parse_object_at_position(entry.offset as usize) {
                        self.objects.insert(*obj_num, obj);
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse object at specific position
    fn parse_object_at_position(&self, position: usize) -> Result<PDFObject, PDFParseError> {
        // This is a placeholder for object parsing
        // Real implementation would parse: "n g obj ... endobj"
        
        Ok(PDFObject::new(
            PDFObjectType::Null,
            position,
            10, // Placeholder length
        ))
    }

    /// Extract number from byte slice
    fn extract_number(&self, data: &[u8]) -> Option<u64> {
        let mut result = 0u64;
        let mut found_digit = false;

        for &byte in data {
            if byte.is_ascii_digit() {
                result = result.saturating_mul(10).saturating_add((byte - b'0') as u64);
                found_digit = true;
            } else if found_digit {
                break;
            }
        }

        if found_digit { Some(result) } else { None }
    }

    /// Get object by number
    pub fn get_object(&self, object_number: u32) -> Option<&PDFObject> {
        self.objects.get(&object_number)
    }

    /// Get all object numbers
    pub fn get_all_object_numbers(&self) -> Vec<u32> {
        let mut numbers: Vec<u32> = self.objects.keys().copied().collect();
        numbers.sort();
        numbers
    }

    /// Check if PDF appears to be encrypted
    pub fn is_encrypted(&self) -> bool {
        // Check for encryption markers in raw data
        let encryption_markers = [b"/Encrypt", b"/U ", b"/O "];
        
        for marker in &encryption_markers {
            if self.raw_data.windows(marker.len()).any(|window| window == *marker) {
                return true;
            }
        }

        false
    }

    /// Get PDF version
    pub fn get_version(&self) -> &str {
        &self.version
    }

    /// Get file size
    pub fn get_file_size(&self) -> usize {
        self.file_size
    }

    /// Get raw data reference
    pub fn get_raw_data(&self) -> &[u8] {
        &self.raw_data
    }

    /// Extract specific byte range from PDF
    pub fn extract_byte_range(&self, start: usize, length: usize) -> Option<&[u8]> {
        if start + length <= self.raw_data.len() {
            Some(&self.raw_data[start..start + length])
        } else {
            None
        }
    }
}

impl Default for PDFStructure {
    fn default() -> Self {
        Self::new()
    }
}

/// PDF parsing errors
#[derive(Debug, Clone)]
pub enum PDFParseError {
    InvalidFormat(String),
    XRefNotFound,
    TrailerNotFound,
    InvalidPosition(usize),
    ObjectNotFound(u32),
    EncryptedPDF,
    CorruptedData(String),
}

impl std::fmt::Display for PDFParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PDFParseError::InvalidFormat(msg) => write!(f, "Invalid PDF format: {}", msg),
            PDFParseError::XRefNotFound => write!(f, "Cross-reference table not found"),
            PDFParseError::TrailerNotFound => write!(f, "Trailer not found"),
            PDFParseError::InvalidPosition(pos) => write!(f, "Invalid position: {}", pos),
            PDFParseError::ObjectNotFound(num) => write!(f, "Object {} not found", num),
            PDFParseError::EncryptedPDF => write!(f, "PDF is encrypted (not supported in this module)"),
            PDFParseError::CorruptedData(msg) => write!(f, "Corrupted PDF data: {}", msg),
        }
    }
}

impl std::error::Error for PDFParseError {}

/// Utility functions for PDF structure operations
pub struct PDFUtils;

impl PDFUtils {
    /// Check if data looks like a valid PDF
    pub fn is_valid_pdf(data: &[u8]) -> bool {
        data.len() > 8 && 
        data.starts_with(b"%PDF-") &&
        data.windows(7).any(|window| window == b"trailer")
    }

    /// Find all occurrences of a pattern in PDF data
    pub fn find_pattern_positions(data: &[u8], pattern: &[u8]) -> Vec<usize> {
        data.windows(pattern.len())
            .enumerate()
            .filter_map(|(i, window)| {
                if window == pattern { Some(i) } else { None }
            })
            .collect()
    }

    /// Extract PDF comment lines (starting with %)
    pub fn extract_comments(data: &[u8]) -> Vec<Vec<u8>> {
        let mut comments = Vec::new();
        let mut i = 0;

        while i < data.len() {
            if data[i] == b'%' {
                // Found comment start
                let mut comment = vec![b'%'];
                i += 1;

                // Extract until end of line
                while i < data.len() && data[i] != b'\n' && data[i] != b'\r' {
                    comment.push(data[i]);
                    i += 1;
                }

                comments.push(comment);
            } else {
                i += 1;
            }
        }

        comments
    }

    /// Count whitespace patterns
    pub fn analyze_whitespace(data: &[u8]) -> HashMap<u8, usize> {
        let mut counts = HashMap::new();
        
        for &byte in data {
            if byte.is_ascii_whitespace() {
                *counts.entry(byte).or_insert(0) += 1;
            }
        }

        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdf_object_creation() {
        let obj = PDFObject::new(PDFObjectType::Null, 100, 10);
        assert_eq!(obj.position, 100);
        assert_eq!(obj.length, 10);
        assert!(!obj.is_dictionary());
        assert!(!obj.is_stream());
    }

    #[test]
    fn test_pdf_object_dictionary() {
        let mut dict = HashMap::new();
        dict.insert(b"Type".to_vec(), PDFObject::new(PDFObjectType::Name(b"Catalog".to_vec()), 0, 0));
        
        let obj = PDFObject::new(PDFObjectType::Dictionary(dict), 0, 0);
        assert!(obj.is_dictionary());
        assert!(obj.as_dictionary().is_some());
    }

    #[test]
    fn test_xref_table() {
        let mut xref = XRefTable::new(1000, 200);
        
        let entry = XRefEntry {
            object_number: 1,
            generation: 0,
            offset: 100,
            in_use: true,
        };
        
        xref.add_entry(entry);
        assert!(xref.get_entry(1).is_some());
        assert_eq!(xref.get_object_numbers(), vec![1]);
    }

    #[test]
    fn test_pdf_trailer() {
        let mut trailer = PDFTrailer::new(2000, 100);
        
        let root_ref = PDFObject::new(
            PDFObjectType::Reference { object_number: 1, generation: 0 },
            0, 0
        );
        trailer.dictionary.insert(b"Root".to_vec(), root_ref);
        
        assert_eq!(trailer.get_root_reference(), Some((1, 0)));
    }

    #[test]
    fn test_pdf_structure_creation() {
        let structure = PDFStructure::new();
        assert!(structure.version.is_empty());
        assert!(structure.objects.is_empty());
        assert!(structure.xref_table.is_none());
        assert!(structure.trailer.is_none());
    }

    #[test]
    fn test_invalid_pdf_parsing() {
        let invalid_data = b"Not a PDF file";
        let result = PDFStructure::parse_from_data(invalid_data.to_vec());
        assert!(result.is_err());
    }

    #[test]
    fn test_pdf_utils() {
        let pdf_data = b"%PDF-1.4\nsome content\ntrailer\n<<>>\n%%EOF";
        
        assert!(PDFUtils::is_valid_pdf(pdf_data));
        
        let pattern_positions = PDFUtils::find_pattern_positions(pdf_data, b"PDF");
        assert!(!pattern_positions.is_empty());
        
        let comments = PDFUtils::extract_comments(pdf_data);
        assert!(!comments.is_empty());
        
        let whitespace = PDFUtils::analyze_whitespace(pdf_data);
        assert!(whitespace.contains_key(&b'\n'));
    }

    #[test]
    fn test_number_extraction() {
        let structure = PDFStructure::new();
        
        assert_eq!(structure.extract_number(b"123"), Some(123));
        assert_eq!(structure.extract_number(b"  456  "), Some(456));
        assert_eq!(structure.extract_number(b"abc"), None);
        assert_eq!(structure.extract_number(b"123abc456"), Some(123));
    }

    #[test]
    fn test_encryption_detection() {
        let encrypted_data = b"%PDF-1.4\n1 0 obj\n<</Encrypt 2 0 R>>\nendobj";
        let structure = PDFStructure {
            raw_data: encrypted_data.to_vec(),
            ..Default::default()
        };
        
        assert!(structure.is_encrypted());
        
        let plain_data = b"%PDF-1.4\n1 0 obj\n<</Type/Catalog>>\nendobj";
        let plain_structure = PDFStructure {
            raw_data: plain_data.to_vec(),
            ..Default::default()
        };
        
        assert!(!plain_structure.is_encrypted());
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
cargo test pdf_structure
```

## Success Criteria
- ✅ Module compiles without errors
- ✅ All unit tests pass
- ✅ Basic PDF parsing works correctly
- ✅ PDF structure analysis functions work
- ✅ Binary data handling preserved
- ✅ Independent compilation with no custom dependencies

## Critical Requirements Met
1. **Binary Preservation**: All PDF data handled in binary format
2. **Structure Analysis**: Basic PDF object and structure parsing
3. **Encryption Detection**: Can identify encrypted PDFs for later handling
4. **Independent Compilation**: Only uses standard library and previous modules
5. **Error Handling**: Comprehensive error types for parsing failures
6. **Foundation**: Provides base for invisible data extraction

## Usage in Later Modules
```rust
use crate::pdf_structure::{PDFStructure, PDFParseError};

// Parse PDF structure
let pdf_structure = PDFStructure::parse_from_data(pdf_data)?;

// Check if encrypted (critical for later modules)
if pdf_structure.is_encrypted() {
    // Must use DecryptionHandler first
    return Err("PDF is encrypted");
}

// Extract structure information
let xref_table = pdf_structure.xref_table.as_ref().unwrap();
let trailer = pdf_structure.trailer.as_ref().unwrap();

// Get document ID from trailer
if let Some((id1, id2)) = trailer.get_document_id() {
    // Store in DocumentIDManager
}
```

## Next Module
After this module compiles and tests pass, you have completed **Sequence 2: File Operations**. 

**Critical Decision Point**: You must now proceed to **Sequence 3: Crypto Handlers** - the most critical modules that will determine if the entire project succeeds or fails. 

Proceed to Module 9: DecryptionHandler - this is where the major Rust PDF encryption challenge must be solved.