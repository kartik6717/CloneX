# Module 18: TimestampCleaner - Timestamp Manipulation

## Overview
The `TimestampCleaner` module handles timestamp manipulation and cleaning for anti-forensic purposes. This module can preserve source timestamps exactly or clean processing timestamps while maintaining invisible data fidelity.

## Module Requirements
- **Dependencies**: None (pure Rust standard library)
- **Purpose**: Clean and manipulate PDF timestamps for anti-forensic operation
- **Critical Rule**: Preserve source timestamps exactly when cloning

## Implementation Guide

### Step 1: Create Module File
Create `src/timestamp_cleaner.rs`:

```rust
//! TimestampCleaner Module
//! 
//! Handles timestamp manipulation and cleaning for anti-forensic purposes.
//! Can preserve source timestamps exactly or clean processing timestamps.

use std::collections::HashMap;
use crate::silent_debug;

/// Timestamp cleaner for anti-forensic operations
pub struct TimestampCleaner {
    /// Source timestamps to preserve
    source_timestamps: HashMap<String, Vec<u8>>,
    /// Processing timestamps to clean
    processing_timestamps: Vec<String>,
    /// Cleaned timestamp count
    cleaned_count: usize,
}

impl TimestampCleaner {
    /// Create new timestamp cleaner
    pub fn new() -> Self {
        Self {
            source_timestamps: HashMap::new(),
            processing_timestamps: Vec::new(),
            cleaned_count: 0,
        }
    }

    /// Set source timestamps to preserve exactly
    pub fn set_source_timestamps(&mut self, timestamps: HashMap<String, Vec<u8>>) {
        self.source_timestamps = timestamps;
        silent_debug!("Set {} source timestamps for preservation", self.source_timestamps.len());
    }

    /// Extract timestamps from source PDF for preservation
    pub fn extract_source_timestamps(&mut self, source_pdf: &[u8]) -> Result<(), TimestampError> {
        silent_debug!("Extracting timestamps from source PDF");

        let mut timestamps = HashMap::new();

        // Extract creation date
        if let Some(creation_date) = self.extract_timestamp_field(source_pdf, b"/CreationDate") {
            timestamps.insert("CreationDate".to_string(), creation_date);
        }

        // Extract modification date
        if let Some(mod_date) = self.extract_timestamp_field(source_pdf, b"/ModDate") {
            timestamps.insert("ModDate".to_string(), mod_date);
        }

        // Extract XMP timestamps
        self.extract_xmp_timestamps(source_pdf, &mut timestamps)?;

        self.set_source_timestamps(timestamps);
        
        silent_debug!("Extracted {} timestamps from source", self.source_timestamps.len());
        Ok(())
    }

    /// Clean all processing timestamps from PDF
    pub fn clean_processing_timestamps(&mut self, pdf_data: &mut Vec<u8>) -> Result<(), TimestampError> {
        silent_debug!("Cleaning processing timestamps");

        let original_len = pdf_data.len();

        // Clean metadata timestamps
        self.clean_metadata_timestamps(pdf_data)?;

        // Clean XMP timestamps
        self.clean_xmp_timestamps(pdf_data)?;

        // Clean comment timestamps
        self.clean_comment_timestamps(pdf_data)?;

        // Clean object timestamps
        self.clean_object_timestamps(pdf_data)?;

        let bytes_cleaned = original_len - pdf_data.len();
        silent_debug!("Timestamp cleaning complete: {} timestamps cleaned, {} bytes removed", 
                     self.cleaned_count, bytes_cleaned);
        
        Ok(())
    }

    /// Inject source timestamps into target PDF
    pub fn inject_source_timestamps(&mut self, target_pdf: &mut Vec<u8>) -> Result<(), TimestampError> {
        silent_debug!("Injecting source timestamps into target");

        // Inject creation date
        if let Some(creation_date) = self.source_timestamps.get("CreationDate") {
            self.inject_timestamp_field(target_pdf, b"/CreationDate", creation_date)?;
        }

        // Inject modification date
        if let Some(mod_date) = self.source_timestamps.get("ModDate") {
            self.inject_timestamp_field(target_pdf, b"/ModDate", mod_date)?;
        }

        // Inject XMP timestamps
        self.inject_xmp_timestamps(target_pdf)?;

        silent_debug!("Source timestamp injection complete");
        Ok(())
    }

    /// Extract timestamp field from PDF
    fn extract_timestamp_field(&self, pdf_data: &[u8], field_name: &[u8]) -> Option<Vec<u8>> {
        // Find the field in the PDF
        if let Some(field_pos) = self.find_pattern(pdf_data, field_name) {
            // Find the timestamp value (between parentheses)
            let value_start = field_pos + field_name.len();
            
            // Skip whitespace
            let mut i = value_start;
            while i < pdf_data.len() && pdf_data[i].is_ascii_whitespace() {
                i += 1;
            }
            
            if i < pdf_data.len() && pdf_data[i] == b'(' {
                // Find closing parenthesis
                let mut j = i + 1;
                while j < pdf_data.len() && pdf_data[j] != b')' {
                    j += 1;
                }
                
                if j < pdf_data.len() {
                    return Some(pdf_data[i + 1..j].to_vec());
                }
            }
        }
        
        None
    }

    /// Extract XMP timestamps
    fn extract_xmp_timestamps(&self, source_pdf: &[u8], timestamps: &mut HashMap<String, Vec<u8>>) -> Result<(), TimestampError> {
        let xmp_timestamp_fields = [
            b"xmp:CreateDate",
            b"xmp:ModifyDate", 
            b"xmp:MetadataDate",
            b"pdf:CreationDate",
            b"pdf:ModDate",
        ];

        for field in &xmp_timestamp_fields {
            if let Some(timestamp) = self.extract_xmp_field(source_pdf, field) {
                let field_name = String::from_utf8_lossy(field).to_string();
                timestamps.insert(field_name, timestamp);
            }
        }

        Ok(())
    }

    /// Extract XMP field value
    fn extract_xmp_field(&self, pdf_data: &[u8], field_name: &[u8]) -> Option<Vec<u8>> {
        if let Some(field_pos) = self.find_pattern(pdf_data, field_name) {
            // Find the value (between > and <)
            let mut i = field_pos + field_name.len();
            
            // Find opening >
            while i < pdf_data.len() && pdf_data[i] != b'>' {
                i += 1;
            }
            
            if i < pdf_data.len() {
                i += 1; // Skip >
                let value_start = i;
                
                // Find closing <
                while i < pdf_data.len() && pdf_data[i] != b'<' {
                    i += 1;
                }
                
                if i > value_start {
                    return Some(pdf_data[value_start..i].to_vec());
                }
            }
        }
        
        None
    }

    /// Clean metadata timestamps
    fn clean_metadata_timestamps(&mut self, pdf_data: &mut Vec<u8>) -> Result<(), TimestampError> {
        let timestamp_fields = [
            b"/CreationDate",
            b"/ModDate",
            b"/ProcessingDate",
            b"/LastModified",
            b"/Timestamp",
        ];

        for field in &timestamp_fields {
            // Skip if this is a source timestamp to preserve
            let field_str = String::from_utf8_lossy(field);
            if self.source_timestamps.contains_key(field_str.trim_start_matches('/')) {
                continue;
            }

            let removed_count = self.remove_timestamp_field(pdf_data, field);
            if removed_count > 0 {
                self.cleaned_count += removed_count;
                silent_debug!("Cleaned {} {} timestamps", removed_count, field_str);
            }
        }

        Ok(())
    }

    /// Clean XMP timestamps
    fn clean_xmp_timestamps(&mut self, pdf_data: &mut Vec<u8>) -> Result<(), TimestampError> {
        let xmp_timestamp_fields = [
            b"xmp:CreateDate",
            b"xmp:ModifyDate",
            b"xmp:MetadataDate", 
            b"pdf:CreationDate",
            b"pdf:ModDate",
            b"stEvt:when",
            b"stEvt:changed",
        ];

        for field in &xmp_timestamp_fields {
            // Skip if this is a source timestamp to preserve
            let field_str = String::from_utf8_lossy(field);
            if self.source_timestamps.contains_key(&field_str) {
                continue;
            }

            let removed_count = self.remove_xmp_timestamp_field(pdf_data, field);
            if removed_count > 0 {
                self.cleaned_count += removed_count;
                silent_debug!("Cleaned {} {} XMP timestamps", removed_count, field_str);
            }
        }

        Ok(())
    }

    /// Clean comment timestamps
    fn clean_comment_timestamps(&mut self, pdf_data: &mut Vec<u8>) -> Result<(), TimestampError> {
        let comment_patterns = [
            b"% Created:",
            b"% Modified:",
            b"% Generated:",
            b"% Processed:",
            b"% Timestamp:",
        ];

        for pattern in &comment_patterns {
            let removed_count = self.remove_comment_lines(pdf_data, pattern);
            if removed_count > 0 {
                self.cleaned_count += removed_count;
            }
        }

        Ok(())
    }

    /// Clean object timestamps
    fn clean_object_timestamps(&mut self, pdf_data: &mut Vec<u8>) -> Result<(), TimestampError> {
        // Remove timestamp objects (simplified implementation)
        let timestamp_patterns = [
            b"TimestampObj",
            b"ProcessingTime",
            b"CreationTime",
            b"ModificationTime",
        ];

        for pattern in &timestamp_patterns {
            let removed_count = self.remove_pattern_occurrences(pdf_data, pattern);
            if removed_count > 0 {
                self.cleaned_count += removed_count;
            }
        }

        Ok(())
    }

    /// Remove timestamp field from PDF
    fn remove_timestamp_field(&self, pdf_data: &mut Vec<u8>, field_name: &[u8]) -> usize {
        let mut removed_count = 0;
        let mut i = 0;

        while i + field_name.len() <= pdf_data.len() {
            if &pdf_data[i..i + field_name.len()] == field_name {
                // Find the complete field (field name + value)
                let field_start = i;
                let mut field_end = i + field_name.len();
                
                // Skip whitespace
                while field_end < pdf_data.len() && pdf_data[field_end].is_ascii_whitespace() {
                    field_end += 1;
                }
                
                // Find the value and its end
                if field_end < pdf_data.len() && pdf_data[field_end] == b'(' {
                    // Find closing parenthesis
                    field_end += 1;
                    while field_end < pdf_data.len() && pdf_data[field_end] != b')' {
                        field_end += 1;
                    }
                    if field_end < pdf_data.len() {
                        field_end += 1; // Include closing parenthesis
                    }
                    
                    // Remove the entire field
                    pdf_data.drain(field_start..field_end);
                    removed_count += 1;
                    // Don't increment i since we removed data
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }

        removed_count
    }

    /// Remove XMP timestamp field
    fn remove_xmp_timestamp_field(&self, pdf_data: &mut Vec<u8>, field_name: &[u8]) -> usize {
        let mut removed_count = 0;
        let mut i = 0;

        while i + field_name.len() <= pdf_data.len() {
            if &pdf_data[i..i + field_name.len()] == field_name {
                // Find the complete XMP field
                let field_start = i;
                let mut field_end = field_start;
                
                // Find end of XML element
                while field_end < pdf_data.len() && pdf_data[field_end] != b'>' {
                    field_end += 1;
                }
                
                if field_end < pdf_data.len() {
                    field_end += 1; // Include >
                    
                    // Find closing tag
                    let closing_tag = format!("</{}>", String::from_utf8_lossy(field_name));
                    if let Some(close_pos) = self.find_pattern_after(pdf_data, closing_tag.as_bytes(), field_end) {
                        field_end = close_pos + closing_tag.len();
                    }
                    
                    // Remove the entire field
                    pdf_data.drain(field_start..field_end);
                    removed_count += 1;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }

        removed_count
    }

    /// Remove comment lines containing timestamps
    fn remove_comment_lines(&self, pdf_data: &mut Vec<u8>, pattern: &[u8]) -> usize {
        let mut removed_count = 0;
        let mut i = 0;

        while i + pattern.len() <= pdf_data.len() {
            if &pdf_data[i..i + pattern.len()] == pattern {
                // Find start of line (go back to %)
                let mut line_start = i;
                while line_start > 0 && pdf_data[line_start - 1] != b'\n' && pdf_data[line_start - 1] != b'\r' {
                    line_start -= 1;
                }
                
                // Find end of line
                let mut line_end = i + pattern.len();
                while line_end < pdf_data.len() && pdf_data[line_end] != b'\n' && pdf_data[line_end] != b'\r' {
                    line_end += 1;
                }
                if line_end < pdf_data.len() {
                    line_end += 1; // Include newline
                }
                
                // Remove the entire comment line
                pdf_data.drain(line_start..line_end);
                removed_count += 1;
                i = line_start;
            } else {
                i += 1;
            }
        }

        removed_count
    }

    /// Inject timestamp field into PDF
    fn inject_timestamp_field(&self, pdf_data: &mut Vec<u8>, field_name: &[u8], timestamp: &[u8]) -> Result<(), TimestampError> {
        // Create the complete field
        let mut field_data = Vec::new();
        field_data.extend_from_slice(field_name);
        field_data.extend_from_slice(b" (");
        field_data.extend_from_slice(timestamp);
        field_data.extend_from_slice(b") ");

        // Find suitable injection point (in trailer or info object)
        let injection_point = self.find_metadata_injection_point(pdf_data);
        pdf_data.splice(injection_point..injection_point, field_data.iter().cloned());

        silent_debug!("Injected timestamp field: {}", String::from_utf8_lossy(field_name));
        Ok(())
    }

    /// Inject XMP timestamps
    fn inject_xmp_timestamps(&self, target_pdf: &mut Vec<u8>) -> Result<(), TimestampError> {
        for (field_name, timestamp) in &self.source_timestamps {
            if field_name.starts_with("xmp:") || field_name.starts_with("pdf:") {
                self.inject_xmp_field(target_pdf, field_name.as_bytes(), timestamp)?;
            }
        }
        Ok(())
    }

    /// Inject XMP field
    fn inject_xmp_field(&self, pdf_data: &mut Vec<u8>, field_name: &[u8], timestamp: &[u8]) -> Result<(), TimestampError> {
        // Create XMP field
        let field_data = format!("<{}>{}</{}>\n", 
                                String::from_utf8_lossy(field_name),
                                String::from_utf8_lossy(timestamp),
                                String::from_utf8_lossy(field_name));

        // Find XMP metadata section or create one
        let injection_point = self.find_xmp_injection_point(pdf_data);
        pdf_data.splice(injection_point..injection_point, field_data.bytes());

        Ok(())
    }

    /// Find metadata injection point
    fn find_metadata_injection_point(&self, pdf_data: &[u8]) -> usize {
        // Look for trailer or info object
        if let Some(trailer_pos) = self.find_pattern(pdf_data, b"trailer") {
            trailer_pos
        } else {
            // Fall back to end of file before %%EOF
            if let Some(eof_pos) = self.find_pattern(pdf_data, b"%%EOF") {
                eof_pos
            } else {
                pdf_data.len()
            }
        }
    }

    /// Find XMP injection point
    fn find_xmp_injection_point(&self, pdf_data: &[u8]) -> usize {
        // Look for existing XMP metadata
        if let Some(xmp_pos) = self.find_pattern(pdf_data, b"<x:xmpmeta") {
            // Find end of opening tag
            let mut i = xmp_pos;
            while i < pdf_data.len() && pdf_data[i] != b'>' {
                i += 1;
            }
            i + 1
        } else {
            // Create XMP section
            self.find_metadata_injection_point(pdf_data)
        }
    }

    /// Remove pattern occurrences
    fn remove_pattern_occurrences(&self, data: &mut Vec<u8>, pattern: &[u8]) -> usize {
        let mut removed_count = 0;
        let mut i = 0;

        while i + pattern.len() <= data.len() {
            if &data[i..i + pattern.len()] == pattern {
                data.drain(i..i + pattern.len());
                removed_count += 1;
            } else {
                i += 1;
            }
        }

        removed_count
    }

    /// Find pattern in data
    fn find_pattern(&self, data: &[u8], pattern: &[u8]) -> Option<usize> {
        data.windows(pattern.len()).position(|window| window == pattern)
    }

    /// Find pattern after position
    fn find_pattern_after(&self, data: &[u8], pattern: &[u8], after_pos: usize) -> Option<usize> {
        if after_pos >= data.len() {
            return None;
        }
        
        data[after_pos..].windows(pattern.len())
            .position(|window| window == pattern)
            .map(|pos| pos + after_pos)
    }

    /// Get cleaning statistics
    pub fn get_cleaning_stats(&self) -> CleaningStats {
        CleaningStats {
            timestamps_cleaned: self.cleaned_count,
            source_timestamps_preserved: self.source_timestamps.len(),
        }
    }

    /// Reset cleaning statistics
    pub fn reset_stats(&mut self) {
        self.cleaned_count = 0;
    }
}

impl Default for TimestampCleaner {
    fn default() -> Self {
        Self::new()
    }
}

/// Cleaning statistics
#[derive(Debug, Clone)]
pub struct CleaningStats {
    pub timestamps_cleaned: usize,
    pub source_timestamps_preserved: usize,
}

/// Timestamp errors
#[derive(Debug, Clone)]
pub enum TimestampError {
    ExtractionFailed(String),
    InjectionFailed(String),
    CleaningFailed(String),
    InvalidFormat(String),
}

impl std::fmt::Display for TimestampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimestampError::ExtractionFailed(msg) => write!(f, "Timestamp extraction failed: {}", msg),
            TimestampError::InjectionFailed(msg) => write!(f, "Timestamp injection failed: {}", msg),
            TimestampError::CleaningFailed(msg) => write!(f, "Timestamp cleaning failed: {}", msg),
            TimestampError::InvalidFormat(msg) => write!(f, "Invalid timestamp format: {}", msg),
        }
    }
}

impl std::error::Error for TimestampError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_cleaner_creation() {
        let cleaner = TimestampCleaner::new();
        assert!(cleaner.source_timestamps.is_empty());
        assert_eq!(cleaner.cleaned_count, 0);
    }

    #[test]
    fn test_timestamp_extraction() {
        let cleaner = TimestampCleaner::new();
        let pdf_data = b"/CreationDate (D:20240101120000Z)";
        
        let timestamp = cleaner.extract_timestamp_field(pdf_data, b"/CreationDate");
        assert_eq!(timestamp, Some(b"D:20240101120000Z".to_vec()));
    }

    #[test]
    fn test_pattern_removal() {
        let cleaner = TimestampCleaner::new();
        let mut data = b"before ProcessingTime after ProcessingTime end".to_vec();
        
        let removed = cleaner.remove_pattern_occurrences(&mut data, b"ProcessingTime");
        assert_eq!(removed, 2);
        assert_eq!(data, b"before  after  end");
    }
}
```

Now let me create the final modules 19-20:

<function_calls>
<invoke name="str_replace_based_edit_tool">
<parameter name="command">create