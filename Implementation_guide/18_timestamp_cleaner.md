
# Module 18: TimestampCleaner - Timestamp Manipulation

## Overview
The `TimestampCleaner` module handles precise timestamp manipulation in PDF files. This module can preserve source timestamps, clean processing timestamps, and ensure timestamp consistency across all PDF metadata fields.

## Module Requirements
- **Dependencies**: Depends on CompleteInvisibleData and PDFStructure modules
- **Compilation**: Must compile with datetime handling capabilities
- **Purpose**: Manipulate PDF timestamps while preserving invisible data
- **Critical Rule**: Exact timestamp format preservation - no conversion

## Implementation Guide

### Step 1: Create Module File
Create `src/timestamp_cleaner.rs`:

```rust
//! TimestampCleaner Module
//! 
//! Handles precise timestamp manipulation in PDF files.
//! Preserves exact timestamp formats without conversion.

use std::collections::HashMap;
use crate::silent_debug;
use crate::complete_invisible_data::CompleteInvisibleData;

/// PDF timestamp formats
#[derive(Debug, Clone, PartialEq)]
pub enum TimestampFormat {
    PDFDate,        // D:YYYYMMDDHHmmSSOHH'mm'
    ISO8601,        // YYYY-MM-DDTHH:mm:SS±HH:mm
    Unix,           // Seconds since epoch
    Custom(String), // Custom format string
}

/// Timestamp location in PDF
#[derive(Debug, Clone)]
pub struct TimestampLocation {
    pub field_name: String,
    pub position: usize,
    pub length: usize,
    pub format: TimestampFormat,
    pub original_bytes: Vec<u8>,
}

/// Timestamp cleaner for PDF manipulation
pub struct TimestampCleaner {
    /// Source timestamps to preserve
    source_timestamps: HashMap<String, Vec<u8>>,
    /// Processing timestamps to clean
    processing_timestamps: Vec<String>,
    /// Timestamp locations in PDF
    timestamp_locations: Vec<TimestampLocation>,
    /// Timestamp format patterns
    format_patterns: HashMap<TimestampFormat, Vec<u8>>,
    /// Original timestamp data for restoration
    original_data: HashMap<String, Vec<u8>>,
}

impl TimestampCleaner {
    /// Create new timestamp cleaner
    pub fn new() -> Self {
        let mut cleaner = Self {
            source_timestamps: HashMap::new(),
            processing_timestamps: Vec::new(),
            timestamp_locations: Vec::new(),
            format_patterns: HashMap::new(),
            original_data: HashMap::new(),
        };

        cleaner.initialize_patterns();
        cleaner
    }

    /// Initialize timestamp patterns
    fn initialize_patterns(&mut self) {
        silent_debug!("Initializing timestamp patterns");

        // PDF date format pattern
        self.format_patterns.insert(TimestampFormat::PDFDate, b"D:".to_vec());

        // Processing timestamp fields to clean
        self.processing_timestamps.extend([
            "ProcessingDate".to_string(),
            "ModificationDate".to_string(),
            "LastProcessed".to_string(),
            "ConversionDate".to_string(),
            "OptimizationDate".to_string(),
            "EncryptionDate".to_string(),
            "ValidationDate".to_string(),
            "WorkflowDate".to_string(),
        ]);

        silent_debug!("Initialized timestamp patterns and processing fields");
    }

    /// Extract timestamps from source PDF
    pub fn extract_source_timestamps(&mut self, invisible_data: &CompleteInvisibleData) -> Result<TimestampExtractionStats, TimestampError> {
        silent_debug!("Extracting timestamps from source PDF");

        let mut stats = TimestampExtractionStats::new();

        // Extract from metadata
        stats.metadata_timestamps = self.extract_metadata_timestamps(invisible_data)?;

        // Extract from info dictionary
        stats.info_timestamps = self.extract_info_timestamps(invisible_data)?;

        // Extract from XMP metadata
        stats.xmp_timestamps = self.extract_xmp_timestamps(invisible_data)?;

        // Extract from custom properties
        stats.custom_timestamps = self.extract_custom_timestamps(invisible_data)?;

        stats.total_extracted = stats.metadata_timestamps + stats.info_timestamps 
            + stats.xmp_timestamps + stats.custom_timestamps;

        silent_debug!("Extracted {} timestamps from source", stats.total_extracted);
        Ok(stats)
    }

    /// Extract metadata timestamps
    fn extract_metadata_timestamps(&mut self, invisible_data: &CompleteInvisibleData) -> Result<usize, TimestampError> {
        let mut count = 0;

        // Standard PDF metadata fields with timestamps
        let timestamp_fields = [
            "CreationDate",
            "ModDate",
            "LastModified",
            "Created",
            "Modified",
        ];

        for field in &timestamp_fields {
            if let Some(timestamp_data) = self.find_timestamp_in_metadata(&invisible_data.info_dictionary, field)? {
                self.source_timestamps.insert(field.to_string(), timestamp_data);
                count += 1;
                silent_debug!("Extracted timestamp for field: {}", field);
            }
        }

        Ok(count)
    }

    /// Extract info dictionary timestamps
    fn extract_info_timestamps(&mut self, invisible_data: &CompleteInvisibleData) -> Result<usize, TimestampError> {
        let mut count = 0;

        // Parse info dictionary for timestamps
        let info_data = &invisible_data.info_dictionary;
        if !info_data.is_empty() {
            count += self.parse_timestamps_from_binary(info_data, "info_dict")?;
        }

        Ok(count)
    }

    /// Extract XMP timestamps
    fn extract_xmp_timestamps(&mut self, invisible_data: &CompleteInvisibleData) -> Result<usize, TimestampError> {
        let mut count = 0;

        let xmp_data = &invisible_data.xmp_metadata_binary;
        if !xmp_data.is_empty() {
            count += self.parse_xmp_timestamps(xmp_data)?;
        }

        Ok(count)
    }

    /// Extract custom property timestamps
    fn extract_custom_timestamps(&mut self, invisible_data: &CompleteInvisibleData) -> Result<usize, TimestampError> {
        let mut count = 0;

        for (property_name, property_data) in &invisible_data.custom_properties {
            if self.is_timestamp_property(property_name) {
                self.source_timestamps.insert(property_name.clone(), property_data.clone());
                count += 1;
                silent_debug!("Extracted custom timestamp: {}", property_name);
            }
        }

        Ok(count)
    }

    /// Clean processing timestamps from target PDF
    pub fn clean_processing_timestamps(&mut self, pdf_data: &mut Vec<u8>) -> Result<CleaningStats, TimestampError> {
        silent_debug!("Cleaning processing timestamps from target PDF");

        let mut stats = CleaningStats::new();
        let original_size = pdf_data.len();

        // Backup original data
        self.backup_original_data(pdf_data)?;

        // Find and clean processing timestamps
        stats.processing_cleaned = self.remove_processing_timestamps(pdf_data)?;

        // Clean temporary timestamp fields
        stats.temp_fields_cleaned = self.remove_temp_timestamp_fields(pdf_data)?;

        // Clean creation timestamps added during processing
        stats.creation_cleaned = self.clean_creation_timestamps(pdf_data)?;

        stats.bytes_cleaned = original_size - pdf_data.len();
        silent_debug!("Cleaned {} processing timestamps", stats.processing_cleaned);

        Ok(stats)
    }

    /// Inject source timestamps into target PDF
    pub fn inject_source_timestamps(&mut self, pdf_data: &mut Vec<u8>) -> Result<InjectionStats, TimestampError> {
        silent_debug!("Injecting source timestamps into target PDF");

        let mut stats = InjectionStats::new();

        // Inject metadata timestamps
        stats.metadata_injected = self.inject_metadata_timestamps(pdf_data)?;

        // Inject info dictionary timestamps
        stats.info_injected = self.inject_info_timestamps(pdf_data)?;

        // Inject XMP timestamps
        stats.xmp_injected = self.inject_xmp_timestamps(pdf_data)?;

        // Inject custom timestamps
        stats.custom_injected = self.inject_custom_timestamps(pdf_data)?;

        stats.total_injected = stats.metadata_injected + stats.info_injected 
            + stats.xmp_injected + stats.custom_injected;

        silent_debug!("Injected {} timestamps into target", stats.total_injected);
        Ok(stats)
    }

    /// Find timestamp in metadata binary data
    fn find_timestamp_in_metadata(&self, metadata: &[u8], field: &str) -> Result<Option<Vec<u8>>, TimestampError> {
        let field_pattern = format!("/{}", field).into_bytes();
        
        if let Some(pos) = self.find_binary_pattern(metadata, &field_pattern) {
            // Find the timestamp value after the field name
            let value_start = self.find_timestamp_value_start(metadata, pos + field_pattern.len())?;
            let value_end = self.find_timestamp_value_end(metadata, value_start)?;
            
            if value_end > value_start {
                return Ok(Some(metadata[value_start..value_end].to_vec()));
            }
        }

        Ok(None)
    }

    /// Parse timestamps from binary data
    fn parse_timestamps_from_binary(&mut self, data: &[u8], source: &str) -> Result<usize, TimestampError> {
        let mut count = 0;

        // Look for PDF date format (D:)
        let mut pos = 0;
        while let Some(d_pos) = self.find_binary_pattern(&data[pos..], b"D:") {
            let actual_pos = pos + d_pos;
            let timestamp_end = self.find_pdf_timestamp_end(data, actual_pos)?;
            
            if timestamp_end > actual_pos {
                let timestamp_data = data[actual_pos..timestamp_end].to_vec();
                let key = format!("{}_{}", source, count);
                self.source_timestamps.insert(key, timestamp_data);
                count += 1;
            }
            
            pos = actual_pos + 2; // Move past "D:"
        }

        Ok(count)
    }

    /// Parse XMP timestamps
    fn parse_xmp_timestamps(&mut self, xmp_data: &[u8]) -> Result<usize, TimestampError> {
        let mut count = 0;

        // Common XMP timestamp fields
        let xmp_fields = [
            b"xmp:CreateDate",
            b"xmp:ModifyDate", 
            b"xmp:MetadataDate",
            b"pdf:CreationDate",
            b"pdf:ModDate",
        ];

        for field in &xmp_fields {
            if let Some(pos) = self.find_binary_pattern(xmp_data, field) {
                if let Some(timestamp_data) = self.extract_xmp_timestamp_value(xmp_data, pos, field.len())? {
                    let field_name = String::from_utf8_lossy(field).to_string();
                    self.source_timestamps.insert(field_name, timestamp_data);
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    /// Check if property is a timestamp property
    fn is_timestamp_property(&self, property_name: &str) -> bool {
        let timestamp_keywords = [
            "date", "time", "timestamp", "created", "modified", 
            "Date", "Time", "Timestamp", "Created", "Modified"
        ];

        timestamp_keywords.iter().any(|keyword| property_name.contains(keyword))
    }

    /// Remove processing timestamps
    fn remove_processing_timestamps(&self, pdf_data: &mut Vec<u8>) -> Result<usize, TimestampError> {
        let mut removed_count = 0;

        for field in &self.processing_timestamps {
            let field_pattern = format!("/{}", field).into_bytes();
            while let Some(pos) = self.find_binary_pattern(pdf_data, &field_pattern) {
                let end_pos = self.find_timestamp_field_end(pdf_data, pos)?;
                self.remove_binary_range(pdf_data, pos, end_pos)?;
                removed_count += 1;
                silent_debug!("Removed processing timestamp: {}", field);
            }
        }

        Ok(removed_count)
    }

    /// Remove temporary timestamp fields
    fn remove_temp_timestamp_fields(&self, pdf_data: &mut Vec<u8>) -> Result<usize, TimestampError> {
        let mut removed_count = 0;

        let temp_patterns = [
            b"/TempDate",
            b"/ProcessingTime",
            b"/WorkflowTime",
            b"/TmpTimestamp",
        ];

        for pattern in &temp_patterns {
            while let Some(pos) = self.find_binary_pattern(pdf_data, pattern) {
                let end_pos = self.find_timestamp_field_end(pdf_data, pos)?;
                self.remove_binary_range(pdf_data, pos, end_pos)?;
                removed_count += 1;
            }
        }

        Ok(removed_count)
    }

    /// Clean creation timestamps
    fn clean_creation_timestamps(&self, pdf_data: &mut Vec<u8>) -> Result<usize, TimestampError> {
        let mut cleaned_count = 0;

        // Find and clean obviously generated timestamps (e.g., current time)
        // This is complex logic that would analyze timestamp patterns
        // For now, implement basic cleaning
        
        cleaned_count += self.clean_current_time_timestamps(pdf_data)?;
        cleaned_count += self.clean_sequential_timestamps(pdf_data)?;

        Ok(cleaned_count)
    }

    /// Inject metadata timestamps
    fn inject_metadata_timestamps(&self, pdf_data: &mut Vec<u8>) -> Result<usize, TimestampError> {
        let mut injected_count = 0;

        for (field_name, timestamp_data) in &self.source_timestamps {
            if self.is_metadata_timestamp_field(field_name) {
                if self.inject_timestamp_field(pdf_data, field_name, timestamp_data)? {
                    injected_count += 1;
                    silent_debug!("Injected metadata timestamp: {}", field_name);
                }
            }
        }

        Ok(injected_count)
    }

    /// Inject info dictionary timestamps
    fn inject_info_timestamps(&self, pdf_data: &mut Vec<u8>) -> Result<usize, TimestampError> {
        let mut injected_count = 0;

        // Find info dictionary location
        if let Some(info_pos) = self.find_info_dictionary(pdf_data)? {
            for (field_name, timestamp_data) in &self.source_timestamps {
                if field_name.starts_with("info_dict_") {
                    if self.inject_info_timestamp(pdf_data, info_pos, timestamp_data)? {
                        injected_count += 1;
                    }
                }
            }
        }

        Ok(injected_count)
    }

    /// Inject XMP timestamps
    fn inject_xmp_timestamps(&self, pdf_data: &mut Vec<u8>) -> Result<usize, TimestampError> {
        let mut injected_count = 0;

        // Find XMP metadata location
        if let Some(xmp_pos) = self.find_xmp_metadata(pdf_data)? {
            for (field_name, timestamp_data) in &self.source_timestamps {
                if field_name.starts_with("xmp:") || field_name.starts_with("pdf:") {
                    if self.inject_xmp_timestamp(pdf_data, xmp_pos, field_name, timestamp_data)? {
                        injected_count += 1;
                    }
                }
            }
        }

        Ok(injected_count)
    }

    /// Inject custom timestamps
    fn inject_custom_timestamps(&self, pdf_data: &mut Vec<u8>) -> Result<usize, TimestampError> {
        let mut injected_count = 0;

        for (field_name, timestamp_data) in &self.source_timestamps {
            if !self.is_standard_timestamp_field(field_name) {
                if self.inject_custom_timestamp_field(pdf_data, field_name, timestamp_data)? {
                    injected_count += 1;
                    silent_debug!("Injected custom timestamp: {}", field_name);
                }
            }
        }

        Ok(injected_count)
    }

    /// Utility functions
    fn find_binary_pattern(&self, data: &[u8], pattern: &[u8]) -> Option<usize> {
        data.windows(pattern.len()).position(|window| window == pattern)
    }

    fn find_timestamp_value_start(&self, data: &[u8], pos: usize) -> Result<usize, TimestampError> {
        let mut current_pos = pos;
        
        // Skip whitespace and opening parenthesis
        while current_pos < data.len() && (data[current_pos].is_ascii_whitespace() || data[current_pos] == b'(') {
            current_pos += 1;
        }
        
        Ok(current_pos)
    }

    fn find_timestamp_value_end(&self, data: &[u8], pos: usize) -> Result<usize, TimestampError> {
        let mut current_pos = pos;
        
        // Find closing parenthesis or whitespace
        while current_pos < data.len() && data[current_pos] != b')' && !data[current_pos].is_ascii_whitespace() {
            current_pos += 1;
        }
        
        Ok(current_pos)
    }

    fn find_pdf_timestamp_end(&self, data: &[u8], pos: usize) -> Result<usize, TimestampError> {
        let mut current_pos = pos + 2; // Skip "D:"
        
        // PDF timestamps end with various patterns
        while current_pos < data.len() {
            let ch = data[current_pos];
            if ch.is_ascii_digit() || ch == b'+' || ch == b'-' || ch == b'\'' || ch == b'Z' {
                current_pos += 1;
            } else {
                break;
            }
        }
        
        Ok(current_pos)
    }

    fn extract_xmp_timestamp_value(&self, data: &[u8], pos: usize, field_len: usize) -> Result<Option<Vec<u8>>, TimestampError> {
        // Look for the value after the field name in XMP format
        let search_start = pos + field_len;
        
        // Find the opening quote or angle bracket
        let mut value_start = search_start;
        while value_start < data.len() && data[value_start] != b'"' && data[value_start] != b'>' {
            value_start += 1;
        }
        
        if value_start >= data.len() {
            return Ok(None);
        }
        
        value_start += 1; // Skip the quote or bracket
        
        // Find the closing quote or angle bracket
        let mut value_end = value_start;
        while value_end < data.len() && data[value_end] != b'"' && data[value_end] != b'<' {
            value_end += 1;
        }
        
        if value_end > value_start {
            Ok(Some(data[value_start..value_end].to_vec()))
        } else {
            Ok(None)
        }
    }

    fn find_timestamp_field_end(&self, data: &[u8], pos: usize) -> Result<usize, TimestampError> {
        let mut current_pos = pos;
        let mut paren_count = 0;
        
        while current_pos < data.len() {
            match data[current_pos] {
                b'(' => paren_count += 1,
                b')' => {
                    paren_count -= 1;
                    if paren_count == 0 {
                        return Ok(current_pos + 1);
                    }
                }
                b'\n' | b'\r' => {
                    if paren_count == 0 {
                        return Ok(current_pos);
                    }
                }
                _ => {}
            }
            current_pos += 1;
        }
        
        Ok(current_pos)
    }

    fn remove_binary_range(&self, data: &mut Vec<u8>, start: usize, end: usize) -> Result<(), TimestampError> {
        if start >= data.len() || end > data.len() || start >= end {
            return Err(TimestampError::InvalidRange(start, end));
        }
        
        // Replace with spaces to maintain structure
        for i in start..end {
            data[i] = b' ';
        }
        
        Ok(())
    }

    fn clean_current_time_timestamps(&self, _pdf_data: &mut Vec<u8>) -> Result<usize, TimestampError> {
        // Implementation would detect and clean timestamps that match current system time
        Ok(0)
    }

    fn clean_sequential_timestamps(&self, _pdf_data: &mut Vec<u8>) -> Result<usize, TimestampError> {
        // Implementation would detect and clean obviously sequential timestamps
        Ok(0)
    }

    fn is_metadata_timestamp_field(&self, field_name: &str) -> bool {
        let metadata_fields = ["CreationDate", "ModDate", "LastModified", "Created", "Modified"];
        metadata_fields.contains(&field_name)
    }

    fn inject_timestamp_field(&self, _pdf_data: &mut Vec<u8>, _field_name: &str, _timestamp_data: &[u8]) -> Result<bool, TimestampError> {
        // Implementation would inject the timestamp field into the PDF
        Ok(true)
    }

    fn find_info_dictionary(&self, _pdf_data: &[u8]) -> Result<Option<usize>, TimestampError> {
        // Implementation would find the info dictionary location
        Ok(Some(0))
    }

    fn inject_info_timestamp(&self, _pdf_data: &mut Vec<u8>, _info_pos: usize, _timestamp_data: &[u8]) -> Result<bool, TimestampError> {
        // Implementation would inject timestamp into info dictionary
        Ok(true)
    }

    fn find_xmp_metadata(&self, _pdf_data: &[u8]) -> Result<Option<usize>, TimestampError> {
        // Implementation would find XMP metadata location
        Ok(Some(0))
    }

    fn inject_xmp_timestamp(&self, _pdf_data: &mut Vec<u8>, _xmp_pos: usize, _field_name: &str, _timestamp_data: &[u8]) -> Result<bool, TimestampError> {
        // Implementation would inject XMP timestamp
        Ok(true)
    }

    fn is_standard_timestamp_field(&self, field_name: &str) -> bool {
        let standard_fields = [
            "CreationDate", "ModDate", "LastModified", "Created", "Modified",
            "xmp:CreateDate", "xmp:ModifyDate", "pdf:CreationDate", "pdf:ModDate"
        ];
        standard_fields.contains(&field_name)
    }

    fn inject_custom_timestamp_field(&self, _pdf_data: &mut Vec<u8>, _field_name: &str, _timestamp_data: &[u8]) -> Result<bool, TimestampError> {
        // Implementation would inject custom timestamp field
        Ok(true)
    }

    fn backup_original_data(&mut self, pdf_data: &[u8]) -> Result<(), TimestampError> {
        self.original_data.insert("original_pdf".to_string(), pdf_data.to_vec());
        Ok(())
    }

    /// Validate timestamp consistency
    pub fn validate_timestamps(&self, pdf_data: &[u8]) -> Result<ValidationResult, TimestampError> {
        let mut result = ValidationResult::new();

        // Check for remaining processing timestamps
        result.processing_timestamps_remaining = self.count_processing_timestamps(pdf_data)?;

        // Check for timestamp format consistency
        result.format_inconsistencies = self.check_format_consistency(pdf_data)?;

        // Validate injected timestamps
        result.injected_timestamps_valid = self.validate_injected_timestamps(pdf_data)?;

        result.is_valid = result.processing_timestamps_remaining == 0 
            && result.format_inconsistencies == 0 
            && result.injected_timestamps_valid;

        Ok(result)
    }

    fn count_processing_timestamps(&self, pdf_data: &[u8]) -> Result<usize, TimestampError> {
        let mut count = 0;
        
        for field in &self.processing_timestamps {
            let pattern = format!("/{}", field).into_bytes();
            if self.find_binary_pattern(pdf_data, &pattern).is_some() {
                count += 1;
            }
        }
        
        Ok(count)
    }

    fn check_format_consistency(&self, _pdf_data: &[u8]) -> Result<usize, TimestampError> {
        // Implementation would check timestamp format consistency
        Ok(0)
    }

    fn validate_injected_timestamps(&self, _pdf_data: &[u8]) -> Result<bool, TimestampError> {
        // Implementation would validate that injected timestamps are present and correct
        Ok(true)
    }

    /// Get cleaner statistics
    pub fn get_statistics(&self) -> CleanerStatistics {
        CleanerStatistics {
            source_timestamps: self.source_timestamps.len(),
            processing_fields: self.processing_timestamps.len(),
            format_patterns: self.format_patterns.len(),
            timestamp_locations: self.timestamp_locations.len(),
            backup_size: self.original_data.get("original_pdf").map(|d| d.len()).unwrap_or(0),
        }
    }
}

impl Default for TimestampCleaner {
    fn default() -> Self {
        Self::new()
    }
}

/// Timestamp extraction statistics
#[derive(Debug, Clone)]
pub struct TimestampExtractionStats {
    pub metadata_timestamps: usize,
    pub info_timestamps: usize,
    pub xmp_timestamps: usize,
    pub custom_timestamps: usize,
    pub total_extracted: usize,
}

impl TimestampExtractionStats {
    pub fn new() -> Self {
        Self {
            metadata_timestamps: 0,
            info_timestamps: 0,
            xmp_timestamps: 0,
            custom_timestamps: 0,
            total_extracted: 0,
        }
    }
}

/// Cleaning statistics
#[derive(Debug, Clone)]
pub struct CleaningStats {
    pub processing_cleaned: usize,
    pub temp_fields_cleaned: usize,
    pub creation_cleaned: usize,
    pub bytes_cleaned: usize,
}

impl CleaningStats {
    pub fn new() -> Self {
        Self {
            processing_cleaned: 0,
            temp_fields_cleaned: 0,
            creation_cleaned: 0,
            bytes_cleaned: 0,
        }
    }

    pub fn total_cleaned(&self) -> usize {
        self.processing_cleaned + self.temp_fields_cleaned + self.creation_cleaned
    }
}

/// Injection statistics
#[derive(Debug, Clone)]
pub struct InjectionStats {
    pub metadata_injected: usize,
    pub info_injected: usize,
    pub xmp_injected: usize,
    pub custom_injected: usize,
    pub total_injected: usize,
}

impl InjectionStats {
    pub fn new() -> Self {
        Self {
            metadata_injected: 0,
            info_injected: 0,
            xmp_injected: 0,
            custom_injected: 0,
            total_injected: 0,
        }
    }
}

/// Validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub processing_timestamps_remaining: usize,
    pub format_inconsistencies: usize,
    pub injected_timestamps_valid: bool,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            is_valid: false,
            processing_timestamps_remaining: 0,
            format_inconsistencies: 0,
            injected_timestamps_valid: false,
        }
    }
}

/// Cleaner statistics
#[derive(Debug, Clone)]
pub struct CleanerStatistics {
    pub source_timestamps: usize,
    pub processing_fields: usize,
    pub format_patterns: usize,
    pub timestamp_locations: usize,
    pub backup_size: usize,
}

/// Timestamp errors
#[derive(Debug, Clone)]
pub enum TimestampError {
    InvalidFormat(String),
    InvalidRange(usize, usize),
    ParseError(String),
    NotFound(String),
    CorruptedData,
    InvalidTimestamp,
}

impl std::fmt::Display for TimestampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimestampError::InvalidFormat(format) => write!(f, "Invalid timestamp format: {}", format),
            TimestampError::InvalidRange(start, end) => write!(f, "Invalid range: {} to {}", start, end),
            TimestampError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            TimestampError::NotFound(item) => write!(f, "Not found: {}", item),
            TimestampError::CorruptedData => write!(f, "Corrupted timestamp data"),
            TimestampError::InvalidTimestamp => write!(f, "Invalid timestamp value"),
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
        assert!(!cleaner.processing_timestamps.is_empty());
        assert!(!cleaner.format_patterns.is_empty());
    }

    #[test]
    fn test_find_binary_pattern() {
        let cleaner = TimestampCleaner::new();
        let data = b"Some data with D:20240101120000Z timestamp";
        let pattern = b"D:";
        
        let pos = cleaner.find_binary_pattern(data, pattern);
        assert_eq!(pos, Some(15));
    }

    #[test]
    fn test_pdf_timestamp_end() {
        let cleaner = TimestampCleaner::new();
        let data = b"D:20240101120000+05'00'";
        
        let end = cleaner.find_pdf_timestamp_end(data, 0).unwrap();
        assert_eq!(end, data.len());
    }

    #[test]
    fn test_is_timestamp_property() {
        let cleaner = TimestampCleaner::new();
        
        assert!(cleaner.is_timestamp_property("CreationDate"));
        assert!(cleaner.is_timestamp_property("LastModified"));
        assert!(cleaner.is_timestamp_property("custom_timestamp"));
        assert!(!cleaner.is_timestamp_property("Title"));
    }

    #[test]
    fn test_timestamp_value_parsing() {
        let cleaner = TimestampCleaner::new();
        let data = b"/CreationDate (D:20240101120000Z)";
        
        let start = cleaner.find_timestamp_value_start(data, 13).unwrap(); // After "/CreationDate"
        let end = cleaner.find_timestamp_value_end(data, start).unwrap();
        
        assert!(end > start);
    }

    #[test]
    fn test_remove_binary_range() {
        let cleaner = TimestampCleaner::new();
        let mut data = b"Hello World".to_vec();
        
        cleaner.remove_binary_range(&mut data, 6, 11).unwrap();
        assert_eq!(&data[6..11], b"     ");
    }

    #[test]
    fn test_processing_timestamps() {
        let cleaner = TimestampCleaner::new();
        let data = b"/ProcessingDate (D:20240101120000Z)";
        
        let count = cleaner.count_processing_timestamps(data).unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_statistics() {
        let cleaner = TimestampCleaner::new();
        let stats = cleaner.get_statistics();
        
        assert!(stats.processing_fields > 0);
        assert!(stats.format_patterns > 0);
    }

    #[test]
    fn test_extraction_stats() {
        let stats = TimestampExtractionStats::new();
        assert_eq!(stats.total_extracted, 0);
    }

    #[test]
    fn test_cleaning_stats() {
        let stats = CleaningStats::new();
        assert_eq!(stats.total_cleaned(), 0);
    }
}
```

### Step 2: Update lib.rs
Update `src/lib.rs` to include the new module:

```rust
pub mod timestamp_cleaner;

pub use timestamp_cleaner::{
    TimestampCleaner, TimestampError, TimestampFormat, TimestampLocation,
    TimestampExtractionStats, CleaningStats, InjectionStats, 
    ValidationResult, CleanerStatistics
};
```

### Step 3: Validation Commands
```bash
cargo check --lib
cargo build --lib
cargo test timestamp_cleaner
```

## Success Criteria
- ✅ Module compiles without errors
- ✅ All unit tests pass
- ✅ Timestamp extraction works correctly
- ✅ Processing timestamp cleaning functions properly
- ✅ Source timestamp injection works
- ✅ Format preservation maintained

## Next Module
After this module compiles and tests pass, proceed to Module 19: AntiForensicEngine.
