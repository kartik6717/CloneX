# Module 12: MetadataManager - Metadata Operations

## Overview
The `MetadataManager` module handles all PDF metadata operations including extraction, cleaning, and injection. This module manages XMP metadata, Info dictionary, custom properties, and all other metadata types while preserving invisible data fidelity.

## Module Requirements
- **Dependencies**: Depends on CompleteInvisibleData module
- **Compilation**: Must compile with CompleteInvisibleData dependency only
- **Purpose**: Manage all PDF metadata types in binary format
- **Critical Rule**: Preserve exact metadata from source, clean target completely

## Implementation Guide

### Step 1: Create Module File
Create `src/metadata_manager.rs`:

```rust
//! MetadataManager Module
//! 
//! Handles all PDF metadata operations including extraction, cleaning, and injection.
//! Manages XMP metadata, Info dictionary, and custom properties.

use std::collections::HashMap;
use crate::silent_debug;
use crate::CompleteInvisibleData;

/// Metadata manager for PDF operations
pub struct MetadataManager {
    /// Extracted metadata from source
    source_metadata: HashMap<String, Vec<u8>>,
    /// XMP metadata packets
    xmp_packets: Vec<Vec<u8>>,
    /// Info dictionary entries
    info_dict_entries: HashMap<Vec<u8>, Vec<u8>>,
    /// Custom properties
    custom_properties: HashMap<String, Vec<u8>>,
    /// Processing statistics
    stats: MetadataStats,
}

impl MetadataManager {
    /// Create new metadata manager
    pub fn new() -> Self {
        Self {
            source_metadata: HashMap::new(),
            xmp_packets: Vec::new(),
            info_dict_entries: HashMap::new(),
            custom_properties: HashMap::new(),
            stats: MetadataStats::new(),
        }
    }

    /// Extract all metadata from source PDF
    pub fn extract_all_metadata(&mut self, pdf_data: &[u8], invisible_data: &mut CompleteInvisibleData) -> Result<(), MetadataError> {
        silent_debug!("Extracting all metadata from source PDF");

        // Extract XMP metadata
        self.extract_xmp_metadata(pdf_data, invisible_data)?;

        // Extract Info dictionary
        self.extract_info_dictionary(pdf_data, invisible_data)?;

        // Extract custom properties
        self.extract_custom_properties(pdf_data, invisible_data)?;

        // Extract usage rights
        self.extract_usage_rights(pdf_data, invisible_data)?;

        // Extract form metadata
        self.extract_form_metadata(pdf_data, invisible_data)?;

        // Extract annotation metadata
        self.extract_annotation_metadata(pdf_data, invisible_data)?;

        self.stats.metadata_extracted = self.source_metadata.len();
        silent_debug!("Metadata extraction complete: {} items extracted", self.stats.metadata_extracted);
        Ok(())
    }

    /// Clean all metadata from target PDF
    pub fn clean_all_metadata(&mut self, pdf_data: &mut Vec<u8>) -> Result<(), MetadataError> {
        silent_debug!("Cleaning all metadata from target PDF");

        let original_size = pdf_data.len();

        // Clean XMP metadata
        self.clean_xmp_metadata(pdf_data)?;

        // Clean Info dictionary
        self.clean_info_dictionary(pdf_data)?;

        // Clean custom properties
        self.clean_custom_properties(pdf_data)?;

        // Clean usage rights
        self.clean_usage_rights(pdf_data)?;

        // Clean form metadata
        self.clean_form_metadata(pdf_data)?;

        // Clean annotation metadata
        self.clean_annotation_metadata(pdf_data)?;

        self.stats.bytes_cleaned = original_size - pdf_data.len();
        silent_debug!("Metadata cleaning complete: {} bytes removed", self.stats.bytes_cleaned);
        Ok(())
    }

    /// Inject source metadata into target PDF
    pub fn inject_metadata(&mut self, pdf_data: &mut Vec<u8>, invisible_data: &CompleteInvisibleData) -> Result<(), MetadataError> {
        silent_debug!("Injecting source metadata into target PDF");

        // Inject XMP metadata
        self.inject_xmp_metadata(pdf_data, invisible_data)?;

        // Inject Info dictionary
        self.inject_info_dictionary(pdf_data, invisible_data)?;

        // Inject custom properties
        self.inject_custom_properties(pdf_data, invisible_data)?;

        // Inject usage rights
        self.inject_usage_rights(pdf_data, invisible_data)?;

        // Inject form metadata
        self.inject_form_metadata(pdf_data, invisible_data)?;

        // Inject annotation metadata
        self.inject_annotation_metadata(pdf_data, invisible_data)?;

        self.stats.metadata_injected = invisible_data.custom_properties.len();
        silent_debug!("Metadata injection complete: {} items injected", self.stats.metadata_injected);
        Ok(())
    }

    /// Extract XMP metadata packets
    fn extract_xmp_metadata(&mut self, pdf_data: &[u8], invisible_data: &mut CompleteInvisibleData) -> Result<(), MetadataError> {
        let xmp_markers = [
            b"<x:xmpmeta",
            b"<?xpacket",
            b"<rdf:RDF",
        ];

        for marker in &xmp_markers {
            let mut start_pos = 0;
            while let Some(pos) = self.find_pattern_after(pdf_data, marker, start_pos) {
                if let Some(xmp_packet) = self.extract_xmp_packet(pdf_data, pos) {
                    self.xmp_packets.push(xmp_packet.clone());
                    
                    // Store in invisible data
                    if invisible_data.xmp_metadata_binary.is_empty() {
                        invisible_data.xmp_metadata_binary = xmp_packet;
                    } else {
                        invisible_data.xmp_metadata_binary.extend_from_slice(&xmp_packet);
                    }
                }
                start_pos = pos + marker.len();
            }
        }

        Ok(())
    }

    /// Extract single XMP packet
    fn extract_xmp_packet(&self, pdf_data: &[u8], start_pos: usize) -> Option<Vec<u8>> {
        // Find end of XMP packet
        let end_markers = [b"</x:xmpmeta>", b"<?xpacket end=", b"</rdf:RDF>"];
        
        for end_marker in &end_markers {
            if let Some(end_pos) = self.find_pattern_after(pdf_data, end_marker, start_pos) {
                let packet_end = end_pos + end_marker.len();
                return Some(pdf_data[start_pos..packet_end].to_vec());
            }
        }

        None
    }

    /// Extract Info dictionary
    fn extract_info_dictionary(&mut self, pdf_data: &[u8], invisible_data: &mut CompleteInvisibleData) -> Result<(), MetadataError> {
        let info_fields = [
            b"/Title", b"/Author", b"/Subject", b"/Keywords",
            b"/Creator", b"/Producer", b"/CreationDate", b"/ModDate",
            b"/Trapped", b"/Custom", b"/Company", b"/SourceModified"
        ];

        for field in &info_fields {
            if let Some(value) = self.extract_info_field(pdf_data, field) {
                self.info_dict_entries.insert(field.to_vec(), value.clone());
                
                // Store in invisible data based on field type
                let field_str = String::from_utf8_lossy(field);
                match field_str.as_ref() {
                    "/CreationDate" | "/ModDate" => {
                        invisible_data.info_dictionary.extend_from_slice(field);
                        invisible_data.info_dictionary.extend_from_slice(&value);
                    }
                    _ => {
                        let field_name = field_str.trim_start_matches('/').to_string();
                        invisible_data.custom_properties.insert(field_name, value);
                    }
                }
            }
        }

        Ok(())
    }

    /// Extract Info field value
    fn extract_info_field(&self, pdf_data: &[u8], field_name: &[u8]) -> Option<Vec<u8>> {
        if let Some(field_pos) = self.find_pattern(pdf_data, field_name) {
            let value_start = field_pos + field_name.len();
            
            // Skip whitespace
            let mut i = value_start;
            while i < pdf_data.len() && pdf_data[i].is_ascii_whitespace() {
                i += 1;
            }
            
            if i < pdf_data.len() {
                match pdf_data[i] {
                    b'(' => {
                        // String value in parentheses
                        i += 1;
                        let value_start = i;
                        while i < pdf_data.len() && pdf_data[i] != b')' {
                            i += 1;
                        }
                        return Some(pdf_data[value_start..i].to_vec());
                    }
                    b'<' => {
                        // Hex string
                        i += 1;
                        let value_start = i;
                        while i < pdf_data.len() && pdf_data[i] != b'>' {
                            i += 1;
                        }
                        return Some(pdf_data[value_start..i].to_vec());
                    }
                    _ => {
                        // Direct value
                        let value_start = i;
                        while i < pdf_data.len() && !pdf_data[i].is_ascii_whitespace() && pdf_data[i] != b'/' {
                            i += 1;
                        }
                        return Some(pdf_data[value_start..i].to_vec());
                    }
                }
            }
        }
        None
    }

    /// Extract custom properties
    fn extract_custom_properties(&mut self, pdf_data: &[u8], invisible_data: &mut CompleteInvisibleData) -> Result<(), MetadataError> {
        // Look for custom property patterns
        let custom_patterns = [
            b"/Custom", b"/Company", b"/Department", b"/Version",
            b"/Application", b"/Software", b"/Tool", b"/Generator"
        ];

        for pattern in &custom_patterns {
            if let Some(value) = self.extract_info_field(pdf_data, pattern) {
                let field_name = String::from_utf8_lossy(pattern).trim_start_matches('/').to_string();
                self.custom_properties.insert(field_name.clone(), value.clone());
                invisible_data.custom_properties.insert(field_name, value);
            }
        }

        Ok(())
    }

    /// Extract usage rights
    fn extract_usage_rights(&mut self, pdf_data: &[u8], invisible_data: &mut CompleteInvisibleData) -> Result<(), MetadataError> {
        let usage_patterns = [b"/Perms", b"/UR", b"/UR3", b"/UsageRights"];

        for pattern in &usage_patterns {
            if let Some(pos) = self.find_pattern(pdf_data, pattern) {
                // Extract usage rights object
                if let Some(usage_data) = self.extract_object_at_position(pdf_data, pos) {
                    invisible_data.usage_rights.extend_from_slice(&usage_data);
                }
            }
        }

        Ok(())
    }

    /// Extract form metadata
    fn extract_form_metadata(&mut self, pdf_data: &[u8], invisible_data: &mut CompleteInvisibleData) -> Result<(), MetadataError> {
        let form_patterns = [b"/AcroForm", b"/Fields", b"/XFA"];

        for pattern in &form_patterns {
            if let Some(pos) = self.find_pattern(pdf_data, pattern) {
                if let Some(form_data) = self.extract_object_at_position(pdf_data, pos) {
                    invisible_data.form_data.extend_from_slice(&form_data);
                }
            }
        }

        Ok(())
    }

    /// Extract annotation metadata
    fn extract_annotation_metadata(&mut self, pdf_data: &[u8], invisible_data: &mut CompleteInvisibleData) -> Result<(), MetadataError> {
        let annotation_patterns = [b"/Annots", b"/Popup", b"/IRT", b"/Markup"];

        for pattern in &annotation_patterns {
            if let Some(pos) = self.find_pattern(pdf_data, pattern) {
                if let Some(annot_data) = self.extract_object_at_position(pdf_data, pos) {
                    invisible_data.annotation_data.extend_from_slice(&annot_data);
                }
            }
        }

        Ok(())
    }

    /// Extract object at position
    fn extract_object_at_position(&self, pdf_data: &[u8], start_pos: usize) -> Option<Vec<u8>> {
        // Find object boundaries
        let mut obj_start = start_pos;
        let mut obj_end = start_pos;

        // Find object start (look backwards for "obj")
        while obj_start > 3 {
            if &pdf_data[obj_start-3..obj_start] == b"obj" {
                obj_start -= 3;
                break;
            }
            obj_start -= 1;
        }

        // Find object end (look forwards for "endobj")
        while obj_end + 6 <= pdf_data.len() {
            if &pdf_data[obj_end..obj_end+6] == b"endobj" {
                obj_end += 6;
                break;
            }
            obj_end += 1;
        }

        if obj_end > obj_start {
            Some(pdf_data[obj_start..obj_end].to_vec())
        } else {
            None
        }
    }

    /// Clean XMP metadata
    fn clean_xmp_metadata(&mut self, pdf_data: &mut Vec<u8>) -> Result<(), MetadataError> {
        let xmp_patterns = [b"<x:xmpmeta", b"<?xpacket", b"<rdf:RDF"];

        for pattern in &xmp_patterns {
            self.remove_metadata_sections(pdf_data, pattern)?;
        }

        Ok(())
    }

    /// Clean Info dictionary
    fn clean_info_dictionary(&mut self, pdf_data: &mut Vec<u8>) -> Result<(), MetadataError> {
        let info_fields = [
            b"/Title", b"/Author", b"/Subject", b"/Keywords",
            b"/Creator", b"/Producer", b"/CreationDate", b"/ModDate",
            b"/Trapped", b"/Custom", b"/Company"
        ];

        for field in &info_fields {
            self.remove_info_field(pdf_data, field)?;
        }

        Ok(())
    }

    /// Clean custom properties
    fn clean_custom_properties(&mut self, pdf_data: &mut Vec<u8>) -> Result<(), MetadataError> {
        let custom_patterns = [
            b"/Custom", b"/Company", b"/Department", b"/Version",
            b"/Application", b"/Software", b"/Tool", b"/Generator"
        ];

        for pattern in &custom_patterns {
            self.remove_info_field(pdf_data, pattern)?;
        }

        Ok(())
    }

    /// Clean usage rights
    fn clean_usage_rights(&mut self, pdf_data: &mut Vec<u8>) -> Result<(), MetadataError> {
        let usage_patterns = [b"/Perms", b"/UR", b"/UR3", b"/UsageRights"];

        for pattern in &usage_patterns {
            self.remove_metadata_sections(pdf_data, pattern)?;
        }

        Ok(())
    }

    /// Clean form metadata
    fn clean_form_metadata(&mut self, pdf_data: &mut Vec<u8>) -> Result<(), MetadataError> {
        let form_patterns = [b"/AcroForm", b"/Fields", b"/XFA"];

        for pattern in &form_patterns {
            self.remove_metadata_sections(pdf_data, pattern)?;
        }

        Ok(())
    }

    /// Clean annotation metadata
    fn clean_annotation_metadata(&mut self, pdf_data: &mut Vec<u8>) -> Result<(), MetadataError> {
        let annotation_patterns = [b"/Annots", b"/Popup", b"/IRT", b"/Markup"];

        for pattern in &annotation_patterns {
            self.remove_metadata_sections(pdf_data, pattern)?;
        }

        Ok(())
    }

    /// Remove metadata sections
    fn remove_metadata_sections(&self, pdf_data: &mut Vec<u8>, pattern: &[u8]) -> Result<(), MetadataError> {
        let mut i = 0;
        while i + pattern.len() <= pdf_data.len() {
            if &pdf_data[i..i + pattern.len()] == pattern {
                // Find the complete section to remove
                if let Some((start, end)) = self.find_section_boundaries(pdf_data, i) {
                    pdf_data.drain(start..end);
                    i = start;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
        Ok(())
    }

    /// Remove Info field
    fn remove_info_field(&self, pdf_data: &mut Vec<u8>, field_name: &[u8]) -> Result<(), MetadataError> {
        let mut i = 0;
        while i + field_name.len() <= pdf_data.len() {
            if &pdf_data[i..i + field_name.len()] == field_name {
                // Find the complete field (name + value)
                let field_start = i;
                let mut field_end = i + field_name.len();
                
                // Skip whitespace
                while field_end < pdf_data.len() && pdf_data[field_end].is_ascii_whitespace() {
                    field_end += 1;
                }
                
                // Find the value and its end
                field_end = self.find_value_end(pdf_data, field_end);
                
                // Remove the entire field
                pdf_data.drain(field_start..field_end);
                i = field_start;
            } else {
                i += 1;
            }
        }
        Ok(())
    }

    /// Find value end position
    fn find_value_end(&self, pdf_data: &[u8], start: usize) -> usize {
        if start >= pdf_data.len() {
            return start;
        }

        match pdf_data[start] {
            b'(' => {
                // String in parentheses
                let mut i = start + 1;
                while i < pdf_data.len() && pdf_data[i] != b')' {
                    i += 1;
                }
                i + 1
            }
            b'<' => {
                // Hex string
                let mut i = start + 1;
                while i < pdf_data.len() && pdf_data[i] != b'>' {
                    i += 1;
                }
                i + 1
            }
            _ => {
                // Direct value until whitespace or delimiter
                let mut i = start;
                while i < pdf_data.len() && !pdf_data[i].is_ascii_whitespace() && pdf_data[i] != b'/' {
                    i += 1;
                }
                i
            }
        }
    }

    /// Find section boundaries
    fn find_section_boundaries(&self, pdf_data: &[u8], start_pos: usize) -> Option<(usize, usize)> {
        // This is a simplified implementation
        // Real implementation would parse PDF structure properly
        let mut start = start_pos;
        let mut end = start_pos;

        // Find logical start
        while start > 0 && pdf_data[start - 1] != b'\n' {
            start -= 1;
        }

        // Find logical end
        while end < pdf_data.len() && pdf_data[end] != b'\n' {
            end += 1;
        }

        Some((start, end + 1))
    }

    /// Inject XMP metadata
    fn inject_xmp_metadata(&self, pdf_data: &mut Vec<u8>, invisible_data: &CompleteInvisibleData) -> Result<(), MetadataError> {
        if !invisible_data.xmp_metadata_binary.is_empty() {
            let injection_point = self.find_metadata_injection_point(pdf_data);
            pdf_data.splice(injection_point..injection_point, invisible_data.xmp_metadata_binary.iter().cloned());
        }
        Ok(())
    }

    /// Inject Info dictionary
    fn inject_info_dictionary(&self, pdf_data: &mut Vec<u8>, invisible_data: &CompleteInvisibleData) -> Result<(), MetadataError> {
        if !invisible_data.info_dictionary.is_empty() {
            let injection_point = self.find_metadata_injection_point(pdf_data);
            pdf_data.splice(injection_point..injection_point, invisible_data.info_dictionary.iter().cloned());
        }
        Ok(())
    }

    /// Inject custom properties
    fn inject_custom_properties(&self, pdf_data: &mut Vec<u8>, invisible_data: &CompleteInvisibleData) -> Result<(), MetadataError> {
        for (name, value) in &invisible_data.custom_properties {
            let field_data = format!("/{} ({})\n", name, String::from_utf8_lossy(value));
            let injection_point = self.find_metadata_injection_point(pdf_data);
            pdf_data.splice(injection_point..injection_point, field_data.bytes());
        }
        Ok(())
    }

    /// Inject usage rights
    fn inject_usage_rights(&self, pdf_data: &mut Vec<u8>, invisible_data: &CompleteInvisibleData) -> Result<(), MetadataError> {
        if !invisible_data.usage_rights.is_empty() {
            let injection_point = self.find_metadata_injection_point(pdf_data);
            pdf_data.splice(injection_point..injection_point, invisible_data.usage_rights.iter().cloned());
        }
        Ok(())
    }

    /// Inject form metadata
    fn inject_form_metadata(&self, pdf_data: &mut Vec<u8>, invisible_data: &CompleteInvisibleData) -> Result<(), MetadataError> {
        if !invisible_data.form_data.is_empty() {
            let injection_point = self.find_metadata_injection_point(pdf_data);
            pdf_data.splice(injection_point..injection_point, invisible_data.form_data.iter().cloned());
        }
        Ok(())
    }

    /// Inject annotation metadata
    fn inject_annotation_metadata(&self, pdf_data: &mut Vec<u8>, invisible_data: &CompleteInvisibleData) -> Result<(), MetadataError> {
        if !invisible_data.annotation_data.is_empty() {
            let injection_point = self.find_metadata_injection_point(pdf_data);
            pdf_data.splice(injection_point..injection_point, invisible_data.annotation_data.iter().cloned());
        }
        Ok(())
    }

    /// Find metadata injection point
    fn find_metadata_injection_point(&self, pdf_data: &[u8]) -> usize {
        // Look for trailer or suitable injection point
        if let Some(trailer_pos) = self.find_pattern(pdf_data, b"trailer") {
            trailer_pos
        } else if let Some(eof_pos) = self.find_pattern(pdf_data, b"%%EOF") {
            eof_pos
        } else {
            pdf_data.len()
        }
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

    /// Get metadata statistics
    pub fn get_statistics(&self) -> &MetadataStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_statistics(&mut self) {
        self.stats = MetadataStats::new();
    }
}

impl Default for MetadataManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Metadata statistics
#[derive(Debug, Clone)]
pub struct MetadataStats {
    pub metadata_extracted: usize,
    pub metadata_injected: usize,
    pub bytes_cleaned: usize,
    pub xmp_packets_found: usize,
    pub info_fields_found: usize,
}

impl MetadataStats {
    fn new() -> Self {
        Self {
            metadata_extracted: 0,
            metadata_injected: 0,
            bytes_cleaned: 0,
            xmp_packets_found: 0,
            info_fields_found: 0,
        }
    }
}

/// Metadata errors
#[derive(Debug, Clone)]
pub enum MetadataError {
    ExtractionFailed(String),
    CleaningFailed(String),
    InjectionFailed(String),
    InvalidFormat(String),
    NotFound(String),
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetadataError::ExtractionFailed(msg) => write!(f, "Metadata extraction failed: {}", msg),
            MetadataError::CleaningFailed(msg) => write!(f, "Metadata cleaning failed: {}", msg),
            MetadataError::InjectionFailed(msg) => write!(f, "Metadata injection failed: {}", msg),
            MetadataError::InvalidFormat(msg) => write!(f, "Invalid metadata format: {}", msg),
            MetadataError::NotFound(msg) => write!(f, "Metadata not found: {}", msg),
        }
    }
}

impl std::error::Error for MetadataError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_manager_creation() {
        let manager = MetadataManager::new();
        assert!(manager.source_metadata.is_empty());
        assert_eq!(manager.stats.metadata_extracted, 0);
    }

    #[test]
    fn test_info_field_extraction() {
        let manager = MetadataManager::new();
        let pdf_data = b"/Title (Test Document) /Author (Test Author)";
        
        let title = manager.extract_info_field(pdf_data, b"/Title");
        assert_eq!(title, Some(b"Test Document".to_vec()));
        
        let author = manager.extract_info_field(pdf_data, b"/Author");
        assert_eq!(author, Some(b"Test Author".to_vec()));
    }

    #[test]
    fn test_value_end_finding() {
        let manager = MetadataManager::new();
        
        // String in parentheses
        let data = b"(Test String) more data";
        let end = manager.find_value_end(data, 0);
        assert_eq!(end, 13);
        
        // Hex string
        let hex_data = b"<48656C6C6F> more data";
        let hex_end = manager.find_value_end(hex_data, 0);
        assert_eq!(hex_end, 11);
    }

    #[test]
    fn test_pattern_finding() {
        let manager = MetadataManager::new();
        let data = b"start <x:xmpmeta> middle </x:xmpmeta> end";
        
        let pos = manager.find_pattern(data, b"<x:xmpmeta>");
        assert_eq!(pos, Some(6));
        
        let after_pos = manager.find_pattern_after(data, b"</x:xmpmeta>", 10);
        assert_eq!(after_pos, Some(25));
    }
}
```

### Step 2: Update lib.rs
Add to `src/lib.rs`:

```rust
pub mod metadata_manager;
pub use metadata_manager::{MetadataManager, MetadataError, MetadataStats};
```

### Step 3: Validation Commands
```bash
cargo check --lib
cargo build --lib
cargo test metadata_manager
```

Let me continue with the remaining modules 13-19...