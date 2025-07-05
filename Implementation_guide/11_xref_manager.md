# Module 11: XRefManager - Cross-Reference Handling

## Overview
The `XRefManager` module manages PDF cross-reference tables and object positioning. This module handles the precise manipulation of PDF object references while preserving invisible data associated with cross-reference structures.

## Module Requirements
- **Dependencies**: Depends on PDFStructure module
- **Compilation**: Must compile with PDFStructure dependency only
- **Purpose**: Manage PDF cross-reference tables and object positioning
- **Critical Rule**: Preserve exact xref structure and invisible data

## Implementation Guide

### Step 1: Create Module File
Create `src/xref_manager.rs`:

```rust
//! XRefManager Module
//! 
//! Manages PDF cross-reference tables and object positioning.
//! Handles precise manipulation while preserving invisible data.

use std::collections::{HashMap, BTreeMap};
use crate::silent_debug;
use crate::pdf_structure::{XRefTable, XRefEntry, PDFStructure};

/// Cross-reference manager for PDF manipulation
pub struct XRefManager {
    /// Main cross-reference table
    xref_table: Option<XRefTable>,
    /// Object position mappings
    object_positions: BTreeMap<u32, u64>,
    /// Generation numbers for each object
    object_generations: HashMap<u32, u16>,
    /// Free object chain
    free_objects: Vec<u32>,
    /// Original xref binary data (for invisible data preservation)
    original_xref_data: Vec<u8>,
}

impl XRefManager {
    /// Create new cross-reference manager
    pub fn new() -> Self {
        Self {
            xref_table: None,
            object_positions: BTreeMap::new(),
            object_generations: HashMap::new(),
            free_objects: Vec::new(),
            original_xref_data: Vec::new(),
        }
    }

    /// Load cross-reference data from PDF structure
    pub fn load_from_structure(&mut self, pdf_structure: &PDFStructure) -> Result<(), XRefError> {
        silent_debug!("Loading cross-reference data from PDF structure");

        if let Some(ref xref_table) = pdf_structure.xref_table {
            self.xref_table = Some(xref_table.clone());
            
            // Extract object positions and generations
            for (obj_num, entry) in &xref_table.entries {
                self.object_positions.insert(*obj_num, entry.offset);
                self.object_generations.insert(*obj_num, entry.generation);
                
                if !entry.in_use {
                    self.free_objects.push(*obj_num);
                }
            }
            
            // Extract original xref binary data
            if let Some(xref_data) = pdf_structure.extract_byte_range(xref_table.position, xref_table.length) {
                self.original_xref_data = xref_data.to_vec();
            }
            
            silent_debug!("Loaded {} xref entries", xref_table.entries.len());
            Ok(())
        } else {
            Err(XRefError::NoXRefTable)
        }
    }

    /// Clone cross-reference structure from source to target
    pub fn clone_xref_structure(&self, target: &mut XRefManager) -> Result<(), XRefError> {
        silent_debug!("Cloning cross-reference structure");

        target.xref_table = self.xref_table.clone();
        target.object_positions = self.object_positions.clone();
        target.object_generations = self.object_generations.clone();
        target.free_objects = self.free_objects.clone();
        target.original_xref_data = self.original_xref_data.clone();

        silent_debug!("Cross-reference structure cloned successfully");
        Ok(())
    }

    /// Update object position
    pub fn update_object_position(&mut self, object_number: u32, new_position: u64) -> Result<(), XRefError> {
        self.object_positions.insert(object_number, new_position);
        
        // Update in xref table if it exists
        if let Some(ref mut xref_table) = self.xref_table {
            if let Some(entry) = xref_table.entries.get_mut(&object_number) {
                entry.offset = new_position;
            }
        }

        silent_debug!("Updated object {} position to {}", object_number, new_position);
        Ok(())
    }

    /// Get object position
    pub fn get_object_position(&self, object_number: u32) -> Option<u64> {
        self.object_positions.get(&object_number).copied()
    }

    /// Get object generation
    pub fn get_object_generation(&self, object_number: u32) -> Option<u16> {
        self.object_generations.get(&object_number).copied()
    }

    /// Add new object to cross-reference table
    pub fn add_object(&mut self, object_number: u32, position: u64, generation: u16) -> Result<(), XRefError> {
        self.object_positions.insert(object_number, position);
        self.object_generations.insert(object_number, generation);

        // Add to xref table
        if let Some(ref mut xref_table) = self.xref_table {
            let entry = XRefEntry {
                object_number,
                generation,
                offset: position,
                in_use: true,
            };
            xref_table.add_entry(entry);
        }

        silent_debug!("Added object {} at position {}", object_number, position);
        Ok(())
    }

    /// Mark object as free
    pub fn mark_object_free(&mut self, object_number: u32) -> Result<(), XRefError> {
        if !self.free_objects.contains(&object_number) {
            self.free_objects.push(object_number);
        }

        // Update in xref table
        if let Some(ref mut xref_table) = self.xref_table {
            if let Some(entry) = xref_table.entries.get_mut(&object_number) {
                entry.in_use = false;
            }
        }

        silent_debug!("Marked object {} as free", object_number);
        Ok(())
    }

    /// Get all object numbers in order
    pub fn get_all_object_numbers(&self) -> Vec<u32> {
        self.object_positions.keys().copied().collect()
    }

    /// Get free object numbers
    pub fn get_free_objects(&self) -> &[u32] {
        &self.free_objects
    }

    /// Rebuild cross-reference table with new positions
    pub fn rebuild_xref_table(&mut self, new_positions: &HashMap<u32, u64>) -> Result<(), XRefError> {
        silent_debug!("Rebuilding cross-reference table");

        // Update positions
        for (obj_num, new_pos) in new_positions {
            self.update_object_position(*obj_num, *new_pos)?;
        }

        // Create new xref table if needed
        if self.xref_table.is_none() {
            self.xref_table = Some(XRefTable::new(0, 0));
        }

        silent_debug!("Cross-reference table rebuilt");
        Ok(())
    }

    /// Generate cross-reference binary data
    pub fn generate_xref_binary(&self) -> Result<Vec<u8>, XRefError> {
        let mut xref_data = Vec::new();
        
        // Write xref header
        xref_data.extend_from_slice(b"xref\n");
        
        // Get object numbers in order
        let obj_numbers = self.get_all_object_numbers();
        if obj_numbers.is_empty() {
            return Ok(xref_data);
        }

        // Find ranges of consecutive objects
        let ranges = self.find_object_ranges(&obj_numbers);
        
        for (start, count) in ranges {
            // Write range header
            xref_data.extend_from_slice(format!("{} {}\n", start, count).as_bytes());
            
            // Write entries for this range
            for obj_num in start..start + count {
                if let (Some(pos), Some(gen)) = (
                    self.get_object_position(obj_num),
                    self.get_object_generation(obj_num)
                ) {
                    let in_use = !self.free_objects.contains(&obj_num);
                    let flag = if in_use { 'n' } else { 'f' };
                    
                    xref_data.extend_from_slice(
                        format!("{:010} {:05} {} \n", pos, gen, flag).as_bytes()
                    );
                } else {
                    // Free entry
                    xref_data.extend_from_slice(b"0000000000 65535 f \n");
                }
            }
        }

        silent_debug!("Generated {} bytes of xref data", xref_data.len());
        Ok(xref_data)
    }

    /// Find ranges of consecutive object numbers
    fn find_object_ranges(&self, obj_numbers: &[u32]) -> Vec<(u32, u32)> {
        if obj_numbers.is_empty() {
            return Vec::new();
        }

        let mut ranges = Vec::new();
        let mut start = obj_numbers[0];
        let mut count = 1;

        for i in 1..obj_numbers.len() {
            if obj_numbers[i] == obj_numbers[i-1] + 1 {
                count += 1;
            } else {
                ranges.push((start, count));
                start = obj_numbers[i];
                count = 1;
            }
        }
        
        ranges.push((start, count));
        ranges
    }

    /// Preserve original cross-reference invisible data
    pub fn preserve_invisible_xref_data(&mut self, source_manager: &XRefManager) -> Result<(), XRefError> {
        // Copy original binary data
        self.original_xref_data = source_manager.original_xref_data.clone();
        
        // Preserve any invisible elements in the xref structure
        // This includes whitespace patterns, comment placement, etc.
        
        silent_debug!("Preserved {} bytes of invisible xref data", self.original_xref_data.len());
        Ok(())
    }

    /// Get original cross-reference binary data
    pub fn get_original_xref_data(&self) -> &[u8] {
        &self.original_xref_data
    }

    /// Validate cross-reference table consistency
    pub fn validate_consistency(&self) -> Result<(), XRefError> {
        // Check that all object positions are valid
        for (obj_num, pos) in &self.object_positions {
            if *pos == 0 && !self.free_objects.contains(obj_num) {
                return Err(XRefError::InvalidPosition(*obj_num, *pos));
            }
        }

        // Check that all objects have generations
        for obj_num in self.object_positions.keys() {
            if !self.object_generations.contains_key(obj_num) {
                return Err(XRefError::MissingGeneration(*obj_num));
            }
        }

        silent_debug!("Cross-reference table validation passed");
        Ok(())
    }

    /// Get cross-reference table statistics
    pub fn get_statistics(&self) -> XRefStatistics {
        XRefStatistics {
            total_objects: self.object_positions.len(),
            free_objects: self.free_objects.len(),
            used_objects: self.object_positions.len() - self.free_objects.len(),
            max_object_number: self.object_positions.keys().copied().max().unwrap_or(0),
            original_data_size: self.original_xref_data.len(),
        }
    }
}

impl Default for XRefManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Cross-reference statistics
#[derive(Debug, Clone)]
pub struct XRefStatistics {
    pub total_objects: usize,
    pub free_objects: usize,
    pub used_objects: usize,
    pub max_object_number: u32,
    pub original_data_size: usize,
}

/// Cross-reference errors
#[derive(Debug, Clone)]
pub enum XRefError {
    NoXRefTable,
    InvalidPosition(u32, u64),
    MissingGeneration(u32),
    ObjectNotFound(u32),
    InconsistentData,
}

impl std::fmt::Display for XRefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XRefError::NoXRefTable => write!(f, "No cross-reference table available"),
            XRefError::InvalidPosition(obj, pos) => write!(f, "Invalid position {} for object {}", pos, obj),
            XRefError::MissingGeneration(obj) => write!(f, "Missing generation number for object {}", obj),
            XRefError::ObjectNotFound(obj) => write!(f, "Object {} not found in cross-reference table", obj),
            XRefError::InconsistentData => write!(f, "Inconsistent cross-reference data"),
        }
    }
}

impl std::error::Error for XRefError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xref_manager_creation() {
        let manager = XRefManager::new();
        assert!(manager.xref_table.is_none());
        assert!(manager.object_positions.is_empty());
        assert!(manager.free_objects.is_empty());
    }

    #[test]
    fn test_add_object() {
        let mut manager = XRefManager::new();
        
        assert!(manager.add_object(1, 100, 0).is_ok());
        assert_eq!(manager.get_object_position(1), Some(100));
        assert_eq!(manager.get_object_generation(1), Some(0));
    }

    #[test]
    fn test_mark_object_free() {
        let mut manager = XRefManager::new();
        
        manager.add_object(1, 100, 0).unwrap();
        manager.mark_object_free(1).unwrap();
        
        assert!(manager.get_free_objects().contains(&1));
    }

    #[test]
    fn test_object_ranges() {
        let manager = XRefManager::new();
        
        let obj_numbers = vec![1, 2, 3, 5, 6, 8];
        let ranges = manager.find_object_ranges(&obj_numbers);
        
        assert_eq!(ranges, vec![(1, 3), (5, 2), (8, 1)]);
    }

    #[test]
    fn test_update_position() {
        let mut manager = XRefManager::new();
        
        manager.add_object(1, 100, 0).unwrap();
        manager.update_object_position(1, 200).unwrap();
        
        assert_eq!(manager.get_object_position(1), Some(200));
    }

    #[test]
    fn test_xref_binary_generation() {
        let mut manager = XRefManager::new();
        
        manager.add_object(1, 100, 0).unwrap();
        manager.add_object(2, 200, 0).unwrap();
        
        let binary = manager.generate_xref_binary().unwrap();
        assert!(binary.starts_with(b"xref\n"));
        assert!(binary.len() > 10);
    }

    #[test]
    fn test_statistics() {
        let mut manager = XRefManager::new();
        
        manager.add_object(1, 100, 0).unwrap();
        manager.add_object(2, 200, 0).unwrap();
        manager.mark_object_free(2).unwrap();
        
        let stats = manager.get_statistics();
        assert_eq!(stats.total_objects, 2);
        assert_eq!(stats.free_objects, 1);
        assert_eq!(stats.used_objects, 1);
        assert_eq!(stats.max_object_number, 2);
    }

    #[test]
    fn test_validation() {
        let mut manager = XRefManager::new();
        
        manager.add_object(1, 100, 0).unwrap();
        assert!(manager.validate_consistency().is_ok());
        
        // Add object without generation (should still work due to add_object handling it)
        manager.object_positions.insert(2, 200);
        assert!(manager.validate_consistency().is_err());
    }
}
```

### Step 2: Update lib.rs
Update `src/lib.rs` to include the new module:

```rust
pub mod xref_manager;

pub use xref_manager::{XRefManager, XRefError, XRefStatistics};
```

### Step 3: Validation Commands
```bash
cargo check --lib
cargo build --lib
cargo test xref_manager
```

## Success Criteria
- ✅ Module compiles without errors
- ✅ All unit tests pass
- ✅ Cross-reference manipulation works correctly
- ✅ Binary xref generation produces valid output
- ✅ Invisible data preservation functions work

## Next Module
After this module compiles and tests pass, proceed to Module 12: MetadataManager.