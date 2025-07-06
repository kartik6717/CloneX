//! PDF cross-reference table implementation

use std::collections::HashMap;
use std::io::{self, Read, Seek};
use crate::error::PDFCryptoError;

/// PDF cross-reference table
#[derive(Default)]
pub struct XRefTable {
    entries: HashMap<u32, u64>,
}

impl XRefTable {
    /// Create new xref table
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Parse xref table from input
    pub fn parse<R: Read + Seek>(&mut self, input: &mut R) -> Result<(), PDFCryptoError> {
        let mut line = String::new();
        input.read_line(&mut line)?;

        // Parse subsection header
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.len() != 2 {
            return Err(PDFCryptoError::MalformedPDF("Invalid xref subsection".to_string()));
        }

        let start = parts[0].parse::<u32>()
            .map_err(|_| PDFCryptoError::MalformedPDF("Invalid xref start number".to_string()))?;
        let count = parts[1].parse::<u32>()
            .map_err(|_| PDFCryptoError::MalformedPDF("Invalid xref count".to_string()))?;

        // Parse entries
        for i in 0..count {
            line.clear();
            input.read_line(&mut line)?;

            let entry = line.trim();
            if entry.len() != 20 {
                return Err(PDFCryptoError::MalformedPDF("Invalid xref entry length".to_string()));
            }

            let offset = u64::from_str_radix(&entry[0..10].trim(), 10)
                .map_err(|_| PDFCryptoError::MalformedPDF("Invalid xref offset".to_string()))?;
            let _generation = u16::from_str_radix(&entry[11..16].trim(), 10)
                .map_err(|_| PDFCryptoError::MalformedPDF("Invalid xref generation".to_string()))?;
            let entry_type = entry.chars().nth(17)
                .ok_or_else(|| PDFCryptoError::MalformedPDF("Invalid xref entry type".to_string()))?;

            if entry_type == 'n' {
                self.entries.insert(start + i, offset);
            }
        }

        Ok(())
    }

    /// Get xref table entries
    pub fn entries(&self) -> Vec<(u32, u64)> {
        self.entries.iter()
            .map(|(&k, &v)| (k, v))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_xref_parsing() {
        let xref_data = b"0 3\n\
                         0000000000 65535 f \n\
                         0000000012 00000 n \n\
                         0000000234 00000 n \n";

        let mut input = Cursor::new(xref_data);
        let mut xref = XRefTable::new();
        xref.parse(&mut input).unwrap();

        assert_eq!(xref.entries.len(), 2);
        assert_eq!(xref.entries.get(&1), Some(&12));
        assert_eq!(xref.entries.get(&2), Some(&234));
    }

    #[test]
    fn test_invalid_xref() {
        let invalid_data = b"0 2\n\
                           invalid entry\n\
                           0000000234 00000 n \n";

        let mut input = Cursor::new(invalid_data);
        let mut xref = XRefTable::new();
        assert!(xref.parse(&mut input).is_err());
    }
}
