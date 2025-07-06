//! PDF document parser implementation

use std::collections::HashMap;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::str::FromStr;
use log::{debug, trace, warn};

use crate::error::{PDFCryptoError, PDFCryptoResult};
use crate::EncryptionAlgorithm;
use super::{PDFObject, ObjectType, XRefTable, Dictionary, Stream, Filter};

const PDF_MAGIC: &[u8] = b"%PDF-";
const PDF_EOF_MARKER: &[u8] = b"%%EOF";
const XREF_MARKER: &[u8] = b"xref";
const TRAILER_MARKER: &[u8] = b"trailer";

/// PDF document parser
#[derive(Debug)]
pub struct PDFParser {
    data: Vec<u8>,
    xref_table: XRefTable,
    trailer: Dictionary,
    objects: HashMap<u32, PDFObject>,
    encrypted_objects: Vec<PDFObject>,
    current_offset: u64,
}

impl PDFParser {
    /// Create new parser instance
    pub fn new(data: &[u8]) -> PDFCryptoResult<Self> {
        debug!("Creating new PDF parser");
        let mut parser = Self {
            data: data.to_vec(),
            xref_table: XRefTable::new(),
            trailer: Dictionary::new(),
            objects: HashMap::new(),
            encrypted_objects: Vec::new(),
            current_offset: 0,
        };
        
        parser.parse()?;
        Ok(parser)
    }

    /// Parse PDF document structure
    fn parse(&mut self) -> PDFCryptoResult<()> {
        trace!("Starting PDF parsing");
        
        // Verify PDF header
        if !self.data.starts_with(PDF_MAGIC) {
            return Err(PDFCryptoError::MalformedPDF("Invalid PDF header".to_string()));
        }

        // Find and parse xref table
        let xref_offset = self.find_last_xref()?;
        self.parse_xref_and_trailer(xref_offset)?;

        // Parse all objects
        self.parse_objects()?;

        trace!("PDF parsing completed");
        Ok(())
    }

    /// Find the last xref table offset
    fn find_last_xref(&self) -> PDFCryptoResult<u64> {
        trace!("Searching for last xref table");
        let mut cursor = Cursor::new(&self.data);
        let file_len = self.data.len() as u64;

        // Search backwards from end of file
        let mut buffer = [0u8; 1024];
        let mut pos = file_len.saturating_sub(1024);

        while pos > 0 {
            cursor.seek(SeekFrom::Start(pos))?;
            let bytes_read = cursor.read(&mut buffer)?;

            // Look for "startxref" marker
            if let Some(idx) = find_sequence_backwards(&buffer[..bytes_read], b"startxref") {
                cursor.seek(SeekFrom::Start(pos + idx as u64 + 9))?; // Skip "startxref" and newline
                let mut offset_str = String::new();
                cursor.read_line(&mut offset_str)?;
                
                if let Ok(offset) = u64::from_str(offset_str.trim()) {
                    trace!("Found xref table at offset {}", offset);
                    return Ok(offset);
                }
            }

            pos = pos.saturating_sub(1024);
        }

        Err(PDFCryptoError::MalformedPDF("No valid xref table found".to_string()))
    }

    /// Parse xref table and trailer
    fn parse_xref_and_trailer(&mut self, offset: u64) -> PDFCryptoResult<()> {
        trace!("Parsing xref table and trailer at offset {}", offset);
        let mut cursor = Cursor::new(&self.data);
        cursor.seek(SeekFrom::Start(offset))?;

        // Verify xref marker
        let mut marker = [0u8; 4];
        cursor.read_exact(&mut marker)?;
        if &marker != XREF_MARKER {
            return Err(PDFCryptoError::MalformedPDF("Invalid xref marker".to_string()));
        }

        // Parse xref entries
        self.xref_table.parse(&mut cursor)?;

        // Parse trailer dictionary
        self.parse_trailer(&mut cursor)?;

        trace!("Xref table and trailer parsing completed");
        Ok(())
    }

    /// Parse trailer dictionary
    fn parse_trailer(&mut self, cursor: &mut Cursor<&[u8]>) -> PDFCryptoResult<()> {
        trace!("Parsing trailer dictionary");
        
        // Find trailer marker
        let mut line = String::new();
        while cursor.read_line(&mut line)? > 0 {
            if line.trim().starts_with("trailer") {
                break;
            }
            line.clear();
        }

        // Parse trailer dictionary
        self.trailer.parse(cursor)?;

        trace!("Trailer parsing completed");
        Ok(())
    }

    /// Parse PDF objects
    fn parse_objects(&mut self) -> PDFCryptoResult<()> {
        trace!("Starting object parsing");
        
        for &(obj_num, offset) in self.xref_table.entries() {
            trace!("Parsing object {} at offset {}", obj_num, offset);
            let mut cursor = Cursor::new(&self.data);
            cursor.seek(SeekFrom::Start(offset))?;

            let obj = PDFObject::parse(&mut cursor)?;
            if obj.requires_encryption() {
                trace!("Object {} requires encryption", obj_num);
                self.encrypted_objects.push(obj.clone());
            }
            self.objects.insert(obj_num, obj);
        }

        trace!("Object parsing completed");
        Ok(())
    }

    /// Get encryption dictionary
    pub fn get_encryption_dictionary(&self) -> PDFCryptoResult<Dictionary> {
        if let Some(encrypt_ref) = self.trailer.get("Encrypt") {
            if let Some(obj) = self.objects.get(&encrypt_ref.0) {
                if let ObjectType::Dictionary(dict) = &obj.object_type {
                    return Ok(dict.clone());
                }
            }
        }

        Err(PDFCryptoError::MalformedPDF("No encryption dictionary found".to_string()))
    }

    /// Get objects that need encryption/decryption
    pub fn get_encrypted_objects(&self) -> PDFCryptoResult<Vec<PDFObject>> {
        Ok(self.encrypted_objects.clone())
    }

    /// Get objects that should be encrypted
    pub fn get_encryptable_objects(&self) -> PDFCryptoResult<Vec<PDFObject>> {
        let mut objects = Vec::new();

        for obj in self.objects.values() {
            if obj.requires_encryption() {
                objects.push(obj.clone());
            }
        }

        Ok(objects)
    }

    /// Update object data
    pub fn update_object_data(&mut self, obj_num: u32, data: Vec<u8>) -> PDFCryptoResult<()> {
        if let Some(obj) = self.objects.get_mut(&obj_num) {
            obj.update_data(data);
        }

        Ok(())
    }

    /// Get object data
    pub fn get_object_data(&self, obj_num: u32) -> PDFCryptoResult<Vec<u8>> {
        self.objects
            .get(&obj_num)
            .map(|obj| obj.get_data())
            .ok_or_else(|| PDFCryptoError::ObjectNotFound(obj_num))
    }

    /// Add encryption dictionary to PDF
    pub fn add_encryption_dictionary(&mut self, dict: Dictionary) -> PDFCryptoResult<()> {
        trace!("Adding encryption dictionary");
        
        // Create new encryption dictionary object
        let obj_num = self.get_next_object_number();
        let obj = PDFObject::new_dictionary(obj_num, 0, dict);
        
        // Add to objects map
        self.objects.insert(obj_num, obj);
        
        // Update trailer
        self.trailer.set("Encrypt", (obj_num, 0));
        
        trace!("Encryption dictionary added with object number {}", obj_num);
        Ok(())
    }

    /// Rebuild PDF with updated objects
    pub fn rebuild_pdf(&self) -> Vec<u8> {
        debug!("Rebuilding PDF document");
        let mut output = Vec::new();
        
        // Write header
        output.extend_from_slice(b"%PDF-1.7\n");
        
        // Write objects
        let mut xref_offsets = HashMap::new();
        for obj in self.objects.values() {
            trace!("Writing object {}", obj.number);
            xref_offsets.insert(obj.number, output.len() as u64);
            obj.write_to(&mut output);
        }
        
        // Write xref table
        trace!("Writing xref table");
        let xref_offset = output.len() as u64;
        self.write_xref(&mut output, &xref_offsets);
        
        // Write trailer
        trace!("Writing trailer");
        self.write_trailer(&mut output);
        
        // Write xref offset and EOF marker
        write!(output, "startxref\n{}\n%%EOF", xref_offset).unwrap();
        
        debug!("PDF rebuilding completed");
        output
    }

    /// Get next available object number
    fn get_next_object_number(&self) -> u32 {
        self.objects.keys().max().map_or(1, |max| max + 1)
    }

    /// Write xref table
    fn write_xref(&self, output: &mut Vec<u8>, offsets: &HashMap<u32, u64>) {
        write!(output, "xref\n0 {}\n", offsets.len() + 1).unwrap();
        
        // Write free object entry
        write!(output, "{:010} {:05} f \n", 0, 65535).unwrap();
        
        // Write used object entries
        for obj_num in 0..offsets.len() as u32 {
            if let Some(&offset) = offsets.get(&obj_num) {
                write!(output, "{:010} {:05} n \n", offset, 0).unwrap();
            }
        }
    }

    /// Write trailer
    fn write_trailer(&self, output: &mut Vec<u8>) {
        write!(output, "trailer\n").unwrap();
        self.trailer.write_to(output);
        write!(output, "\n").unwrap();
    }
}

/// Find byte sequence in reverse
fn find_sequence_backwards(data: &[u8], sequence: &[u8]) -> Option<usize> {
    if sequence.len() > data.len() {
        return None;
    }

    'outer: for i in (0..=data.len() - sequence.len()).rev() {
        for (j, &b) in sequence.iter().enumerate() {
            if data[i + j] != b {
                continue 'outer;
            }
        }
        return Some(i);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    const TEST_FILES_DIR: &str = "tests/files";

    #[test]
    fn test_pdf_parsing() -> PDFCryptoResult<()> {
        let sample_pdf = std::fs::read(format!("{}/sample.pdf", TEST_FILES_DIR))?;
        let parser = PDFParser::new(&sample_pdf)?;
        
        // Verify basic PDF structure
        assert!(!parser.objects.is_empty());
        assert!(!parser.xref_table.entries().is_empty());
        
        // Verify trailer dictionary
        assert!(parser.trailer.get("Size").is_some());
        assert!(parser.trailer.get("Root").is_some());
        
        Ok(())
    }

    #[test]
    fn test_encrypted_pdf_parsing() -> PDFCryptoResult<()> {
        let encrypted_pdf = std::fs::read(format!("{}/encrypted.pdf", TEST_FILES_DIR))?;
        let parser = PDFParser::new(&encrypted_pdf)?;
        
        // Verify encryption dictionary exists
        let encrypt_dict = parser.get_encryption_dictionary()?;
        assert_eq!(encrypt_dict.get_name("Filter")?, "Standard");
        
        // Verify encrypted objects are identified
        let encrypted_objects = parser.get_encrypted_objects()?;
        assert!(!encrypted_objects.is_empty());
        
        Ok(())
    }

    #[test]
    fn test_pdf_rebuilding() -> PDFCryptoResult<()> {
        let sample_pdf = std::fs::read(format!("{}/sample.pdf", TEST_FILES_DIR))?;
        let parser = PDFParser::new(&sample_pdf)?;
        
        // Rebuild PDF
        let rebuilt = parser.rebuild_pdf();
        
        // Verify rebuilt PDF structure
        assert!(rebuilt.starts_with(PDF_MAGIC));
        assert!(rebuilt.ends_with(PDF_EOF_MARKER));
        
        // Parse rebuilt PDF
        let rebuilt_parser = PDFParser::new(&rebuilt)?;
        assert_eq!(rebuilt_parser.objects.len(), parser.objects.len());
        
        Ok(())
    }

    #[test]
    fn test_invalid_pdf() {
        let result = PDFParser::new(b"Not a PDF file");
        assert!(matches!(result, Err(PDFCryptoError::MalformedPDF(_))));
    }

    #[test]
    fn test_object_modification() -> PDFCryptoResult<()> {
        let sample_pdf = std::fs::read(format!("{}/sample.pdf", TEST_FILES_DIR))?;
        let mut parser = PDFParser::new(&sample_pdf)?;
        
        // Modify an object
        let obj_num = *parser.objects.keys().next().unwrap();
        let new_data = b"Modified data".to_vec();
        parser.update_object_data(obj_num, new_data.clone())?;
        
        // Verify modification
        let retrieved_data = parser.get_object_data(obj_num)?;
        assert_eq!(retrieved_data, new_data);
        
        Ok(())
    }
}
