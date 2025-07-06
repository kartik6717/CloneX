//! PDF object types and parsing

use std::io::{self, Read, Seek};
use std::fmt::Write;
use crate::error::PDFCryptoError;
use super::Dictionary;

/// PDF object types
#[derive(Debug, Clone)]
pub enum PDFObjectType {
    Number(f64),
    Boolean(bool),
    String(Vec<u8>),
    Name(String),
    Array(Vec<PDFObjectType>),
    Dictionary(Dictionary),
    Stream {
        dict: Dictionary,
        data: Vec<u8>,
    },
    Null,
}

/// PDF object representation
#[derive(Debug, Clone)]
pub struct PDFObject {
    pub number: u32,
    pub generation: u16,
    pub object_type: PDFObjectType,
    raw_data: Vec<u8>,
}

impl PDFObject {
    /// Create new dictionary object
    pub fn new_dictionary(number: u32, generation: u16, dict: Dictionary) -> Self {
        Self {
            number,
            generation,
            object_type: PDFObjectType::Dictionary(dict),
            raw_data: Vec::new(),
        }
    }

    /// Parse PDF object from input
    pub fn parse<R: Read + Seek>(input: &mut R) -> Result<Self, PDFCryptoError> {
        let mut line = String::new();
        input.read_line(&mut line)?;

        // Parse object header
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.len() != 4 || parts[2] != "obj" {
            return Err(PDFCryptoError::MalformedPDF("Invalid object header".to_string()));
        }

        let number = parts[0].parse::<u32>()
            .map_err(|_| PDFCryptoError::MalformedPDF("Invalid object number".to_string()))?;
        let generation = parts[1].parse::<u16>()
            .map_err(|_| PDFCryptoError::MalformedPDF("Invalid generation number".to_string()))?;

        // Record start position for raw data
        let start_pos = input.stream_position()?;

        // Parse object content
        let object_type = Self::parse_object_type(input)?;

        // Record end position and extract raw data
        let end_pos = input.stream_position()?;
        input.seek(io::SeekFrom::Start(start_pos))?;
        let mut raw_data = vec![0; (end_pos - start_pos) as usize];
        input.read_exact(&mut raw_data)?;

        Ok(Self {
            number,
            generation,
            object_type,
            raw_data,
        })
    }

    /// Parse PDF object type
    fn parse_object_type<R: Read + Seek>(input: &mut R) -> Result<PDFObjectType, PDFCryptoError> {
        let mut line = String::new();
        input.read_line(&mut line)?;
        let token = line.trim();

        match token.chars().next() {
            Some('(') => Self::parse_string(input, token),
            Some('/') => Ok(PDFObjectType::Name(token[1..].to_string())),
            Some('[') => Self::parse_array(input, token),
            Some('<') if token.starts_with("<<") => Self::parse_dictionary(input),
            Some('t') if token == "true" => Ok(PDFObjectType::Boolean(true)),
            Some('f') if token == "false" => Ok(PDFObjectType::Boolean(false)),
            Some('n') if token == "null" => Ok(PDFObjectType::Null),
            Some(c) if c.is_ascii_digit() || c == '-' || c == '+' || c == '.' => {
                Ok(PDFObjectType::Number(token.parse().map_err(|_| 
                    PDFCryptoError::MalformedPDF("Invalid number".to_string()))?))
            }
            _ => Err(PDFCryptoError::MalformedPDF("Unknown object type".to_string())),
        }
    }

    /// Parse PDF string object
    fn parse_string<R: Read + Seek>(input: &mut R, token: &str) -> Result<PDFObjectType, PDFCryptoError> {
        let mut content = token.to_string();
        let mut nesting = 1;

        while nesting > 0 {
            let mut line = String::new();
            input.read_line(&mut line)?;
            
            for c in line.chars() {
                match c {
                    '(' => nesting += 1,
                    ')' => nesting -= 1,
                    '\\' => content.push('\\'),
                    _ => content.push(c),
                }
            }
        }

        Ok(PDFObjectType::String(content.into_bytes()))
    }

    /// Parse PDF array object
    fn parse_array<R: Read + Seek>(input: &mut R, token: &str) -> Result<PDFObjectType, PDFCryptoError> {
        let mut content = token.to_string();
        let mut nesting = 1;

        while nesting > 0 {
            let mut line = String::new();
            input.read_line(&mut line)?;
            
            for c in line.chars() {
                match c {
                    '[' => nesting += 1,
                    ']' => nesting -= 1,
                    _ => content.push(c),
                }
            }
        }

        // Parse array elements
        let mut elements = Vec::new();
        let mut cursor = io::Cursor::new(content.as_bytes());
        
        while let Ok(element) = Self::parse_object_type(&mut cursor) {
            elements.push(element);
        }

        Ok(PDFObjectType::Array(elements))
    }

    /// Parse PDF dictionary object
    fn parse_dictionary<R: Read + Seek>(input: &mut R) -> Result<PDFObjectType, PDFCryptoError> {
        let mut dict = Dictionary::new();
        dict.parse(input)?;

        // Check for stream
        let mut line = String::new();
        let pos = input.stream_position()?;
        input.read_line(&mut line)?;

        if line.trim() == "stream" {
            // Parse stream data
            let length = dict.get_integer("Length")
                .ok_or_else(|| PDFCryptoError::MalformedPDF("Missing stream length".to_string()))? as usize;

            let mut data = vec![0; length];
            input.read_exact(&mut data)?;

            // Skip "endstream" marker
            input.read_line(&mut line)?;
            if !line.trim().ends_with("endstream") {
                return Err(PDFCryptoError::MalformedPDF("Missing endstream marker".to_string()));
            }

            Ok(PDFObjectType::Stream { dict, data })
        } else {
            input.seek(io::SeekFrom::Start(pos))?;
            Ok(PDFObjectType::Dictionary(dict))
        }
    }

    /// Check if object requires encryption
    pub fn requires_encryption(&self) -> bool {
        match &self.object_type {
            PDFObjectType::String(_) => true,
            PDFObjectType::Stream { .. } => true,
            _ => false,
        }
    }

    /// Update object data
    pub fn update_data(&mut self, data: Vec<u8>) {
        match &mut self.object_type {
            PDFObjectType::String(s) => *s = data,
            PDFObjectType::Stream { data: d, .. } => *d = data,
            _ => {}
        }
        self.raw_data = data;
    }

    /// Get object data
    pub fn get_data(&self) -> Vec<u8> {
        match &self.object_type {
            PDFObjectType::String(s) => s.clone(),
            PDFObjectType::Stream { data, .. } => data.clone(),
            _ => self.raw_data.clone(),
        }
    }

    /// Write object to output
    pub fn write_to(&self, output: &mut Vec<u8>) {
        write!(output, "{} {} obj\n", self.number, self.generation).unwrap();
        
        match &self.object_type {
            PDFObjectType::Number(n) => write!(output, "{}\n", n).unwrap(),
            PDFObjectType::Boolean(b) => write!(output, "{}\n", b).unwrap(),
            PDFObjectType::String(s) => {
                output.extend_from_slice(b"(");
                output.extend_from_slice(s);
                output.extend_from_slice(b")\n");
            }
            PDFObjectType::Name(n) => write!(output, "/{}\n", n).unwrap(),
            PDFObjectType::Array(a) => {
                output.extend_from_slice(b"[");
                for item in a {
                    match item {
                        PDFObjectType::Number(n) => write!(output, " {}", n).unwrap(),
                        PDFObjectType::String(s) => {
                            output.extend_from_slice(b" (");
                            output.extend_from_slice(s);
                            output.extend_from_slice(b")");
                        }
                        _ => {} // Handle other types as needed
                    }
                }
                output.extend_from_slice(b" ]\n");
            }
            PDFObjectType::Dictionary(d) => d.write_to(output),
            PDFObjectType::Stream { dict, data } => {
                dict.write_to(output);
                output.extend_from_slice(b"stream\n");
                output.extend_from_slice(data);
                output.extend_from_slice(b"\nendstream\n");
            }
            PDFObjectType::Null => output.extend_from_slice(b"null\n"),
        }
        
        output.extend_from_slice(b"endobj\n\n");
    }
}
