//! PDF object types and parsing implementation

use std::io::{self, Read, Seek, SeekFrom};
use std::fmt::Write;
use log::{trace, warn};
use crate::error::{PDFCryptoError, PDFCryptoResult};
use super::{Dictionary, Stream, PDFObjectCommon};

/// PDF object types
#[derive(Debug, Clone)]
pub enum ObjectType {
    /// Null object
    Null,
    /// Boolean value
    Boolean(bool),
    /// Numeric value
    Number(f64),
    /// String value (literal or hexadecimal)
    String(Vec<u8>),
    /// Name object
    Name(String),
    /// Array object
    Array(Vec<ObjectType>),
    /// Dictionary object
    Dictionary(Dictionary),
    /// Stream object
    Stream(Stream),
    /// Indirect reference
    Reference(u32, u16),
}

/// PDF object representation
#[derive(Debug, Clone)]
pub struct PDFObject {
    /// Object number
    pub number: u32,
    /// Generation number
    pub generation: u16,
    /// Object type
    pub object_type: ObjectType,
    /// Raw object data
    pub data: Vec<u8>,
}

impl PDFObject {
    /// Create new PDF object
    pub fn new(number: u32, generation: u16, object_type: ObjectType, data: Vec<u8>) -> Self {
        Self {
            number,
            generation,
            object_type,
            data,
        }
    }

    /// Create new dictionary object
    pub fn new_dictionary(number: u32, generation: u16, dict: Dictionary) -> Self {
        Self::new(number, generation, ObjectType::Dictionary(dict), Vec::new())
    }

    /// Parse PDF object from input
    pub fn parse<R: Read + Seek>(input: &mut R) -> PDFCryptoResult<Self> {
        trace!("Starting object parsing");
        let start_pos = input.stream_position()?;
        
        // Parse object header
        let (number, generation) = Self::parse_object_header(input)?;
        trace!("Parsed object header: {} {}", number, generation);

        // Parse object content
        let object_type = Self::parse_object_type(input)?;
        
        // Get raw data
        let end_pos = input.stream_position()?;
        input.seek(SeekFrom::Start(start_pos))?;
        let mut raw_data = vec![0; (end_pos - start_pos) as usize];
        input.read_exact(&mut raw_data)?;
        
        trace!("Object parsing completed");
        Ok(Self::new(number, generation, object_type, raw_data))
    }

    /// Parse object header (obj_num gen_num obj)
    fn parse_object_header<R: Read>(input: &mut R) -> PDFCryptoResult<(u32, u16)> {
        let mut line = String::new();
        input.read_line(&mut line)?;

        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.len() != 3 || parts[2] != "obj" {
            return Err(PDFCryptoError::MalformedPDF("Invalid object header".to_string()));
        }

        let number = parts[0].parse::<u32>()
            .map_err(|_| PDFCryptoError::MalformedPDF("Invalid object number".to_string()))?;
        let generation = parts[1].parse::<u16>()
            .map_err(|_| PDFCryptoError::MalformedPDF("Invalid generation number".to_string()))?;

        Ok((number, generation))
    }

    /// Parse object type and content
    fn parse_object_type<R: Read + Seek>(input: &mut R) -> PDFCryptoResult<ObjectType> {
        let mut token = Self::read_token(input)?;
        
        match token.as_bytes().first() {
            Some(b'n') if token == "null" => Ok(ObjectType::Null),
            Some(b't') if token == "true" => Ok(ObjectType::Boolean(true)),
            Some(b'f') if token == "false" => Ok(ObjectType::Boolean(false)),
            Some(b'/') => Ok(ObjectType::Name(token[1..].to_string())),
            Some(b'(') => Self::parse_literal_string(input, &token),
            Some(b'<') => {
                if token == "<<" {
                    Self::parse_dictionary(input)
                } else {
                    Self::parse_hex_string(input, &token)
                }
            },
            Some(b'[') => Self::parse_array(input),
            Some(c) if c.is_ascii_digit() || *c == b'-' || *c == b'+' || *c == b'.' => {
                Self::parse_number(&token)
            },
            _ => Err(PDFCryptoError::MalformedPDF(format!("Unknown object type: {}", token))),
        }
    }

    /// Read next token from input
    fn read_token<R: Read>(input: &mut R) -> PDFCryptoResult<String> {
        let mut token = String::new();
        let mut in_string = false;
        let mut in_hex = false;
        let mut nested_level = 0;

        loop {
            let mut byte = [0u8];
            if input.read_exact(&mut byte).is_err() {
                break;
            }

            match byte[0] {
                b'(' => {
                    in_string = true;
                    nested_level += 1;
                    token.push('(');
                }
                b')' => {
                    nested_level -= 1;
                    token.push(')');
                    if nested_level == 0 {
                        in_string = false;
                        break;
                    }
                }
                b'<' => {
                    if in_hex {
                        nested_level += 1;
                    } else {
                        in_hex = true;
                    }
                    token.push('<');
                }
                b'>' => {
                    if nested_level > 0 {
                        nested_level -= 1;
                    } else {
                        in_hex = false;
                        token.push('>');
                        break;
                    }
                }
                b'[' | b'{' => {
                    nested_level += 1;
                    token.push(byte[0] as char);
                }
                b']' | b'}' => {
                    nested_level -= 1;
                    token.push(byte[0] as char);
                    if nested_level == 0 {
                        break;
                    }
                }
                b' ' | b'\t' | b'\n' | b'\r' if !in_string && !in_hex && nested_level == 0 => {
                    if !token.is_empty() {
                        break;
                    }
                }
                _ => token.push(byte[0] as char),
            }
        }

        Ok(token)
    }

    /// Parse literal string
    fn parse_literal_string<R: Read + Seek>(input: &mut R, initial: &str) -> PDFCryptoResult<ObjectType> {
        let mut content = initial.to_string();
        let mut nesting = 1;
        let mut escaped = false;

        while nesting > 0 {
            let mut byte = [0u8];
            input.read_exact(&mut byte)?;
            
            match (byte[0], escaped) {
                (b'(', false) => {
                    nesting += 1;
                    content.push('(');
                }
                (b')', false) => {
                    nesting -= 1;
                    if nesting > 0 {
                        content.push(')');
                    }
                }
                (b'\\', false) => {
                    escaped = true;
                }
                (b'n', true) => {
                    content.push('\n');
                    escaped = false;
                }
                (b'r', true) => {
                    content.push('\r');
                    escaped = false;
                }
                (b't', true) => {
                    content.push('\t');
                    escaped = false;
                }
                (b'b', true) => {
                    content.push('\x08');
                    escaped = false;
                }
                (b'f', true) => {
                    content.push('\x0c');
                    escaped = false;
                }
                (c, true) => {
                    content.push(c as char);
                    escaped = false;
                }
                (c, false) => {
                    content.push(c as char);
                }
            }
        }

        Ok(ObjectType::String(content[1..content.len()-1].as_bytes().to_vec()))
    }

    /// Parse hexadecimal string
    fn parse_hex_string<R: Read + Seek>(input: &mut R, initial: &str) -> PDFCryptoResult<ObjectType> {
        let mut content = initial[1..].to_string(); // Skip initial '<'
        
        loop {
            let mut byte = [0u8];
            input.read_exact(&mut byte)?;
            
            match byte[0] {
                b'>' => break,
                b' ' | b'\t' | b'\n' | b'\r' => continue,
                c if c.is_ascii_hexdigit() => content.push(c as char),
                _ => return Err(PDFCryptoError::MalformedPDF("Invalid hex string".to_string())),
            }
        }

        // Handle odd number of digits
        if content.len() % 2 != 0 {
            content.push('0');
        }

        // Convert hex string to bytes
        let bytes = (0..content.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&content[i..i+2], 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PDFCryptoError::MalformedPDF("Invalid hex string".to_string()))?;

        Ok(ObjectType::String(bytes))
    }

    /// Parse array object
    fn parse_array<R: Read + Seek>(input: &mut R) -> PDFCryptoResult<ObjectType> {
        let mut array = Vec::new();
        
        loop {
            let token = Self::read_token(input)?;
            if token == "]" {
                break;
            }
            
            match token.as_bytes().first() {
                Some(b'[') => array.push(Self::parse_array(input)?),
                Some(_) => {
                    let mut cursor = io::Cursor::new(token.as_bytes());
                    array.push(Self::parse_object_type(&mut cursor)?);
                }
                None => break,
            }
        }

        Ok(ObjectType::Array(array))
    }

    /// Parse dictionary object
    fn parse_dictionary<R: Read + Seek>(input: &mut R) -> PDFCryptoResult<ObjectType> {
        let mut dict = Dictionary::new();
        dict.parse(input)?;

        // Check for stream
        let mut peek_buf = [0u8; 6];
        let pos = input.stream_position()?;
        input.read_exact(&mut peek_buf)?;
        
        if &peek_buf == b"stream" {
            let mut stream = Stream::new(dict);
            stream.parse(input)?;
            Ok(ObjectType::Stream(stream))
        } else {
            input.seek(SeekFrom::Start(pos))?;
            Ok(ObjectType::Dictionary(dict))
        }
    }

    /// Parse number object
    fn parse_number(token: &str) -> PDFCryptoResult<ObjectType> {
        // Check for indirect reference (three numbers followed by 'R')
        let parts: Vec<&str> = token.split_whitespace().collect();
        if parts.len() == 3 && parts[2] == "R" {
            let obj_num = parts[0].parse::<u32>()
                .map_err(|_| PDFCryptoError::MalformedPDF("Invalid object number in reference".to_string()))?;
            let gen_num = parts[1].parse::<u16>()
                .map_err(|_| PDFCryptoError::MalformedPDF("Invalid generation number in reference".to_string()))?;
            return Ok(ObjectType::Reference(obj_num, gen_num));
        }

        // Parse as regular number
        token.parse::<f64>()
            .map(ObjectType::Number)
            .map_err(|_| PDFCryptoError::MalformedPDF("Invalid number".to_string()))
    }

    /// Check if object requires encryption
    pub fn requires_encryption(&self) -> bool {
        matches!(self.object_type,
            ObjectType::String(_) |
            ObjectType::Stream(_)
        )
    }

    /// Update object data
    pub fn update_data(&mut self, data: Vec<u8>) {
        match &mut self.object_type {
            ObjectType::String(s) => *s = data,
            ObjectType::Stream(s) => s.update_data(data),
            _ => self.data = data,
        }
    }

    /// Get object data
    pub fn get_data(&self) -> Vec<u8> {
        match &self.object_type {
            ObjectType::String(s) => s.clone(),
            ObjectType::Stream(s) => s.get_data(),
            _ => self.data.clone(),
        }
    }
}

impl PDFObjectCommon for PDFObject {
    fn get_type(&self) -> ObjectType {
        self.object_type.clone()
    }
    
    fn write_to(&self, output: &mut Vec<u8>) {
        write!(output, "{} {} obj\n", self.number, self.generation).unwrap();
        
        match &self.object_type {
            ObjectType::Null => output.extend_from_slice(b"null"),
            ObjectType::Boolean(b) => write!(output, "{}", b).unwrap(),
            ObjectType::Number(n) => write!(output, "{}", n).unwrap(),
            ObjectType::String(s) => {
                output.extend_from_slice(b"(");
                output.extend_from_slice(s);
                output.extend_from_slice(b")");
            }
            ObjectType::Name(n) => write!(output, "/{}", n).unwrap(),
            ObjectType::Array(a) => {
                output.extend_from_slice(b"[");
                for item in a {
                    output.extend_from_slice(b" ");
                    match item {
                        ObjectType::Number(n) => write!(output, "{}", n).unwrap(),
                        ObjectType::String(s) => {
                            output.extend_from_slice(b"(");
                            output.extend_from_slice(s);
                            output.extend_from_slice(b")");
                        }
                        ObjectType::Name(n) => write!(output, "/{}", n).unwrap(),
                        ObjectType::Reference(obj, gen) => write!(output, "{} {} R", obj, gen).unwrap(),
                        _ => warn!("Unsupported array element type"),
                    }
                }
                output.extend_from_slice(b" ]");
            }
            ObjectType::Dictionary(d) => d.write_to(output),
            ObjectType::Stream(s) => s.write_to(output),
            ObjectType::Reference(obj, gen) => write!(output, "{} {} R", obj, gen).unwrap(),
        }
        
        output.extend_from_slice(b"\nendobj\n\n");
    }
    
    fn clone_object(&self) -> Box<dyn PDFObjectCommon> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    #[test]
    fn test_object_parsing() -> PDFCryptoResult<()> {
        let data = b"1 0 obj\n(Test string)\nendobj\n";
        let mut cursor = io::Cursor::new(data);
        let obj = PDFObject::parse(&mut cursor)?;
        
        assert_eq!(obj.number, 1);
        assert_eq!(obj.generation, 0);
        
        if let ObjectType::String(s) = obj.object_type {
            assert_eq!(s, b"Test string");
        } else {
            panic!("Expected string object");
        }
        
        Ok(())
    }

    #[test]
    fn test_dictionary_parsing() -> PDFCryptoResult<()> {
        let data = b"1 0 obj\n<< /Type /Test\n/Value 123 >>\nendobj\n";
        let mut cursor = io::Cursor::new(data);
        let obj = PDFObject::parse(&mut cursor)?;
        
        if let ObjectType::Dictionary(dict) = obj.object_type {
            assert_eq!(dict.get_name("Type")?, "Test");
            assert_eq!(dict.get_number("Value")?, 123.0);
        } else {
            panic!("Expected dictionary object");
        }
        
        Ok(())
    }

    #[test]
    fn test_array_parsing() -> PDFCryptoResult<()> {
        let data = b"1 0 obj\n[1 2 /Name (String)]\nendobj\n";
        let mut cursor = io::Cursor::new(data);
        let obj = PDFObject::parse(&mut cursor)?;
        
        if let ObjectType::Array(array) = obj.object_type {
            assert_eq!(array.len(), 4);
            assert!(matches!(array[0], ObjectType::Number(1.0)));
            assert!(matches!(array[2], ObjectType::Name(ref s) if s == "Name"));
        } else {
            panic!("Expected array object");
        }
        
        Ok(())
    }

    #[test]
    fn test_hex_string_parsing() -> PDFCryptoResult<()> {
        let data = b"1 0 obj\n<48656C6C6F>\nendobj\n";
        let mut cursor = io::Cursor::new(data);
        let obj = PDFObject::parse(&mut cursor)?;
        
        if let ObjectType::String(s) = obj.object_type {
            assert_eq!(s, b"Hello");
        } else {
            panic!("Expected string object");
        }
        
        Ok(())
    }

    #[test]
    fn test_stream_object() -> PDFCryptoResult<()> {
        let data = b"1 0 obj\n<< /Length 11 >>\nstream\nHello World\nendstream\nendobj\n";
        let mut cursor = io::Cursor::new(data);
        let obj = PDFObject::parse(&mut cursor)?;
        
        if let ObjectType::Stream(stream) = obj.object_type {
            assert_eq!(stream.get_data(), b"Hello World");
        } else {
            panic!("Expected stream object");
        }
        
        Ok(())
    }
}
