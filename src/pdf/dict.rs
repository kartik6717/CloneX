//! PDF dictionary implementation

use std::collections::HashMap;
use std::io::{self, Read, Seek};
use std::fmt::Write;
use crate::error::PDFCryptoError;

/// PDF dictionary object
#[derive(Debug, Clone, Default)]
pub struct Dictionary {
    entries: HashMap<String, Value>,
}

/// Dictionary value types
#[derive(Debug, Clone)]
pub enum Value {
    Number(f64),
    String(String),
    Name(String),
    Reference(u32, u16), // object number, generation
    Array(Vec<Value>),
    Dictionary(Box<Dictionary>),
    Boolean(bool),
    Null,
}

impl Dictionary {
    /// Create new dictionary
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Parse dictionary from input
    pub fn parse<R: Read + Seek>(&mut self, input: &mut R) -> Result<(), PDFCryptoError> {
        let mut content = String::new();
        let mut nesting = 1;

        while nesting > 0 {
            let mut line = String::new();
            input.read_line(&mut line)?;
            
            for chunk in line.split_whitespace() {
                match chunk {
                    "<<" => nesting += 1,
                    ">>" => nesting -= 1,
                    _ => content.push_str(chunk),
                }
                content.push(' ');
            }

            if nesting == 0 {
                break;
            }
        }

        self.parse_content(&content)?;
        Ok(())
    }

    /// Get value by key
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.get(key)
    }

    /// Get integer value
    pub fn get_integer(&self, key: &str) -> Option<i64> {
        match self.get(key) {
            Some(Value::Number(n)) => Some(*n as i64),
            _ => None,
        }
    }

    /// Get string value
    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Value::String(s)) => Some(s),
            _ => None,
        }
    }

    /// Get name value
    pub fn get_name(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Value::Name(n)) => Some(n),
            _ => None,
        }
    }

    /// Get reference value
    pub fn get_reference(&self, key: &str) -> Option<(u32, u16)> {
        match self.get(key) {
            Some(Value::Reference(obj_num, gen_num)) => Some((*obj_num, *gen_num)),
            _ => None,
        }
    }

    /// Set value
    pub fn set(&mut self, key: &str, value: Value) {
        self.entries.insert(key.to_string(), value);
    }

    /// Set reference value
    pub fn set_reference(&mut self, key: &str, obj_num: u32, gen_num: u16) {
        self.set(key, Value::Reference(obj_num, gen_num));
    }

    /// Write dictionary to output
    pub fn write_to(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(b"<<\n");
        
        for (key, value) in &self.entries {
            write!(output, "/{} ", key).unwrap();
            self.write_value(output, value);
            output.extend_from_slice(b"\n");
        }
        
        output.extend_from_slice(b">>\n");
    }

    /// Parse dictionary content
    fn parse_content(&mut self, content: &str) -> Result<(), PDFCryptoError> {
        let mut tokens = content.split_whitespace().peekable();

        while let Some(token) = tokens.next() {
            if token.starts_with('/') {
                let key = token[1..].to_string();
                let value = self.parse_value(&mut tokens)?;
                self.entries.insert(key, value);
            }
        }

        Ok(())
    }

    /// Parse dictionary value
    fn parse_value<I>(&self, tokens: &mut std::iter::Peekable<I>) -> Result<Value, PDFCryptoError>
    where
        I: Iterator<Item = String>,
    {
        let token = tokens.next()
            .ok_or_else(|| PDFCryptoError::MalformedPDF("Unexpected end of dictionary".to_string()))?;

        match token.chars().next() {
            Some('(') => Ok(Value::String(token[1..token.len()-1].to_string())),
            Some('/') => Ok(Value::Name(token[1..].to_string())),
            Some('[') => self.parse_array(tokens),
            Some('<') if token == "<<" => self.parse_nested_dict(tokens),
            Some('t') if token == "true" => Ok(Value::Boolean(true)),
            Some('f') if token == "false" => Ok(Value::Boolean(false)),
            Some('n') if token == "null" => Ok(Value::Null),
            Some(c) if c.is_ascii_digit() || c == '-' || c == '+' || c == '.' => {
                let num = token.parse()
                    .map_err(|_| PDFCryptoError::MalformedPDF("Invalid number".to_string()))?;
                
                // Check if it's a reference (followed by generation number and 'R')
                if let Some(gen_str) = tokens.next() {
                    if let Some(r) = tokens.next() {
                        if r == "R" {
                            let generation = gen_str.parse()
                                .map_err(|_| PDFCryptoError::MalformedPDF("Invalid generation number".to_string()))?;
                            return Ok(Value::Reference(num as u32, generation));
                        }
                    }
                }
                
                Ok(Value::Number(num))
            }
            _ => Err(PDFCryptoError::MalformedPDF("Invalid dictionary value".to_string())),
        }
    }

    /// Parse array value
    fn parse_array<I>(&self, tokens: &mut std::iter::Peekable<I>) -> Result<Value, PDFCryptoError>
    where
        I: Iterator<Item = String>,
    {
        let mut array = Vec::new();
        
        while let Some(token) = tokens.next() {
            if token == "]" {
                break;
            }
            let mut token_iter = std::iter::once(token).chain(tokens.by_ref());
            array.push(self.parse_value(&mut token_iter.peekable())?);
        }
        
        Ok(Value::Array(array))
    }

    /// Parse nested dictionary
    fn parse_nested_dict<I>(&self, tokens: &mut std::iter::Peekable<I>) -> Result<Value, PDFCryptoError>
    where
        I: Iterator<Item = String>,
    {
        let mut dict = Dictionary::new();
        
        while let Some(token) = tokens.next() {
            if token == ">>" {
                break;
            }
            if token.starts_with('/') {
                let key = token[1..].to_string();
                let value = self.parse_value(tokens)?;
                dict.entries.insert(key, value);
            }
        }
        
        Ok(Value::Dictionary(Box::new(dict)))
    }

    /// Write value to output
    fn write_value(&self, output: &mut Vec<u8>, value: &Value) {
        match value {
            Value::Number(n) => write!(output, "{}", n).unwrap(),
            Value::String(s) => write!(output, "({})", s).unwrap(),
            Value::Name(n) => write!(output, "/{}", n).unwrap(),
            Value::Reference(obj_num, gen_num) => write!(output, "{} {} R", obj_num, gen_num).unwrap(),
            Value::Array(arr) => {
                output.extend_from_slice(b"[");
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        output.extend_from_slice(b" ");
                    }
                    self.write_value(output, item);
                }
                output.extend_from_slice(b"]");
            }
            Value::Dictionary(dict) => {
                dict.write_to(output);
            }
            Value::Boolean(b) => write!(output, "{}", b).unwrap(),
            Value::Null => output.extend_from_slice(b"null"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_dictionary_parsing() {
        let dict_data = b"<< /Type /Example\n/Subtype /DictTest\n/Version 1.0\n/IntItem 12\n/StringItem (test)\n>>";
        let mut cursor = Cursor::new(dict_data);
        
        let mut dict = Dictionary::new();
        dict.parse(&mut cursor).unwrap();
        
        assert_eq!(dict.get_name("Type"), Some("Example"));
        assert_eq!(dict.get_name("Subtype"), Some("DictTest"));
        assert_eq!(dict.get_integer("IntItem"), Some(12));
        assert_eq!(dict.get_string("StringItem"), Some("test"));
    }

    #[test]
    fn test_nested_dictionary() {
        let dict_data = b"<< /Type /Test\n/Nested << /Key1 (Value1)\n/Key2 123 >>\n>>";
        let mut cursor = Cursor::new(dict_data);
        
        let mut dict = Dictionary::new();
        dict.parse(&mut cursor).unwrap();
        
        if let Some(Value::Dictionary(nested)) = dict.get("Nested") {
            assert_eq!(nested.get_string("Key1"), Some("Value1"));
            assert_eq!(nested.get_integer("Key2"), Some(123));
        } else {
            panic!("Nested dictionary not found");
        }
    }

    #[test]
    fn test_dictionary_references() {
        let dict_data = b"<< /Type /Test\n/Ref 1 0 R\n>>";
        let mut cursor = Cursor::new(dict_data);
        
        let mut dict = Dictionary::new();
        dict.parse(&mut cursor).unwrap();
        
        assert_eq!(dict.get_reference("Ref"), Some((1, 0)));
    }
}
