//! PDF stream object implementation

use std::io::{self, Read, Seek, SeekFrom};
use std::collections::HashMap;
use flate2::read::{DeflateDecoder, ZlibDecoder};
use log::{debug, trace, warn};
use crate::error::{PDFCryptoError, PDFCryptoResult};
use super::{Dictionary, Filter, PDFObjectCommon};

/// PDF stream object
#[derive(Debug, Clone)]
pub struct Stream {
    /// Stream dictionary
    dictionary: Dictionary,
    /// Raw stream data
    data: Vec<u8>,
    /// Decoded stream data
    decoded_data: Option<Vec<u8>>,
    /// Filters applied to stream
    filters: Vec<Filter>,
}

impl Stream {
    /// Create new stream object
    pub fn new(dictionary: Dictionary) -> Self {
        let filters = Self::parse_filters(&dictionary);
        Self {
            dictionary,
            data: Vec::new(),
            decoded_data: None,
            filters,
        }
    }

    /// Parse stream from input
    pub fn parse<R: Read + Seek>(&mut self, input: &mut R) -> PDFCryptoResult<()> {
        trace!("Parsing stream");
        
        // Skip 'stream' keyword and following newline
        let mut buf = [0u8; 1];
        while buf[0] != b'\n' {
            input.read_exact(&mut buf)?;
        }

        // Get stream length
        let length = self.get_stream_length()?;
        trace!("Stream length: {}", length);

        // Read stream data
        let mut data = vec![0u8; length];
        input.read_exact(&mut data)?;
        self.data = data;

        // Skip 'endstream' keyword
        let mut buf = [0u8; 9];
        input.read_exact(&mut buf)?;
        if &buf != b"endstream" {
            return Err(PDFCryptoError::MalformedPDF("Missing endstream marker".to_string()));
        }

        trace!("Stream parsing completed");
        Ok(())
    }

    /// Get stream length from dictionary
    fn get_stream_length(&self) -> PDFCryptoResult<usize> {
        match self.dictionary.get("Length") {
            Some(value) => value.as_integer()
                .ok_or_else(|| PDFCryptoError::MalformedPDF("Invalid stream length".to_string())),
            None => Err(PDFCryptoError::MalformedPDF("Missing stream length".to_string())),
        }
    }

    /// Parse filters from dictionary
    fn parse_filters(dict: &Dictionary) -> Vec<Filter> {
        let mut filters = Vec::new();

        if let Some(filter) = dict.get("Filter") {
            match filter {
                // Single filter
                Dictionary::Name(name) => {
                    if let Ok(filter) = Filter::from_name(name) {
                        filters.push(filter);
                    }
                },
                // Array of filters
                Dictionary::Array(array) => {
                    for f in array {
                        if let Dictionary::Name(name) = f {
                            if let Ok(filter) = Filter::from_name(name) {
                                filters.push(filter);
                            }
                        }
                    }
                },
                _ => warn!("Invalid filter specification"),
            }
        }

        filters
    }

    /// Get filter parameters from dictionary
    fn get_filter_params(&self, filter: &Filter) -> Option<HashMap<String, Dictionary>> {
        if let Some(params) = self.dictionary.get("DecodeParms") {
            match params {
                // Single parameter dictionary
                Dictionary::Dictionary(dict) => {
                    let mut map = HashMap::new();
                    map.insert(filter.to_string(), dict.clone());
                    Some(map)
                },
                // Array of parameter dictionaries
                Dictionary::Array(array) => {
                    let mut map = HashMap::new();
                    for (i, p) in array.iter().enumerate() {
                        if let Dictionary::Dictionary(dict) = p {
                            if i < self.filters.len() {
                                map.insert(self.filters[i].to_string(), dict.clone());
                            }
                        }
                    }
                    Some(map)
                },
                _ => None,
            }
        } else {
            None
        }
    }

    /// Decode stream data
    pub fn decode(&mut self) -> PDFCryptoResult<()> {
        if self.decoded_data.is_some() {
            return Ok(());
        }

        trace!("Decoding stream with {} filters", self.filters.len());
        let mut data = self.data.clone();

        for filter in self.filters.iter().rev() {
            trace!("Applying filter: {:?}", filter);
            let params = self.get_filter_params(filter);
            data = filter.decode(&data, params.as_ref())?;
        }

        self.decoded_data = Some(data);
        Ok(())
    }

    /// Encode stream data
    pub fn encode(&mut self) -> PDFCryptoResult<()> {
        if let Some(ref decoded) = self.decoded_data {
            trace!("Encoding stream with {} filters", self.filters.len());
            let mut data = decoded.clone();

            for filter in &self.filters {
                trace!("Applying filter: {:?}", filter);
                let params = self.get_filter_params(filter);
                data = filter.encode(&data, params.as_ref())?;
            }

            self.data = data;
            self.dictionary.set("Length", self.data.len() as i64);
        }

        Ok(())
    }

    /// Update stream data
    pub fn update_data(&mut self, data: Vec<u8>) {
        self.decoded_data = Some(data);
        self.encode().unwrap_or_else(|e| warn!("Failed to encode stream: {}", e));
    }

    /// Get stream data
    pub fn get_data(&self) -> Vec<u8> {
        self.decoded_data.as_ref()
            .map(|d| d.clone())
            .unwrap_or_else(|| self.data.clone())
    }

    /// Add filter to stream
    pub fn add_filter(&mut self, filter: Filter) {
        self.filters.push(filter);
        
        // Update dictionary
        let filter_names: Vec<String> = self.filters.iter()
            .map(|f| f.to_string())
            .collect();
        
        if filter_names.len() == 1 {
            self.dictionary.set("Filter", filter_names[0].clone());
        } else {
            self.dictionary.set_array("Filter", filter_names);
        }
    }
}

impl PDFObjectCommon for Stream {
    fn write_to(&self, output: &mut Vec<u8>) {
        // Write stream dictionary
        self.dictionary.write_to(output);
        output.extend_from_slice(b"stream\n");
        
        // Write stream data
        output.extend_from_slice(&self.data);
        
        // Write stream end
        output.extend_from_slice(b"\nendstream");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    fn create_test_stream(data: &[u8], filter: Option<Filter>) -> Stream {
        let mut dict = Dictionary::new();
        dict.set("Length", data.len() as i64);
        
        if let Some(f) = filter {
            dict.set("Filter", f.to_string());
        }
        
        let mut stream = Stream::new(dict);
        stream.data = data.to_vec();
        stream
    }

    #[test]
    fn test_stream_parsing() -> PDFCryptoResult<()> {
        let data = b"<< /Length 11 >>\nstream\nHello World\nendstream";
        let mut cursor = io::Cursor::new(data);
        let mut dict = Dictionary::new();
        dict.parse(&mut cursor)?;
        
        let mut stream = Stream::new(dict);
        stream.parse(&mut cursor)?;
        
        assert_eq!(stream.data, b"Hello World");
        Ok(())
    }

    #[test]
    fn test_flate_decode() -> PDFCryptoResult<()> {
        // Create deflated test data
        let original = b"Test data for deflate compression";
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        io::Write::write_all(&mut encoder, original)?;
        let compressed = encoder.finish()?;
        
        let mut stream = create_test_stream(&compressed, Some(Filter::FlateDecode));
        stream.decode()?;
        
        assert_eq!(stream.get_data(), original);
        Ok(())
    }

    #[test]
    fn test_multiple_filters() -> PDFCryptoResult<()> {
        let mut dict = Dictionary::new();
        dict.set_array("Filter", vec![
            "FlateDecode".to_string(),
            "ASCIIHexDecode".to_string(),
        ]);
        
        let stream = Stream::new(dict);
        assert_eq!(stream.filters.len(), 2);
        assert!(matches!(stream.filters[0], Filter::FlateDecode));
        assert!(matches!(stream.filters[1], Filter::ASCIIHexDecode));
        
        Ok(())
    }

    #[test]
    fn test_stream_update() -> PDFCryptoResult<()> {
        let mut stream = create_test_stream(b"Original data", None);
        let new_data = b"Updated data".to_vec();
        
        stream.update_data(new_data.clone());
        assert_eq!(stream.get_data(), new_data);
        
        // Verify dictionary length was updated
        assert_eq!(stream.dictionary.get_integer("Length")?, new_data.len() as i64);
        
        Ok(())
    }

    #[test]
    fn test_filter_params() -> PDFCryptoResult<()> {
        let mut dict = Dictionary::new();
        dict.set("Filter", "FlateDecode");
        
        let mut params = Dictionary::new();
        params.set("Predictor", 12);
        dict.set_dict("DecodeParms", params);
        
        let stream = Stream::new(dict);
        let filter_params = stream.get_filter_params(&Filter::FlateDecode);
        
        assert!(filter_params.is_some());
        assert_eq!(
            filter_params.unwrap()
                .get("FlateDecode")
                .unwrap()
                .get_integer("Predictor")?,
            12
        );
        
        Ok(())
    }
}
