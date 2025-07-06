//! PDF stream filter implementations

use std::io::{self, Read, Write};
use std::collections::HashMap;
use flate2::{Compress, Decompress};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use lzw::{LsbReader, LsbWriter, Msb, LittleEndian};
use log::{debug, trace, warn};
use crate::error::{PDFCryptoError, PDFCryptoResult};
use super::Dictionary;

/// PDF stream filters
#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    /// ASCII85 encoding
    ASCII85Decode,
    /// ASCII hex encoding
    ASCIIHexDecode,
    /// Run length encoding
    RunLengthDecode,
    /// CCITT Group 3 fax encoding
    CCITTFaxDecode,
    /// CCITT Group 4 fax encoding
    CCITTFax4Decode,
    /// JBIG2 encoding
    JBIG2Decode,
    /// DCT (JPEG) encoding
    DCTDecode,
    /// Flate (zlib) compression
    FlateDecode,
    /// LZW compression
    LZWDecode,
}

impl Filter {
    /// Create filter from name
    pub fn from_name(name: &str) -> PDFCryptoResult<Self> {
        match name {
            "ASCII85Decode" => Ok(Filter::ASCII85Decode),
            "ASCIIHexDecode" => Ok(Filter::ASCIIHexDecode),
            "RunLengthDecode" => Ok(Filter::RunLengthDecode),
            "CCITTFaxDecode" => Ok(Filter::CCITTFaxDecode),
            "CCITTFax4Decode" => Ok(Filter::CCITTFax4Decode),
            "JBIG2Decode" => Ok(Filter::JBIG2Decode),
            "DCTDecode" => Ok(Filter::DCTDecode),
            "FlateDecode" => Ok(Filter::FlateDecode),
            "LZWDecode" => Ok(Filter::LZWDecode),
            _ => Err(PDFCryptoError::UnsupportedFilter(name.to_string())),
        }
    }

    /// Decode stream data
    pub fn decode(&self, data: &[u8], params: Option<&HashMap<String, Dictionary>>) -> PDFCryptoResult<Vec<u8>> {
        match self {
            Filter::ASCII85Decode => self.decode_ascii85(data),
            Filter::ASCIIHexDecode => self.decode_ascii_hex(data),
            Filter::RunLengthDecode => self.decode_run_length(data),
            Filter::CCITTFaxDecode => self.decode_ccitt(data, params, false),
            Filter::CCITTFax4Decode => self.decode_ccitt(data, params, true),
            Filter::JBIG2Decode => self.decode_jbig2(data, params),
            Filter::DCTDecode => self.decode_dct(data, params),
            Filter::FlateDecode => self.decode_flate(data, params),
            Filter::LZWDecode => self.decode_lzw(data, params),
        }
    }

    /// Encode stream data
    pub fn encode(&self, data: &[u8], params: Option<&HashMap<String, Dictionary>>) -> PDFCryptoResult<Vec<u8>> {
        match self {
            Filter::ASCII85Decode => self.encode_ascii85(data),
            Filter::ASCIIHexDecode => self.encode_ascii_hex(data),
            Filter::RunLengthDecode => self.encode_run_length(data),
            Filter::CCITTFaxDecode => self.encode_ccitt(data, params, false),
            Filter::CCITTFax4Decode => self.encode_ccitt(data, params, true),
            Filter::JBIG2Decode => self.encode_jbig2(data, params),
            Filter::DCTDecode => self.encode_dct(data, params),
            Filter::FlateDecode => self.encode_flate(data, params),
            Filter::LZWDecode => self.encode_lzw(data, params),
        }
    }

    // ASCII85 encoding/decoding
    fn decode_ascii85(&self, data: &[u8]) -> PDFCryptoResult<Vec<u8>> {
        let mut output = Vec::new();
        let mut value: u32 = 0;
        let mut count = 0;

        for &byte in data {
            match byte {
                b'z' if count == 0 => {
                    output.extend_from_slice(&[0, 0, 0, 0]);
                }
                b'~' => break, // End marker
                b'\n' | b'\r' | b'\t' | b' ' => continue,
                b'!' ..= b'u' => {
                    value = value * 85 + ((byte - b'!') as u32);
                    count += 1;
                    if count == 5 {
                        output.extend_from_slice(&value.to_be_bytes());
                        value = 0;
                        count = 0;
                    }
                }
                _ => return Err(PDFCryptoError::MalformedPDF("Invalid ASCII85 data".to_string())),
            }
        }

        // Handle remaining bytes
        if count > 0 {
            count -= 1;
            value *= 85u32.pow(4 - count as u32);
            let bytes = value.to_be_bytes();
            output.extend_from_slice(&bytes[..count]);
        }

        Ok(output)
    }

    fn encode_ascii85(&self, data: &[u8]) -> PDFCryptoResult<Vec<u8>> {
        let mut output = Vec::new();
        let mut buffer = [0u8; 4];
        let mut count = 0;

        for chunk in data.chunks(4) {
            // Fill buffer with chunk
            buffer.fill(0);
            buffer[..chunk.len()].copy_from_slice(chunk);
            
            let value = u32::from_be_bytes(buffer);
            
            if value == 0 && chunk.len() == 4 {
                output.push(b'z');
                continue;
            }

            let mut digits = [0u8; 5];
            let mut temp = value;
            for digit in digits.iter_mut().rev() {
                *digit = (temp % 85) as u8 + b'!';
                temp /= 85;
            }

            output.extend_from_slice(&digits[..chunk.len() + 1]);
            count += chunk.len();
        }

        // Add end marker
        output.extend_from_slice(b"~>");
        Ok(output)
    }

    // ASCII Hex encoding/decoding
    fn decode_ascii_hex(&self, data: &[u8]) -> PDFCryptoResult<Vec<u8>> {
        let mut output = Vec::new();
        let mut value = 0u8;
        let mut high_digit = true;

        for &byte in data {
            match byte {
                b'0'..=b'9' | b'A'..=b'F' | b'a'..=b'f' => {
                    let digit = match byte {
                        b'0'..=b'9' => byte - b'0',
                        b'A'..=b'F' => byte - b'A' + 10,
                        b'a'..=b'f' => byte - b'a' + 10,
                        _ => unreachable!(),
                    };

                    if high_digit {
                        value = digit << 4;
                        high_digit = false;
                    } else {
                        value |= digit;
                        output.push(value);
                        high_digit = true;
                    }
                }
                b'>' => break,
                b'\n' | b'\r' | b'\t' | b' ' => continue,
                _ => return Err(PDFCryptoError::MalformedPDF("Invalid hex data".to_string())),
            }
        }

        // Handle odd number of digits
        if !high_digit {
            output.push(value);
        }

        Ok(output)
    }

    fn encode_ascii_hex(&self, data: &[u8]) -> PDFCryptoResult<Vec<u8>> {
        let mut output = Vec::with_capacity(data.len() * 2 + 2);
        
        for &byte in data {
            write!(output, "{:02X}", byte)?;
        }
        
        output.extend_from_slice(b">");
        Ok(output)
    }

    // Run Length encoding/decoding
    fn decode_run_length(&self, data: &[u8]) -> PDFCryptoResult<Vec<u8>> {
        let mut output = Vec::new();
        let mut i = 0;

        while i < data.len() {
            let length = data[i] as i8;
            i += 1;

            if length >= 0 {
                // Copy next n+1 bytes literally
                let count = length as usize + 1;
                if i + count > data.len() {
                    return Err(PDFCryptoError::MalformedPDF("Invalid run length data".to_string()));
                }
                output.extend_from_slice(&data[i..i + count]);
                i += count;
            } else if length != -128 {
                // Repeat next byte -length+1 times
                if i >= data.len() {
                    return Err(PDFCryptoError::MalformedPDF("Invalid run length data".to_string()));
                }
                let count = (-length + 1) as usize;
                output.extend(std::iter::repeat(data[i]).take(count));
                i += 1;
            }
        }

        Ok(output)
    }

    fn encode_run_length(&self, data: &[u8]) -> PDFCryptoResult<Vec<u8>> {
        let mut output = Vec::new();
        let mut i = 0;

        while i < data.len() {
            let mut run_length = 1;
            let mut literal_length = 1;

            // Look for repeated bytes
            while i + run_length < data.len() && 
                  data[i] == data[i + run_length] && 
                  run_length < 128 {
                run_length += 1;
            }

            // Look for literal sequence
            while i + literal_length < data.len() &&
                  (literal_length < 128) &&
                  (literal_length < 2 || data[i + literal_length] != data[i + literal_length - 1]) {
                literal_length += 1;
            }

            if run_length >= 3 {
                // Output run
                output.push((-(run_length as i8) + 1) as u8);
                output.push(data[i]);
                i += run_length;
            } else {
                // Output literal sequence
                output.push((literal_length - 1) as u8);
                output.extend_from_slice(&data[i..i + literal_length]);
                i += literal_length;
            }
        }

        output.push(128); // EOD marker
        Ok(output)
    }

    // CCITT Fax encoding/decoding
    fn decode_ccitt(&self, data: &[u8], params: Option<&HashMap<String, Dictionary>>, is_group4: bool) -> PDFCryptoResult<Vec<u8>> {
        // Get decode parameters
        let params = if let Some(params) = params {
            params.get(&self.to_string())
                .ok_or_else(|| PDFCryptoError::MalformedPDF("Missing CCITT parameters".to_string()))?
        } else {
            return Err(PDFCryptoError::MalformedPDF("Missing CCITT parameters".to_string()));
        };

        let k = params.get_integer("K")
            .unwrap_or(if is_group4 { -1 } else { 0 });
        let columns = params.get_integer("Columns").unwrap_or(1728) as u32;
        let rows = params.get_integer("Rows").unwrap_or(0) as u32;
        let black_is_1 = params.get_boolean("BlackIs1").unwrap_or(false);
        let encoded_byte_align = params.get_boolean("EncodedByteAlign").unwrap_or(false);

        // Create decoder configuration
        let mut decoder = fax::CCITTFaxDecoder::new(columns, rows)
            .group4(is_group4)
            .k(k)
            .black_is_1(black_is_1)
            .byte_align(encoded_byte_align);

        // Decode data
        decoder.decode(data)
            .map_err(|e| PDFCryptoError::CompressionError(e.to_string()))
    }

    fn encode_ccitt(&self, data: &[u8], params: Option<&HashMap<String, Dictionary>>, is_group4: bool) -> PDFCryptoResult<Vec<u8>> {
        // Get encode parameters (similar to decode)
        let params = if let Some(params) = params {
            params.get(&self.to_string())
                .ok_or_else(|| PDFCryptoError::MalformedPDF("Missing CCITT parameters".to_string()))?
        } else {
            return Err(PDFCryptoError::MalformedPDF("Missing CCITT parameters".to_string()));
        };

        let k = params.get_integer("K")
            .unwrap_or(if is_group4 { -1 } else { 0 });
        let columns = params.get_integer("Columns").unwrap_or(1728) as u32;
        let rows = params.get_integer("Rows").unwrap_or(0) as u32;
        let black_is_1 = params.get_boolean("BlackIs1").unwrap_or(false);
        let encoded_byte_align = params.get_boolean("EncodedByteAlign").unwrap_or(false);

        // Create encoder configuration
        let mut encoder = fax::CCITTFaxEncoder::new(columns, rows)
            .group4(is_group4)
            .k(k)
            .black_is_1(black_is_1)
            .byte_align(encoded_byte_align);

        // Encode data
        encoder.encode(data)
            .map_err(|e| PDFCryptoError::CompressionError(e.to_string()))
    }

    // JBIG2 encoding/decoding
    fn decode_jbig2(&self, data: &[u8], params: Option<&HashMap<String, Dictionary>>) -> PDFCryptoResult<Vec<u8>> {
        // Get global stream if available
        let global_stream = if let Some(params) = params {
            params.get(&self.to_string())
                .and_then(|dict| dict.get_stream("JBIG2Globals"))
        } else {
            None
        };

        // Create decoder
        let mut decoder = jbig2::Decoder::new()
            .map_err(|e| PDFCryptoError::CompressionError(e.to_string()))?;

        // Add global segments if available
        if let Some(globals) = global_stream {
            decoder.process_globals(&globals)
                .map_err(|e| PDFCryptoError::CompressionError(e.to_string()))?;
        }

        // Decode data
        decoder.process_segments(data)
            .map_err(|e| PDFCryptoError::CompressionError(e.to_string()))
    }

    fn encode_jbig2(&self, data: &[u8], _params: Option<&HashMap<String, Dictionary>>) -> PDFCryptoResult<Vec<u8>> {
        // JBIG2 encoding is typically not performed on the fly
        // as it requires sophisticated image analysis
        Err(PDFCryptoError::UnsupportedOperation("JBIG2 encoding not supported".to_string()))
    }

    // DCT (JPEG) encoding/decoding
    fn decode_dct(&self, data: &[u8], _params: Option<&HashMap<String, Dictionary>>) -> PDFCryptoResult<Vec<u8>> {
        let mut decoder = jpeg_decoder::Decoder::new(io::Cursor::new(data));
        decoder.decode()
            .map_err(|e| PDFCryptoError::CompressionError(e.to_string()))
    }

    fn encode_dct(&self, data: &[u8], params: Option<&HashMap<String, Dictionary>>) -> PDFCryptoResult<Vec<u8>> {
        let quality = if let Some(params) = params {
            params.get(&self.to_string())
                .and_then(|dict| dict.get_integer("Quality"))
                .unwrap_or(75) as u8
        } else {
            75
        };

        let mut encoder = jpeg_encoder::Encoder::new_with_quality(Vec::new(), quality);
        encoder.encode(data)
            .map_err(|e| PDFCryptoError::CompressionError(e.to_string()))
    }

    // Flate (zlib) compression/decompression
    fn decode_flate(&self, data: &[u8], params: Option<&HashMap<String, Dictionary>>) -> PDFCryptoResult<Vec<u8>> {
        let mut decoder = Decompress::new(true);
        let mut output = Vec::new();
        
        decoder.decompress_vec(data, &mut output, flate2::FlushDecompress::Finish)
            .map_err(|e| PDFCryptoError::CompressionError(e.to_string()))?;

        // Apply predictor if specified
        if let Some(params) = params {
            if let Some(dict) = params.get(&self.to_string()) {
                if let Some(predictor) = dict.get_integer("Predictor") {
                    output = self.apply_predictor(&output, predictor as u8, params)?;
                }
            }
        }

        Ok(output)
    }

    fn encode_flate(&self, data: &[u8], params: Option<&HashMap<String, Dictionary>>) -> PDFCryptoResult<Vec<u8>> {
        let mut encoder = Compress::new(flate2::Compression::default(), true);
        let mut output = Vec::new();
        
        encoder.compress_vec(data, &mut output, flate2::FlushCompress::Finish)
            .map_err(|e| PDFCryptoError::CompressionError(e.to_string()))?;

        Ok(output)
    }

    // LZW compression/decompression
    fn decode_lzw(&self, data: &[u8], params: Option<&HashMap<String, Dictionary>>) -> PDFCryptoResult<Vec<u8>> {
        let mut decoder = LzwDecoder::new();
        let output = decoder.decode(data)
            .map_err(|e| PDFCryptoError::CompressionError(e.to_string()))?;

        // Apply predictor if specified
        if let Some(params) = params {
            if let Some(dict) = params.get(&self.to_string()) {
                if let Some(predictor) = dict.get_integer("Predictor") {
                    return self.apply_predictor(&output, predictor as u8, params);
                }
            }
        }

        Ok(output)
    }

    fn encode_lzw(&self, data: &[u8], _params: Option<&HashMap<String, Dictionary>>) -> PDFCryptoResult<Vec<u8>> {
        let mut encoder = LzwEncoder::new();
        encoder.encode(data)
            .map_err(|e| PDFCryptoError::CompressionError(e.to_string()))
    }

    // Predictor handling
    fn apply_predictor(&self, data: &[u8], predictor: u8, params: Option<&HashMap<String, Dictionary>>) -> PDFCryptoResult<Vec<u8>> {
        let params = params.and_then(|p| p.get(&self.to_string()));
        
        let columns = params.and_then(|d| d.get_integer("Columns")).unwrap_or(1) as usize;
        let colors = params.and_then(|d| d.get_integer("Colors")).unwrap_or(1) as usize;
        let bits_per_component = params.and_then(|d| d.get_integer("BitsPerComponent")).unwrap_or(8) as usize;
        
        let bytes_per_pixel = (colors * bits_per_component + 7) / 8;
        let bytes_per_row = (columns * colors * bits_per_component + 7) / 8;
        
        let mut output = Vec::with_capacity(data.len());
        
        match predictor {
            1 => Ok(data.to_vec()), // No prediction
            2 => { // TIFF Predictor
                for row in data.chunks(bytes_per_row) {
                    let mut prev = vec![0; bytes_per_pixel];
                    for pixel in row.chunks(bytes_per_pixel) {
                        for (i, &byte) in pixel.iter().enumerate() {
                            output.push(byte.wrapping_add(prev[i]));
                            prev[i] = byte;
                        }
                    }
                }
                Ok(output)
            },
            10..=15 => { // PNG Predictors
                let mut prev_row = vec![0; bytes_per_row];
                
                for row in data.chunks(bytes_per_row + 1) {
                    let filter_type = row[0];
                    let row_data = &row[1..];
                    
                    match filter_type {
                        0 => output.extend_from_slice(row_data), // None
                        1 => { // Sub
                            let mut result = vec![0; bytes_per_row];
                            for i in 0..bytes_per_row {
                                let left = if i >= bytes_per_pixel { result[i - bytes_per_pixel] } else { 0 };
                                result[i] = row_data[i].wrapping_add(left);
                            }
                            output.extend_from_slice(&result);
                        },
                        2 => { // Up
                            let mut result = vec![0; bytes_per_row];
                            for i in 0..bytes_per_row {
                                result[i] = row_data[i].wrapping_add(prev_row[i]);
                            }
                            output.extend_from_slice(&result);
                        },
                        3 => { // Average
                            let mut result = vec![0; bytes_per_row];
                            for i in 0..bytes_per_row {
                                let left = if i >= bytes_per_pixel { result[i - bytes_per_pixel] } else { 0 };
                                let up = prev_row[i];
                                result[i] = row_data[i].wrapping_add((left.wrapping_add(up)) / 2);
                            }
                            output.extend_from_slice(&result);
                        },
                        4 => { // Paeth
                            let mut result = vec![0; bytes_per_row];
                            for i in 0..bytes_per_row {
                                let left = if i >= bytes_per_pixel { result[i - bytes_per_pixel] } else { 0 };
                                let up = prev_row[i];
                                let up_left = if i >= bytes_per_pixel { prev_row[i - bytes_per_pixel] } else { 0 };
                                
                                let p = left.wrapping_add(up).wrapping_sub(up_left);
                                let pa = p.wrapping_sub(left).abs();
                                let pb = p.wrapping_sub(up).abs();
                                let pc = p.wrapping_sub(up_left).abs();
                                
                                let predictor = if pa <= pb && pa <= pc {
                                    left
                                } else if pb <= pc {
                                    up
                                } else {
                                    up_left
                                };
                                
                                result[i] = row_data[i].wrapping_add(predictor);
                            }
                            output.extend_from_slice(&result);
                        },
                        _ => return Err(PDFCryptoError::MalformedPDF("Invalid PNG filter type".to_string())),
                    }
                    
                    prev_row.copy_from_slice(&output[output.len() - bytes_per_row..]);
                }
                Ok(output)
            },
            _ => Err(PDFCryptoError::MalformedPDF("Invalid predictor".to_string())),
        }
    }
}

impl ToString for Filter {
    fn to_string(&self) -> String {
        match self {
            Filter::ASCII85Decode => "ASCII85Decode",
            Filter::ASCIIHexDecode => "ASCIIHexDecode",
            Filter::RunLengthDecode => "RunLengthDecode",
            Filter::CCITTFaxDecode => "CCITTFaxDecode",
            Filter::CCITTFax4Decode => "CCITTFax4Decode",
            Filter::JBIG2Decode => "JBIG2Decode",
            Filter::DCTDecode => "DCTDecode",
            Filter::FlateDecode => "FlateDecode",
            Filter::LZWDecode => "LZWDecode",
        }.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    #[test]
    fn test_ascii85_codec() -> PDFCryptoResult<()> {
        let filter = Filter::ASCII85Decode;
        let original = b"Hello, World!";
        
        let encoded = filter.encode_ascii85(original)?;
        let decoded = filter.decode_ascii85(&encoded)?;
        
        assert_eq!(decoded, original);
        Ok(())
    }

    #[test]
    fn test_ascii_hex_codec() -> PDFCryptoResult<()> {
        let filter = Filter::ASCIIHexDecode;
        let original = b"Test Data";
        
        let encoded = filter.encode_ascii_hex(original)?;
        let decoded = filter.decode_ascii_hex(&encoded)?;
        
        assert_eq!(decoded, original);
        Ok(())
    }

    #[test]
    fn test_run_length_codec() -> PDFCryptoResult<()> {
        let filter = Filter::RunLengthDecode;
        let original = b"AAAAABBBCC";
        
        let encoded = filter.encode_run_length(original)?;
        let decoded = filter.decode_run_length(&encoded)?;
        
        assert_eq!(decoded, original);
        Ok(())
    }

    #[test]
    fn test_flate_codec() -> PDFCryptoResult<()> {
        let filter = Filter::FlateDecode;
        let original = b"Test compression with some repeated content";
        
        let encoded = filter.encode_flate(original, None)?;
        let decoded = filter.decode_flate(&encoded, None)?;
        
        assert_eq!(decoded, original);
        Ok(())
    }

    #[test]
    fn test_lzw_codec() -> PDFCryptoResult<()> {
        let filter = Filter::LZWDecode;
        let original = b"Test LZW compression";
        
        let encoded = filter.encode_lzw(original, None)?;
        let decoded = filter.decode_lzw(&encoded, None)?;
        
        assert_eq!(decoded, original);
        Ok(())
    }

    #[test]
    fn test_predictor() -> PDFCryptoResult<()> {
        let filter = Filter::FlateDecode;
        let original = b"Test data with predictor";
        
        let mut params = HashMap::new();
        let mut dict = Dictionary::new();
        dict.set("Predictor", 12);
        dict.set("Columns", 4);
        params.insert("FlateDecode".to_string(), dict);
        
        let encoded = filter.encode_flate(original, Some(&params))?;
        let decoded = filter.decode_flate(&encoded, Some(&params))?;
        
        assert_eq!(decoded, original);
        Ok(())
    }
}
