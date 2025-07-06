//! Error types for PDF crypto library

use std::fmt;
use std::io;
use thiserror::Error;
use crate::EncryptionAlgorithm;

/// Main error type for PDF crypto operations
#[derive(Error, Debug)]
pub enum PDFCryptoError {
    /// Authentication failed (wrong password)
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Unsupported encryption filter
    #[error("Unsupported encryption filter: {0}")]
    UnsupportedFilter(String),

    /// Unsupported encryption revision
    #[error("Unsupported revision: {0}")]
    UnsupportedRevision(u8),

    /// Invalid key length
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),

    /// Unsupported key length
    #[error("Unsupported key length: {0}")]
    UnsupportedKeyLength(usize),

    /// Invalid data length
    #[error("Invalid data length for {operation}")]
    InvalidDataLength {
        operation: String,
    },

    /// Malformed PDF structure
    #[error("Malformed PDF structure: {0}")]
    MalformedPDF(String),

    /// Certificate error
    #[error("Certificate error: {0}")]
    CertificateError(String),

    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// No private key available
    #[error("No private key available")]
    NoPrivateKey,

    /// Invalid permissions
    #[error("Invalid permissions: {0}")]
    InvalidPermissions(u32),

    /// Object not found
    #[error("Object not found: {0}")]
    ObjectNotFound(u32),

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(EncryptionAlgorithm),

    /// Unsupported operation
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// Invalid object type
    #[error("Invalid object type: expected {expected}, found {found}")]
    InvalidObjectType {
        expected: &'static str,
        found: &'static str,
    },

    /// Missing required dictionary entry
    #[error("Missing required dictionary entry: {0}")]
    MissingDictionaryEntry(String),

    /// Invalid dictionary value
    #[error("Invalid dictionary value for key {key}: {message}")]
    InvalidDictionaryValue {
        key: String,
        message: String,
    },

    /// Stream error
    #[error("Stream error: {0}")]
    StreamError(String),

    /// Compression error
    #[error("Compression error: {0}")]
    CompressionError(String),

    /// Invalid password
    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    /// Cross reference table error
    #[error("Cross reference table error: {0}")]
    XRefError(String),

    /// Invalid file format
    #[error("Invalid file format: {0}")]
    InvalidFormat(String),

    /// Buffer overflow
    #[error("Buffer overflow in {operation}")]
    BufferOverflow {
        operation: String,
    },

    /// Memory allocation error
    #[error("Memory allocation error: {0}")]
    MemoryError(String),

    /// Encryption setup error
    #[error("Encryption setup error: {0}")]
    EncryptionSetupError(String),

    /// Key derivation error
    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    /// UTF-8 encoding error
    #[error("UTF-8 encoding error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    /// Integer parsing error
    #[error("Integer parsing error: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),

    /// Float parsing error
    #[error("Float parsing error: {0}")]
    ParseFloatError(#[from] std::num::ParseFloatError),

    /// RSA error
    #[error("RSA error: {0}")]
    RsaError(String),

    /// AES error
    #[error("AES error: {0}")]
    AesError(String),

    /// RC4 error
    #[error("RC4 error: {0}")]
    Rc4Error(String),
}

/// Result type for PDF crypto operations
pub type PDFCryptoResult<T> = Result<T, PDFCryptoError>;

impl PDFCryptoError {
    /// Create a new malformed PDF error
    pub fn malformed(msg: impl Into<String>) -> Self {
        Self::MalformedPDF(msg.into())
    }

    /// Create a new crypto error
    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::CryptoError(msg.into())
    }

    /// Create a new certificate error
    pub fn certificate(msg: impl Into<String>) -> Self {
        Self::CertificateError(msg.into())
    }

    /// Create a new invalid data length error
    pub fn invalid_length(operation: impl Into<String>) -> Self {
        Self::InvalidDataLength {
            operation: operation.into(),
        }
    }

    /// Create a new buffer overflow error
    pub fn buffer_overflow(operation: impl Into<String>) -> Self {
        Self::BufferOverflow {
            operation: operation.into(),
        }
    }

    /// Create a new invalid dictionary value error
    pub fn invalid_dict_value(key: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::InvalidDictionaryValue {
            key: key.into(),
            message: msg.into(),
        }
    }

    /// Check if error is authentication related
    pub fn is_auth_error(&self) -> bool {
        matches!(self, 
            Self::AuthenticationFailed |
            Self::InvalidPassword(_) |
            Self::NoPrivateKey
        )
    }

    /// Check if error is cryptographic
    pub fn is_crypto_error(&self) -> bool {
        matches!(self,
            Self::CryptoError(_) |
            Self::RsaError(_) |
            Self::AesError(_) |
            Self::Rc4Error(_) |
            Self::KeyDerivationError(_)
        )
    }

    /// Check if error is related to PDF structure
    pub fn is_structure_error(&self) -> bool {
        matches!(self,
            Self::MalformedPDF(_) |
            Self::InvalidFormat(_) |
            Self::XRefError(_) |
            Self::ObjectNotFound(_)
        )
    }
}

impl From<rsa::errors::Error> for PDFCryptoError {
    fn from(err: rsa::errors::Error) -> Self {
        Self::RsaError(err.to_string())
    }
}

impl From<aes::cipher::InvalidLength> for PDFCryptoError {
    fn from(err: aes::cipher::InvalidLength) -> Self {
        Self::AesError(err.to_string())
    }
}

impl From<block_modes::BlockModeError> for PDFCryptoError {
    fn from(err: block_modes::BlockModeError) -> Self {
        Self::AesError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = PDFCryptoError::malformed("Invalid header");
        assert!(matches!(err, PDFCryptoError::MalformedPDF(_)));

        let err = PDFCryptoError::crypto("Key generation failed");
        assert!(matches!(err, PDFCryptoError::CryptoError(_)));

        let err = PDFCryptoError::invalid_length("AES encryption");
        assert!(matches!(err, PDFCryptoError::InvalidDataLength { .. }));
    }

    #[test]
    fn test_error_categorization() {
        let auth_err = PDFCryptoError::AuthenticationFailed;
        assert!(auth_err.is_auth_error());
        assert!(!auth_err.is_crypto_error());

        let crypto_err = PDFCryptoError::CryptoError("test".to_string());
        assert!(crypto_err.is_crypto_error());
        assert!(!crypto_err.is_structure_error());

        let struct_err = PDFCryptoError::MalformedPDF("test".to_string());
        assert!(struct_err.is_structure_error());
        assert!(!struct_err.is_auth_error());
    }

    #[test]
    fn test_error_display() {
        let err = PDFCryptoError::InvalidKeyLength(32);
        assert_eq!(err.to_string(), "Invalid key length: 32");

        let err = PDFCryptoError::InvalidDictionaryValue {
            key: "Type".to_string(),
            message: "Expected string".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Invalid dictionary value for key Type: Expected string"
        );
    }

    #[test]
    fn test_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let pdf_err: PDFCryptoError = io_err.into();
        assert!(matches!(pdf_err, PDFCryptoError::IoError(_)));

        let int_err = "abc".parse::<i32>().unwrap_err();
        let pdf_err: PDFCryptoError = int_err.into();
        assert!(matches!(pdf_err, PDFCryptoError::ParseIntError(_)));
    }
}
