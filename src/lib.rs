//! PDF Crypto Library for Rust
//! 
//! A comprehensive implementation for PDF encryption/decryption following the PDF specification.
//! Supports both password-based and certificate-based encryption methods.

#![forbid(unsafe_code)]
#![deny(missing_docs, missing_debug_implementations)]
#![warn(rust_2018_idioms)]

use std::fmt;
use std::sync::Arc;

pub mod error;
pub mod handlers;
pub mod crypto;
pub mod pdf;
pub mod utils;

pub use error::{PDFCryptoError, PDFCryptoResult};
use handlers::{SecurityHandler, StandardSecurityHandler, PublicKeySecurityHandler};
use crypto::PDFCryptoEngine;
use pdf::PDFParser;

/// Supported encryption algorithms for PDF encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionAlgorithm {
    /// RC4 encryption with 40-bit key (PDF 1.3)
    RC4_40,
    /// RC4 encryption with 128-bit key (PDF 1.4)
    RC4_128,
    /// AES encryption with 128-bit key (PDF 1.6)
    AES_128,
    /// AES encryption with 256-bit key (PDF 1.7+/2.0)
    AES_256,
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionAlgorithm::RC4_40 => write!(f, "RC4-40"),
            EncryptionAlgorithm::RC4_128 => write!(f, "RC4-128"),
            EncryptionAlgorithm::AES_128 => write!(f, "AES-128"),
            EncryptionAlgorithm::AES_256 => write!(f, "AES-256"),
        }
    }
}

/// PDF permissions flags
#[derive(Debug, Clone, Copy)]
pub struct PDFPermissions(u32);

impl PDFPermissions {
    /// No permissions
    pub const NONE: u32 = 0;
    /// Print the document (bit 3)
    pub const PRINT: u32 = 1 << 2;
    /// Modify the document contents (bit 4)
    pub const MODIFY: u32 = 1 << 3;
    /// Copy text and graphics (bit 5)
    pub const COPY: u32 = 1 << 4;
    /// Add or modify annotations (bit 6)
    pub const ANNOTATE: u32 = 1 << 5;
    /// Fill form fields (bit 9)
    pub const FILL_FORMS: u32 = 1 << 8;
    /// Extract text and graphics (bit 10)
    pub const EXTRACT: u32 = 1 << 9;
    /// Assemble the document (bit 11)
    pub const ASSEMBLE: u32 = 1 << 10;
    /// Print in high quality (bit 12)
    pub const PRINT_HIGH: u32 = 1 << 11;
    /// All permissions
    pub const ALL: u32 = 0xF_FFFF;

    /// Create new permissions from raw bits
    pub fn new(bits: u32) -> Self {
        Self(bits & Self::ALL)
    }

    /// Get raw permission bits
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Check if specific permission is granted
    pub fn has_permission(&self, permission: u32) -> bool {
        (self.0 & permission) == permission
    }

    /// Create permissions with all flags set
    pub fn all() -> Self {
        Self(Self::ALL)
    }

    /// Create permissions with no flags set
    pub fn none() -> Self {
        Self(Self::NONE)
    }
}

impl Default for PDFPermissions {
    fn default() -> Self {
        Self::none()
    }
}

/// Main PDF encryption/decryption interface
#[derive(Debug, Clone)]
pub struct PDFCrypto {
    engine: Arc<PDFCryptoEngine>,
}

impl Default for PDFCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl PDFCrypto {
    /// Create a new PDFCrypto instance
    pub fn new() -> Self {
        Self {
            engine: Arc::new(PDFCryptoEngine::new()),
        }
    }

    /// Decrypt PDF with user password
    pub fn decrypt_with_password(
        &self,
        pdf_data: &[u8],
        password: &str,
    ) -> PDFCryptoResult<Vec<u8>> {
        let mut parser = PDFParser::new(pdf_data)?;
        let encryption_dict = parser.get_encryption_dictionary()?;
        
        let handler = match encryption_dict.get_name("Filter")? {
            "Standard" => SecurityHandler::Standard(
                StandardSecurityHandler::from_dict(&encryption_dict)?
            ),
            "Adobe.PPKLite" | "Adobe.PPKMS" => SecurityHandler::PublicKey(
                PublicKeySecurityHandler::from_dict(&encryption_dict)?
            ),
            filter => return Err(PDFCryptoError::UnsupportedFilter(filter.to_string())),
        };

        let file_key = handler.authenticate_password(password.as_bytes())?;
        self.engine.decrypt_pdf_objects(&mut parser, &file_key, &handler)?;
        
        Ok(parser.rebuild_pdf())
    }

    /// Encrypt PDF with password
    pub fn encrypt_with_password(
        &self,
        pdf_data: &[u8],
        user_password: &str,
        owner_password: &str,
        permissions: PDFPermissions,
        algorithm: EncryptionAlgorithm,
    ) -> PDFCryptoResult<Vec<u8>> {
        let mut parser = PDFParser::new(pdf_data)?;
        
        let handler = StandardSecurityHandler::new(
            algorithm,
            permissions.bits(),
            user_password.as_bytes(),
            owner_password.as_bytes(),
        )?;

        let file_key = handler.generate_file_key()?;
        self.engine.encrypt_pdf_objects(&mut parser, &file_key, &SecurityHandler::Standard(handler.clone()))?;
        
        parser.add_encryption_dictionary(handler.to_dict())?;
        
        Ok(parser.rebuild_pdf())
    }

    /// Decrypt PDF with certificate
    pub fn decrypt_with_certificate(
        &self,
        pdf_data: &[u8],
        certificate_data: &[u8],
        private_key_data: &[u8],
    ) -> PDFCryptoResult<Vec<u8>> {
        let mut parser = PDFParser::new(pdf_data)?;
        let encryption_dict = parser.get_encryption_dictionary()?;
        
        let mut handler = PublicKeySecurityHandler::from_dict(&encryption_dict)?;
        handler.set_decryption_key(certificate_data, private_key_data)?;
        
        let file_key = handler.get_file_key()?;
        self.engine.decrypt_pdf_objects(&mut parser, &file_key, &SecurityHandler::PublicKey(handler))?;
        
        Ok(parser.rebuild_pdf())
    }

    /// Encrypt PDF with certificates
    pub fn encrypt_with_certificates(
        &self,
        pdf_data: &[u8],
        certificates: &[&[u8]],
        permissions: PDFPermissions,
        algorithm: EncryptionAlgorithm,
    ) -> PDFCryptoResult<Vec<u8>> {
        let mut parser = PDFParser::new(pdf_data)?;
        
        let mut handler = PublicKeySecurityHandler::new(algorithm)?;
        for cert_data in certificates {
            handler.add_recipient(cert_data, permissions)?;
        }

        let file_key = handler.generate_file_key()?;
        self.engine.encrypt_pdf_objects(&mut parser, &file_key, &SecurityHandler::PublicKey(handler.clone()))?;
        
        parser.add_encryption_dictionary(handler.to_dict())?;
        
        Ok(parser.rebuild_pdf())
    }

    /// Get encryption information from PDF
    pub fn get_encryption_info(&self, pdf_data: &[u8]) -> PDFCryptoResult<EncryptionInfo> {
        let parser = PDFParser::new(pdf_data)?;
        
        if let Ok(dict) = parser.get_encryption_dictionary() {
            Ok(EncryptionInfo {
                algorithm: dict.get_algorithm()?,
                is_encrypted: true,
                encryption_type: match dict.get_name("Filter")? {
                    "Standard" => EncryptionType::Password,
                    "Adobe.PPKLite" | "Adobe.PPKMS" => EncryptionType::Certificate,
                    _ => EncryptionType::Unknown,
                },
            })
        } else {
            Ok(EncryptionInfo {
                algorithm: EncryptionAlgorithm::RC4_40, // Default
                is_encrypted: false,
                encryption_type: EncryptionType::Unknown,
            })
        }
    }
}

/// Information about PDF encryption
#[derive(Debug, Clone)]
pub struct EncryptionInfo {
    /// The encryption algorithm used
    pub algorithm: EncryptionAlgorithm,
    /// Whether the PDF is encrypted
    pub is_encrypted: bool,
    /// Type of encryption used
    pub encryption_type: EncryptionType,
}

/// Type of encryption used in PDF
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionType {
    /// Password-based encryption
    Password,
    /// Certificate-based encryption
    Certificate,
    /// Unknown encryption type
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const TEST_FILES_DIR: &str = "tests/files";

    fn setup() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_permissions() {
        let perms = PDFPermissions::new(PDFPermissions::PRINT | PDFPermissions::COPY);
        assert!(perms.has_permission(PDFPermissions::PRINT));
        assert!(perms.has_permission(PDFPermissions::COPY));
        assert!(!perms.has_permission(PDFPermissions::MODIFY));
    }

    #[test]
    fn test_password_encryption() -> PDFCryptoResult<()> {
        setup();
        let pdf_crypto = PDFCrypto::new();
        let sample_pdf = fs::read(format!("{}/sample.pdf", TEST_FILES_DIR))?;
        
        // Test encryption
        let encrypted = pdf_crypto.encrypt_with_password(
            &sample_pdf,
            "user123",
            "owner123",
            PDFPermissions::new(PDFPermissions::ALL),
            EncryptionAlgorithm::AES_256,
        )?;
        
        // Verify encryption
        let info = pdf_crypto.get_encryption_info(&encrypted)?;
        assert!(info.is_encrypted);
        assert_eq!(info.algorithm, EncryptionAlgorithm::AES_256);
        assert_eq!(info.encryption_type, EncryptionType::Password);
        
        // Test decryption
        let decrypted = pdf_crypto.decrypt_with_password(&encrypted, "user123")?;
        assert_eq!(sample_pdf, decrypted);
        
        Ok(())
    }

    #[test]
    fn test_certificate_encryption() -> PDFCryptoResult<()> {
        setup();
        let pdf_crypto = PDFCrypto::new();
        let sample_pdf = fs::read(format!("{}/sample.pdf", TEST_FILES_DIR))?;
        let cert_data = fs::read(format!("{}/test_cert.der", TEST_FILES_DIR))?;
        let key_data = fs::read(format!("{}/test_key.der", TEST_FILES_DIR))?;
        
        // Test encryption
        let encrypted = pdf_crypto.encrypt_with_certificates(
            &sample_pdf,
            &[&cert_data],
            PDFPermissions::new(PDFPermissions::ALL),
            EncryptionAlgorithm::AES_256,
        )?;
        
        // Verify encryption
        let info = pdf_crypto.get_encryption_info(&encrypted)?;
        assert!(info.is_encrypted);
        assert_eq!(info.algorithm, EncryptionAlgorithm::AES_256);
        assert_eq!(info.encryption_type, EncryptionType::Certificate);
        
        // Test decryption
        let decrypted = pdf_crypto.decrypt_with_certificate(&encrypted, &cert_data, &key_data)?;
        assert_eq!(sample_pdf, decrypted);
        
        Ok(())
    }

    #[test]
    fn test_invalid_password() {
        setup();
        let pdf_crypto = PDFCrypto::new();
        let sample_pdf = fs::read(format!("{}/encrypted.pdf", TEST_FILES_DIR)).unwrap();
        
        let result = pdf_crypto.decrypt_with_password(&sample_pdf, "wrong_password");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PDFCryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_encryption_info() -> PDFCryptoResult<()> {
        setup();
        let pdf_crypto = PDFCrypto::new();
        
        // Test unencrypted PDF
        let sample_pdf = fs::read(format!("{}/sample.pdf", TEST_FILES_DIR))?;
        let info = pdf_crypto.get_encryption_info(&sample_pdf)?;
        assert!(!info.is_encrypted);
        
        // Test encrypted PDF
        let encrypted_pdf = fs::read(format!("{}/encrypted.pdf", TEST_FILES_DIR))?;
        let info = pdf_crypto.get_encryption_info(&encrypted_pdf)?;
        assert!(info.is_encrypted);
        assert_eq!(info.encryption_type, EncryptionType::Password);
        
        Ok(())
    }
}
