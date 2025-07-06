//! Security handlers for PDF encryption/decryption

mod standard;
mod public_key;

pub use standard::StandardSecurityHandler;
pub use public_key::PublicKeySecurityHandler;

use std::sync::Arc;
use log::{debug, warn};
use crate::error::{PDFCryptoError, PDFCryptoResult};
use crate::EncryptionAlgorithm;
use crate::pdf::Dictionary;

/// Security handler interface for PDF encryption
#[derive(Debug, Clone)]
pub enum SecurityHandler {
    /// Standard security handler (password-based)
    Standard(StandardSecurityHandler),
    /// Public key security handler (certificate-based)
    PublicKey(PublicKeySecurityHandler),
}

impl SecurityHandler {
    /// Authenticate using password
    pub fn authenticate_password(&self, password: &[u8]) -> PDFCryptoResult<Vec<u8>> {
        match self {
            SecurityHandler::Standard(handler) => {
                debug!("Authenticating with standard security handler");
                handler.authenticate_password(password)
            },
            SecurityHandler::PublicKey(_) => {
                warn!("Password authentication not supported for certificate security handler");
                Err(PDFCryptoError::UnsupportedOperation(
                    "Password authentication not supported for certificate security handler".to_string(),
                ))
            }
        }
    }

    /// Get encryption algorithm
    pub fn get_algorithm(&self) -> EncryptionAlgorithm {
        match self {
            SecurityHandler::Standard(handler) => handler.algorithm,
            SecurityHandler::PublicKey(handler) => handler.algorithm,
        }
    }

    /// Create security handler from dictionary
    pub fn from_dict(dict: &Dictionary) -> PDFCryptoResult<Self> {
        let filter = dict.get_name("Filter")?;
        match filter {
            "Standard" => Ok(SecurityHandler::Standard(StandardSecurityHandler::from_dict(dict)?)),
            "Adobe.PPKLite" | "Adobe.PPKMS" => Ok(SecurityHandler::PublicKey(PublicKeySecurityHandler::from_dict(dict)?)),
            _ => Err(PDFCryptoError::UnsupportedFilter(filter.to_string())),
        }
    }

    /// Convert security handler to dictionary
    pub fn to_dict(&self) -> Dictionary {
        match self {
            SecurityHandler::Standard(handler) => handler.to_dict(),
            SecurityHandler::PublicKey(handler) => handler.to_dict(),
        }
    }
}

/// Common security handler methods
pub(crate) trait SecurityHandlerCommon {
    /// Get encryption algorithm
    fn get_algorithm(&self) -> EncryptionAlgorithm;
    
    /// Get encryption dictionary
    fn to_dict(&self) -> Dictionary;
    
    /// Create from encryption dictionary
    fn from_dict(dict: &Dictionary) -> PDFCryptoResult<Self> where Self: Sized;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PDFPermissions;
    use test_log::test;

    #[test]
    fn test_standard_handler_creation() -> PDFCryptoResult<()> {
        let mut dict = Dictionary::new();
        dict.set_name("Filter", "Standard");
        dict.set_integer("V", 4);
        dict.set_integer("R", 4);
        dict.set_integer("Length", 128);
        dict.set_string("O", vec![1, 2, 3, 4]);
        dict.set_string("U", vec![5, 6, 7, 8]);
        dict.set_integer("P", PDFPermissions::all().bits() as i64);

        let handler = SecurityHandler::from_dict(&dict)?;
        assert!(matches!(handler, SecurityHandler::Standard(_)));
        assert_eq!(handler.get_algorithm(), EncryptionAlgorithm::AES_128);

        Ok(())
    }

    #[test]
    fn test_public_key_handler_creation() -> PDFCryptoResult<()> {
        let mut dict = Dictionary::new();
        dict.set_name("Filter", "Adobe.PPKLite");
        dict.set_integer("V", 4);
        dict.set_integer("Length", 256);
        dict.set_array("Recipients", vec![]);

        let handler = SecurityHandler::from_dict(&dict)?;
        assert!(matches!(handler, SecurityHandler::PublicKey(_)));
        assert_eq!(handler.get_algorithm(), EncryptionAlgorithm::AES_256);

        Ok(())
    }

    #[test]
    fn test_unsupported_filter() {
        let mut dict = Dictionary::new();
        dict.set_name("Filter", "Unsupported");

        let result = SecurityHandler::from_dict(&dict);
        assert!(matches!(result, Err(PDFCryptoError::UnsupportedFilter(_))));
    }

    #[test]
    fn test_handler_conversion() -> PDFCryptoResult<()> {
        let handler = StandardSecurityHandler::new(
            EncryptionAlgorithm::AES_256,
            PDFPermissions::all().bits(),
            b"user",
            b"owner",
        )?;

        let dict = SecurityHandler::Standard(handler.clone()).to_dict();
        assert_eq!(dict.get_name("Filter")?, "Standard");
        
        let reconstructed = SecurityHandler::from_dict(&dict)?;
        assert!(matches!(reconstructed, SecurityHandler::Standard(_)));

        Ok(())
    }
