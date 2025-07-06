//! Security handlers for PDF encryption/decryption

mod standard;
mod public_key;

pub use standard::StandardSecurityHandler;
pub use public_key::PublicKeySecurityHandler;

use crate::error::PDFCryptoError;
use crate::EncryptionAlgorithm;
use crate::pdf::Dictionary;
use log::debug;

/// Security handler interface for PDF encryption
#[derive(Debug, Clone)]
pub enum SecurityHandler {
    /// Standard password-based security handler
    Standard(StandardSecurityHandler),
    /// Public key (certificate-based) security handler
    PublicKey(PublicKeySecurityHandler),
}

impl SecurityHandler {
    /// Authenticate with password
    pub fn authenticate_password(&self, password: &[u8]) -> Result<Vec<u8>, PDFCryptoError> {
        debug!("Attempting password authentication");
        match self {
            SecurityHandler::Standard(handler) => handler.authenticate_password(password),
            SecurityHandler::PublicKey(_) => Err(PDFCryptoError::UnsupportedOperation(
                "Password authentication not supported for certificate security handler".to_string(),
            )),
        }
    }

    /// Get encryption algorithm
    pub fn get_algorithm(&self) -> EncryptionAlgorithm {
        match self {
            SecurityHandler::Standard(handler) => handler.algorithm,
            SecurityHandler::PublicKey(handler) => handler.algorithm,
        }
    }

    /// Create dictionary representation
    pub fn to_dict(&self) -> Dictionary {
        match self {
            SecurityHandler::Standard(handler) => handler.to_dict(),
            SecurityHandler::PublicKey(handler) => handler.to_dict(),
        }
    }
}
