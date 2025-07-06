//! Security handlers for PDF encryption/decryption

mod standard;
mod public_key;

pub use standard::StandardSecurityHandler;
pub use public_key::PublicKeySecurityHandler;

use crate::error::PDFCryptoError;
use crate::EncryptionAlgorithm;

/// Security handler interface for PDF encryption
#[derive(Clone)]
pub enum SecurityHandler {
    Standard(StandardSecurityHandler),
    PublicKey(PublicKeySecurityHandler),
}

impl SecurityHandler {
    pub fn authenticate_password(&self, password: &[u8]) -> Result<Vec<u8>, PDFCryptoError> {
        match self {
            SecurityHandler::Standard(handler) => handler.authenticate_password(password),
            SecurityHandler::PublicKey(_) => Err(PDFCryptoError::UnsupportedOperation(
                "Password authentication not supported for certificate security handler".to_string(),
            )),
        }
    }

    pub fn get_algorithm(&self) -> EncryptionAlgorithm {
        match self {
            SecurityHandler::Standard(handler) => handler.algorithm,
            SecurityHandler::PublicKey(handler) => handler.algorithm,
        }
    }
}
