//! PDF cryptographic engine implementation

mod rc4;
mod aes;
mod engine;

pub use engine::PDFCryptoEngine;
use crate::error::PDFCryptoError;
use crate::EncryptionAlgorithm;

/// Trait for PDF object encryption/decryption
pub(crate) trait CryptoProvider: Send + Sync {
    fn process_data(&self, data: &mut [u8], key: &[u8]) -> Result<(), PDFCryptoError>;
}
