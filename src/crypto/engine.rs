//! Core cryptographic engine implementation

use std::sync::Arc;
use std::collections::HashMap;
use md5::{Md5, Digest};
use rand::{thread_rng, RngCore};
use log::{debug, warn};

use crate::error::{PDFCryptoError, PDFCryptoResult};
use crate::EncryptionAlgorithm;
use crate::handlers::SecurityHandler;
use crate::pdf::PDFParser;
use super::{rc4, aes, CryptoProvider};

/// Core engine for PDF encryption/decryption operations
#[derive(Debug)]
pub struct PDFCryptoEngine {
    providers: Arc<ProvidersMap>,
}

type ProvidersMap = HashMap<EncryptionAlgorithm, Box<dyn CryptoProvider>>;

impl PDFCryptoEngine {
    /// Create new cryptographic engine instance
    pub fn new() -> Self {
        debug!("Initializing PDF cryptographic engine");
        let mut providers = HashMap::new();
        
        providers.insert(EncryptionAlgorithm::RC4_40, 
            Box::new(rc4::RC4Provider::new(5)) as Box<dyn CryptoProvider>);
        providers.insert(EncryptionAlgorithm::RC4_128,
            Box::new(rc4::RC4Provider::new(16)) as Box<dyn CryptoProvider>);
        providers.insert(EncryptionAlgorithm::AES_128,
            Box::new(aes::AESProvider::new(16)) as Box<dyn CryptoProvider>);
        providers.insert(EncryptionAlgorithm::AES_256,
            Box::new(aes::AESProvider::new(32)) as Box<dyn CryptoProvider>);

        Self {
            providers: Arc::new(providers),
        }
    }

    /// Decrypt PDF objects in place
    pub fn decrypt_pdf_objects(
        &self,
        parser: &mut PDFParser,
        file_key: &[u8],
        handler: &SecurityHandler,
    ) -> PDFCryptoResult<()> {
        debug!("Starting PDF object decryption");
        let algorithm = handler.get_algorithm();
        let provider = self.get_provider(algorithm)?;

        // Process each encrypted object
        for obj in parser.get_encrypted_objects()? {
            debug!("Decrypting object {}", obj.number);
            let mut data = obj.data.clone();
            let object_key = self.generate_object_key(
                file_key,
                obj.number,
                obj.generation,
                algorithm,
            )?;

            provider.process_data(&mut data, &object_key)?;
            parser.update_object_data(obj.number, data)?;
        }

        debug!("PDF object decryption completed");
        Ok(())
    }

    /// Encrypt PDF objects in place
    pub fn encrypt_pdf_objects(
        &self,
        parser: &mut PDFParser,
        file_key: &[u8],
        handler: &SecurityHandler,
    ) -> PDFCryptoResult<()> {
        debug!("Starting PDF object encryption");
        let algorithm = handler.get_algorithm();
        let provider = self.get_provider(algorithm)?;

        // Process each object that needs encryption
        for obj in parser.get_encryptable_objects()? {
            debug!("Encrypting object {}", obj.number);
            let mut data = obj.data.clone();
            let object_key = self.generate_object_key(
                file_key,
                obj.number,
                obj.generation,
                algorithm,
            )?;

            provider.process_data(&mut data, &object_key)?;
            parser.update_object_data(obj.number, data)?;
        }

        debug!("PDF object encryption completed");
        Ok(())
    }

    /// Generate unique encryption key for each object
    fn generate_object_key(
        &self,
        file_key: &[u8],
        obj_num: u32,
        gen_num: u16,
        algorithm: EncryptionAlgorithm,
    ) -> PDFCryptoResult<Vec<u8>> {
        let mut hasher = Md5::new();
        
        // Input file encryption key
        hasher.update(file_key);
        
        // Add object number (low order 3 bytes)
        hasher.update(&obj_num.to_le_bytes()[0..3]);
        
        // Add generation number
        hasher.update(&gen_num.to_le_bytes());
        
        // Add AES salt if needed
        if matches!(algorithm, EncryptionAlgorithm::AES_128 | EncryptionAlgorithm::AES_256) {
            hasher.update(b"sAlT");
        }
        
        let hash = hasher.finalize();
        
        // Key length depends on algorithm
        let key_len = match algorithm {
            EncryptionAlgorithm::RC4_40 => 5,
            EncryptionAlgorithm::RC4_128 | EncryptionAlgorithm::AES_128 => 16,
            EncryptionAlgorithm::AES_256 => 32,
        };
        
        if hash.len() < key_len {
            return Err(PDFCryptoError::InvalidKeyLength(hash.len()));
        }
        
        Ok(hash[..key_len].to_vec())
    }

    /// Get crypto provider for algorithm
    fn get_provider(&self, algorithm: EncryptionAlgorithm) -> PDFCryptoResult<&dyn CryptoProvider> {
        self.providers
            .get(&algorithm)
            .ok_or_else(|| PDFCryptoError::UnsupportedAlgorithm(algorithm))
            .map(|p| p.as_ref())
    }
}

impl Default for PDFCryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;
    use crate::PDFPermissions;
    use crate::handlers::StandardSecurityHandler;

    #[test]
    fn test_object_key_generation() {
        let engine = PDFCryptoEngine::new();
        let file_key = b"test_key_123456789";
        
        // Test RC4-40 key generation
        let rc4_40_key = engine.generate_object_key(
            file_key,
            1,
            0,
            EncryptionAlgorithm::RC4_40,
        ).unwrap();
        assert_eq!(rc4_40_key.len(), 5);
        
        // Test AES-256 key generation
        let aes_256_key = engine.generate_object_key(
            file_key,
            1,
            0,
            EncryptionAlgorithm::AES_256,
        ).unwrap();
        assert_eq!(aes_256_key.len(), 32);
        
        // Verify keys are different
        assert_ne!(rc4_40_key, aes_256_key[..5]);
    }

    #[test]
    fn test_provider_selection() {
        let engine = PDFCryptoEngine::new();
        
        assert!(engine.get_provider(EncryptionAlgorithm::RC4_40).is_ok());
        assert!(engine.get_provider(EncryptionAlgorithm::AES_256).is_ok());
    }

    #[test]
    fn test_encryption_decryption() -> PDFCryptoResult<()> {
        let engine = PDFCryptoEngine::new();
        let file_key = b"test_key_123456789";
        
        // Create test data
        let original_data = b"Test data for encryption".to_vec();
        let mut test_data = original_data.clone();
        
        // Get AES provider
        let provider = engine.get_provider(EncryptionAlgorithm::AES_256)?;
        
        // Generate object key
        let object_key = engine.generate_object_key(
            file_key,
            1,
            0,
            EncryptionAlgorithm::AES_256,
        )?;
        
        // Encrypt data
        provider.process_data(&mut test_data, &object_key)?;
        assert_ne!(test_data, original_data);
        
        // Decrypt data
        provider.process_data(&mut test_data, &object_key)?;
        assert_eq!(test_data, original_data);
        
        Ok(())
    }

    #[test]
    fn test_full_pdf_encryption() -> PDFCryptoResult<()> {
        let engine = PDFCryptoEngine::new();
        
        // Create test PDF data
        let mut parser = PDFParser::new(include_bytes!("../../../tests/files/sample.pdf"))?;
        
        // Create security handler
        let handler = StandardSecurityHandler::new(
            EncryptionAlgorithm::AES_256,
            PDFPermissions::all().bits(),
            b"user",
            b"owner",
        )?;
        
        // Generate file key
        let file_key = handler.generate_file_key()?;
        
        // Encrypt PDF objects
        engine.encrypt_pdf_objects(&mut parser, &file_key, &SecurityHandler::Standard(handler.clone()))?;
        
        // Get encrypted data
        let encrypted = parser.rebuild_pdf();
        
        // Create new parser for decryption
        let mut parser = PDFParser::new(&encrypted)?;
        
        // Decrypt PDF objects
        engine.decrypt_pdf_objects(&mut parser, &file_key, &SecurityHandler::Standard(handler))?;
        
        // Verify decrypted data
        let decrypted = parser.rebuild_pdf();
        assert_eq!(decrypted, include_bytes!("../../../tests/files/sample.pdf"));
        
        Ok(())
    }
}
