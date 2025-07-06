//! Core cryptographic engine implementation

use std::sync::Arc;
use crate::error::PDFCryptoError;
use crate::EncryptionAlgorithm;
use crate::handlers::SecurityHandler;
use crate::pdf::PDFParser;
use super::{rc4, aes, CryptoProvider};

/// Core engine for PDF encryption/decryption operations
pub struct PDFCryptoEngine {
    providers: Arc<ProvidersMap>,
}

type ProvidersMap = std::collections::HashMap<EncryptionAlgorithm, Box<dyn CryptoProvider>>;

impl PDFCryptoEngine {
    /// Create new cryptographic engine instance
    pub fn new() -> Self {
        let mut providers = std::collections::HashMap::new();
        
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
    ) -> Result<(), PDFCryptoError> {
        let algorithm = handler.get_algorithm();
        let provider = self.get_provider(algorithm)?;

        // Process each encrypted object
        for obj in parser.get_encrypted_objects()? {
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

        Ok(())
    }

    /// Encrypt PDF objects in place
    pub fn encrypt_pdf_objects(
        &self,
        parser: &mut PDFParser,
        file_key: &[u8],
        handler: &SecurityHandler,
    ) -> Result<(), PDFCryptoError> {
        let algorithm = handler.get_algorithm();
        let provider = self.get_provider(algorithm)?;

        // Process each object that needs encryption
        for obj in parser.get_encryptable_objects()? {
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

        Ok(())
    }

    /// Generate unique encryption key for each object
    fn generate_object_key(
        &self,
        file_key: &[u8],
        obj_num: u32,
        gen_num: u16,
        algorithm: EncryptionAlgorithm,
    ) -> Result<Vec<u8>, PDFCryptoError> {
        use md5::{Md5, Digest};
        
        let mut hasher = Md5::new();
        
        // Input file encryption key
        hasher.update(file_key);
        
        // Add object number and generation (low order 3 bytes of object number)
        hasher.update(&obj_num.to_le_bytes()[0..3]);
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
        
        Ok(hash[..key_len].to_vec())
    }

    fn get_provider(&self, algorithm: EncryptionAlgorithm) -> Result<&dyn CryptoProvider, PDFCryptoError> {
        self.providers
            .get(&algorithm)
            .ok_or_else(|| PDFCryptoError::UnsupportedAlgorithm(algorithm))
            .map(|p| p.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    }

    #[test]
    fn test_encryption_decryption() -> Result<(), PDFCryptoError> {
        let engine = PDFCryptoEngine::new();
        let test_data = b"Hello, PDF encryption!";
        let file_key = b"test_key_123456789";
        
        // Create a mock parser with test data
        let mut parser = PDFParser::new(test_data)?;
        
        // Create a security handler
        let handler = StandardSecurityHandler::new(
            EncryptionAlgorithm::AES_256,
            0xffffffff,
            b"user",
            b"owner",
        )?;
        
        // Test encryption
        engine.encrypt_pdf_objects(&mut parser, file_key, &SecurityHandler::Standard(handler.clone()))?;
        
        // Get encrypted data
        let encrypted = parser.get_object_data(1)?;
        assert_ne!(encrypted, test_data);
        
        // Test decryption
        engine.decrypt_pdf_objects(&mut parser, file_key, &SecurityHandler::Standard(handler))?;
        
        // Verify decrypted data matches original
        let decrypted = parser.get_object_data(1)?;
        assert_eq!(decrypted, test_data);
        
        Ok(())
    }
}
