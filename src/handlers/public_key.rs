//! Public Key Security Handler implementation for certificate-based PDF encryption

use std::convert::TryInto;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use x509_parser::prelude::*;
use sha2::{Sha256, Digest};
use rand::{thread_rng, RngCore};
use log::{debug, trace};

use crate::error::{PDFCryptoError, PDFCryptoResult};
use crate::EncryptionAlgorithm;
use crate::pdf::Dictionary;
use super::SecurityHandlerCommon;

/// Recipient information for public key security
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct Recipient {
    pub permissions: u32,
    #[zeroize]
    encrypted_key: Vec<u8>,
    version: u8,
    security_handler: String,
    key_length: u16,
    #[zeroize]
    certificate: Vec<u8>,
}

/// Public key security handler for certificate-based encryption
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct PublicKeySecurityHandler {
    pub(crate) algorithm: EncryptionAlgorithm,
    version: u8,
    recipients: Vec<Recipient>,
    #[zeroize]
    encryption_key: Option<Vec<u8>>,
    #[zeroize]
    private_key: Option<Vec<u8>>,
}

impl PublicKeySecurityHandler {
    /// Create new public key security handler
    pub fn new(algorithm: EncryptionAlgorithm) -> PDFCryptoResult<Self> {
        debug!("Creating new public key security handler with algorithm {:?}", algorithm);
        
        Ok(Self {
            algorithm,
            version: 1,
            recipients: Vec::new(),
            encryption_key: None,
            private_key: None,
        })
    }

    /// Add recipient with certificate
    pub fn add_recipient(
        &mut self,
        certificate_data: &[u8],
        permissions: u32,
    ) -> PDFCryptoResult<()> {
        debug!("Adding recipient with permissions: {:#x}", permissions);
        
        // Parse X.509 certificate
        let (_, cert) = X509Certificate::from_der(certificate_data)
            .map_err(|e| PDFCryptoError::CertificateError(e.to_string()))?;
        
        // Extract public key
        let public_key = cert.public_key();
        let rsa_key = RsaPublicKey::try_from(public_key.subject_public_key.data)
            .map_err(|e| PDFCryptoError::CertificateError(e.to_string()))?;
        
        // Generate encryption key if not exists
        if self.encryption_key.is_none() {
            let mut key = vec![0u8; 32];
            thread_rng().fill_bytes(&mut key);
            self.encryption_key = Some(key);
        }
        
        // Encrypt file encryption key for recipient
        let encryption_key = self.encryption_key.as_ref().unwrap();
        let mut data = Vec::with_capacity(encryption_key.len() + 4);
        data.extend_from_slice(encryption_key);
        data.extend_from_slice(&permissions.to_le_bytes());
        
        let encrypted_key = rsa_key.encrypt(
            &mut thread_rng(),
            Pkcs1v15Encrypt,
            &data,
        ).map_err(|e| PDFCryptoError::CryptoError(e.to_string()))?;
        
        // Add recipient
        self.recipients.push(Recipient {
            permissions,
            encrypted_key,
            version: 0,
            security_handler: String::from("Adobe.PPKLite"),
            key_length: (encryption_key.len() * 8) as u16,
            certificate: certificate_data.to_vec(),
        });
        
        Ok(())
    }

    /// Set decryption key from certificate and private key
    pub fn set_decryption_key(
        &mut self,
        certificate_data: &[u8],
        private_key_data: &[u8],
    ) -> PDFCryptoResult<()> {
        debug!("Setting decryption key from certificate");
        
        // Parse X.509 certificate
        let (_, cert) = X509Certificate::from_der(certificate_data)
            .map_err(|e| PDFCryptoError::CertificateError(e.to_string()))?;
        
        // Find matching recipient
        let recipient = self.recipients.iter()
            .find(|r| r.certificate == certificate_data)
            .ok_or_else(|| PDFCryptoError::CertificateError("No matching recipient found".to_string()))?;
        
        // Parse private key
        let private_key = RsaPrivateKey::from_pkcs8_der(private_key_data)
            .map_err(|e| PDFCryptoError::CertificateError(e.to_string()))?;
        
        // Decrypt file encryption key
        let decrypted = private_key.decrypt(
            Pkcs1v15Encrypt,
            &recipient.encrypted_key,
        ).map_err(|e| PDFCryptoError::CryptoError(e.to_string()))?;
        
        // Verify permissions
        let key_len = decrypted.len() - 4;
        let (key, perms) = decrypted.split_at(key_len);
        let perms = u32::from_le_bytes(perms.try_into().unwrap());
        
        if perms != recipient.permissions {
            return Err(PDFCryptoError::InvalidPermissions(perms));
        }
        
        self.encryption_key = Some(key.to_vec());
        self.private_key = Some(private_key_data.to_vec());
        
        Ok(())
    }

    /// Get file encryption key
    pub fn get_file_key(&self) -> PDFCryptoResult<Vec<u8>> {
        self.encryption_key.clone()
            .ok_or_else(|| PDFCryptoError::NoPrivateKey)
    }

    /// Generate file encryption key
    pub fn generate_file_key(&mut self) -> PDFCryptoResult<Vec<u8>> {
        if self.encryption_key.is_none() {
            let mut key = vec![0u8; 32];
            thread_rng().fill_bytes(&mut key);
            self.encryption_key = Some(key);
        }
        self.get_file_key()
    }
}

impl SecurityHandlerCommon for PublicKeySecurityHandler {
    fn get_algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }
    
    fn to_dict(&self) -> Dictionary {
        let mut dict = Dictionary::new();
        
        dict.set_name("Filter", "Adobe.PPKLite");
        dict.set_integer("V", 5); // Version for AES-256
        dict.set_integer("Length", 256); // Key length in bits
        dict.set_name("SubFilter", "adbe.pkcs7.s5");
        
        // Add recipients array
        let mut recipients_array = Vec::new();
        for recipient in &self.recipients {
            let mut rec_dict = Dictionary::new();
            rec_dict.set_integer("Version", recipient.version as i64);
            rec_dict.set_string("Cert", recipient.certificate.clone());
            rec_dict.set_string("EncryptedKey", recipient.encrypted_key.clone());
            rec_dict.set_integer("Permissions", recipient.permissions as i64);
            recipients_array.push(rec_dict);
        }
        dict.set_array("Recipients", recipients_array);
        
        // Add encryption dictionary
        let mut cf_dict = Dictionary::new();
        cf_dict.set_name("Type", "CryptoFilter");
        cf_dict.set_name("CFM", "AESV3");
        cf_dict.set_integer("Length", 256);
        
        let mut crypt_filters = Dictionary::new();
        crypt_filters.set_dict("DefaultCryptFilter", cf_dict);
        dict.set_dict("CF", crypt_filters);
        
        dict.set_name("StmF", "DefaultCryptFilter");
        dict.set_name("StrF", "DefaultCryptFilter");
        
        dict
    }
    
    fn from_dict(dict: &Dictionary) -> PDFCryptoResult<Self> {
        let version = dict.get_integer("V")? as u8;
        let length = dict.get_integer("Length")? as usize;
        
        let algorithm = match length {
            128 => EncryptionAlgorithm::AES_128,
            256 => EncryptionAlgorithm::AES_256,
            _ => return Err(PDFCryptoError::UnsupportedKeyLength(length)),
        };
        
        let mut handler = Self::new(algorithm)?;
        handler.version = version;
        
        // Parse recipients
        if let Some(recipients) = dict.get_array("Recipients") {
            for rec_dict in recipients {
                if let Dictionary::Dict(ref rec) = rec_dict {
                    let recipient = Recipient {
                        version: rec.get_integer("Version")? as u8,
                        certificate: rec.get_string_bytes("Cert")?,
                        encrypted_key: rec.get_string_bytes("EncryptedKey")?,
                        permissions: rec.get_integer("Permissions")? as u32,
                        security_handler: String::from("Adobe.PPKLite"),
                        key_length: length as u16,
                    };
                    handler.recipients.push(recipient);
                }
            }
        }
        
        Ok(handler)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    const TEST_CERT: &[u8] = include_bytes!("../../../tests/files/test_cert.der");
    const TEST_KEY: &[u8] = include_bytes!("../../../tests/files/test_key.der");

    #[test]
    fn test_handler_creation() -> PDFCryptoResult<()> {
        let handler = PublicKeySecurityHandler::new(EncryptionAlgorithm::AES_256)?;
        assert_eq!(handler.algorithm, EncryptionAlgorithm::AES_256);
        assert!(handler.recipients.is_empty());
        assert!(handler.encryption_key.is_none());
        Ok(())
    }

    #[test]
    fn test_add_recipient() -> PDFCryptoResult<()> {
        let mut handler = PublicKeySecurityHandler::new(EncryptionAlgorithm::AES_256)?;
        handler.add_recipient(TEST_CERT, 0xffffffff)?;
        
        assert_eq!(handler.recipients.len(), 1);
        assert!(handler.encryption_key.is_some());
        
        let recipient = &handler.recipients[0];
        assert_eq!(recipient.permissions, 0xffffffff);
        assert_eq!(recipient.security_handler, "Adobe.PPKLite");
        assert_eq!(recipient.key_length, 256);
        
        Ok(())
    }

    #[test]
    fn test_encryption_decryption() -> PDFCryptoResult<()> {
        let mut handler = PublicKeySecurityHandler::new(EncryptionAlgorithm::AES_256)?;
        
        // Add recipient and get original key
        handler.add_recipient(TEST_CERT, 0xffffffff)?;
        let original_key = handler.encryption_key.clone().unwrap();
        
        // Clear encryption key
        handler.encryption_key = None;
        
        // Set decryption key
        handler.set_decryption_key(TEST_CERT, TEST_KEY)?;
        
        // Verify decrypted key matches original
        let decrypted_key = handler.get_file_key()?;
        assert_eq!(original_key, decrypted_key);
        
        Ok(())
    }

    #[test]
    fn test_dictionary_conversion() -> PDFCryptoResult<()> {
        let mut handler = PublicKeySecurityHandler::new(EncryptionAlgorithm::AES_256)?;
        handler.add_recipient(TEST_CERT, 0xffffffff)?;
        
        let dict = handler.to_dict();
        
        // Verify dictionary contents
        assert_eq!(dict.get_name("Filter")?, "Adobe.PPKLite");
        assert_eq!(dict.get_integer("V")?, 5);
        assert_eq!(dict.get_integer("Length")?, 256);
        
        // Convert back
        let new_handler = PublicKeySecurityHandler::from_dict(&dict)?;
        assert_eq!(new_handler.algorithm, handler.algorithm);
        assert_eq!(new_handler.recipients.len(), handler.recipients.len());
        
        Ok(())
    }

    #[test]
    fn test_invalid_certificate() {
        let mut handler = PublicKeySecurityHandler::new(EncryptionAlgorithm::AES_256).unwrap();
        let result = handler.add_recipient(&[0; 32], 0xffffffff);
        assert!(matches!(result, Err(PDFCryptoError::CertificateError(_))));
    }

    #[test]
    fn test_no_matching_recipient() {
        let mut handler = PublicKeySecurityHandler::new(EncryptionAlgorithm::AES_256).unwrap();
        let result = handler.set_decryption_key(TEST_CERT, TEST_KEY);
        assert!(matches!(result, Err(PDFCryptoError::CertificateError(_))));
    }
}
