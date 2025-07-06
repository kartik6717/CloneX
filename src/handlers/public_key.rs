//! Public Key Security Handler implementation according to PDF specification

use std::convert::TryInto;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use x509_parser::prelude::*;
use rand::{thread_rng, RngCore};

use crate::error::PDFCryptoError;
use crate::EncryptionAlgorithm;

/// Recipient information for public key security
#[derive(Clone)]
pub struct Recipient {
    pub permissions: u32,
    encrypted_key: Vec<u8>,
    version: u8,
    security_handler: String,
    key_length: u16,
    certificate: Vec<u8>,
}

/// Public key security handler for certificate-based encryption
#[derive(Clone, ZeroizeOnDrop)]
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
    pub fn new(algorithm: EncryptionAlgorithm) -> Result<Self, PDFCryptoError> {
        Ok(Self {
            algorithm,
            version: 1,
            recipients: Vec::new(),
            encryption_key: None,
            private_key: None,
        })
    }

    pub fn add_recipient(
        &mut self,
        certificate_data: &[u8],
        permissions: u32,
    ) -> Result<(), PDFCryptoError> {
        // Parse X.509 certificate
        let (_, cert) = X509Certificate::from_der(certificate_data)
            .map_err(|e| PDFCryptoError::CertificateError(e.to_string()))?;
        
        // Extract public key
        let public_key = RsaPublicKey::try_from(cert.public_key())
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
        
        let encrypted_key = public_key.encrypt(
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
            key_length: encryption_key.len() as u16 * 8,
            certificate: certificate_data.to_vec(),
        });
        
        Ok(())
    }

    pub fn set_decryption_key(
        &mut self,
        certificate_data: &[u8],
        private_key_data: &[u8],
    ) -> Result<(), PDFCryptoError> {
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

    pub fn get_file_key(&self) -> Result<Vec<u8>, PDFCryptoError> {
        self.encryption_key.clone()
            .ok_or_else(|| PDFCryptoError::NoPrivateKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_certificate_encryption() -> Result<(), PDFCryptoError> {
        // Load test certificate and private key
        let cert_data = include_bytes!("../../../tests/samples/test_cert.der");
        let key_data = include_bytes!("../../../tests/samples/test_key.der");
        
        // Create handler and add recipient
        let mut handler = PublicKeySecurityHandler::new(EncryptionAlgorithm::AES_256)?;
        handler.add_recipient(cert_data, 0xffffffff)?;
        
        // Get original encryption key
        let original_key = handler.encryption_key.clone().unwrap();
        
        // Test decryption with private key
        handler.set_decryption_key(cert_data, key_data)?;
        let decrypted_key = handler.get_file_key()?;
        
        assert_eq!(original_key, decrypted_key);
        
        Ok(())
    }
}
