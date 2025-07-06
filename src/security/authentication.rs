use super::{
    StandardSecurityHandler, 
    PublicKeySecurityHandler,
    PDFCryptoError,
    EncryptionAlgorithm
};
use sha2::{Sha256, Sha384, Sha512, Digest};
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use x509_parser::prelude::*;
use zeroize::Zeroizing;

impl StandardSecurityHandler {
    /// Algorithm 6: Authenticate user password
    pub fn authenticate_user_password(
        &self,
        password: &[u8],
        u_value: &[u8]
    ) -> Result<Zeroizing<Vec<u8>>, PDFCryptoError> {
        let file_key = self.compute_encryption_key(
            password,
            &self.o_value,
            self.permissions,
            &self.file_id
        )?;

        match self.revision {
            2 => self.verify_user_password_rev2(&file_key, u_value),
            3 | 4 => self.verify_user_password_rev3_4(&file_key, u_value),
            5 | 6 => self.verify_user_password_rev5_6(password, u_value),
            _ => Err(PDFCryptoError::UnsupportedRevision(self.revision))
        }
    }

    /// Algorithm 7: Authenticate owner password
    pub fn authenticate_owner_password(
        &self,
        password: &[u8]
    ) -> Result<Zeroizing<Vec<u8>>, PDFCryptoError> {
        match self.revision {
            2 | 3 | 4 => self.verify_owner_password_rev2_3_4(password),
            5 | 6 => self.verify_owner_password_rev5_6(password),
            _ => Err(PDFCryptoError::UnsupportedRevision(self.revision))
        }
    }

    /// Algorithm 4: User password verification for Rev 2
    fn verify_user_password_rev2(
        &self,
        file_key: &[u8],
        u_value: &[u8]
    ) -> Result<Zeroizing<Vec<u8>>, PDFCryptoError> {
        let padding = self.get_password_padding();
        let mut cipher = rc4::Rc4::new(file_key);
        let mut computed_u = padding.to_vec();
        cipher.apply_keystream(&mut computed_u);

        if constant_time_eq(&computed_u, u_value) {
            Ok(Zeroizing::new(file_key.to_vec()))
        } else {
            Err(PDFCryptoError::AuthenticationFailed)
        }
    }

    /// Algorithm 5: User password verification for Rev 3-4
    fn verify_user_password_rev3_4(
        &self,
        file_key: &[u8],
        u_value: &[u8]
    ) -> Result<Zeroizing<Vec<u8>>, PDFCryptoError> {
        let padding = self.get_password_padding();
        
        let mut hasher = md5::Md5::new();
        hasher.update(&padding);
        hasher.update(&self.file_id);
        let mut hash = hasher.finalize().to_vec();
        
        // Encrypt hash with RC4
        let mut cipher = rc4::Rc4::new(file_key);
        cipher.apply_keystream(&mut hash);
        
        // Perform 19 additional rounds
        for i in 1..=19 {
            let mut key = file_key.to_vec();
            for byte in &mut key {
                *byte ^= i as u8;
            }
            let mut cipher = rc4::Rc4::new(&key);
            cipher.apply_keystream(&mut hash);
        }
        
        if constant_time_eq(&hash[..16], &u_value[..16]) {
            Ok(Zeroizing::new(file_key.to_vec()))
        } else {
            Err(PDFCryptoError::AuthenticationFailed)
        }
    }

    /// User password verification for Rev 5-6
    fn verify_user_password_rev5_6(
        &self,
        password: &[u8],
        u_value: &[u8]
    ) -> Result<Zeroizing<Vec<u8>>, PDFCryptoError> {
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(&u_value[32..40]); // Validation salt
        let mut hash = hasher.finalize().to_vec();
        
        // Perform 100 rounds of SHA-256
        for _ in 0..100 {
            let mut hasher = Sha256::new();
            hasher.update(&hash);
            hash = hasher.finalize().to_vec();
        }
        
        if constant_time_eq(&hash, &u_value[..32]) {
            // Generate encryption key
            let mut hasher = Sha256::new();
            hasher.update(password);
            hasher.update(&u_value[40..48]); // Key salt
            let mut key = hasher.finalize().to_vec();
            
            // Perform 100 rounds of SHA-256
            for _ in 0..100 {
                let mut hasher = Sha256::new();
                hasher.update(&key);
                key = hasher.finalize().to_vec();
            }
            
            Ok(Zeroizing::new(key))
        } else {
            Err(PDFCryptoError::AuthenticationFailed)
        }
    }

    /// Owner password verification for Rev 2-4
    fn verify_owner_password_rev2_3_4(
        &self,
        password: &[u8]
    ) -> Result<Zeroizing<Vec<u8>>, PDFCryptoError> {
        let mut hasher = md5::Md5::new();
        
        // Pad owner password
        let mut padded_owner = [0u8; 32];
        let pass_len = password.len().min(32);
        padded_owner[..pass_len].copy_from_slice(&password[..pass_len]);
        padded_owner[pass_len..].copy_from_slice(&PADDING[..32-pass_len]);
        
        hasher.update(&padded_owner);
        let mut key = hasher.finalize().to_vec();
        
        if self.revision >= 3 {
            for _ in 0..50 {
                let mut hasher = md5::Md5::new();
                hasher.update(&key);
                key = hasher.finalize().to_vec();
            }
        }
        
        let mut user_pass = self.o_value.clone();
        let mut cipher = rc4::Rc4::new(&key[..self.key_length/8]);
        cipher.apply_keystream(&mut user_pass);
        
        if self.revision >= 3 {
            for i in (0..19).rev() {
                let mut key_i = key.clone();
                for byte in &mut key_i {
                    *byte ^= (i + 1) as u8;
                }
                let mut cipher = rc4::Rc4::new(&key_i[..self.key_length/8]);
                cipher.apply_keystream(&mut user_pass);
            }
        }
        
        // Now authenticate with decrypted user password
        self.authenticate_user_password(&user_pass, &self.u_value)
    }

    /// Owner password verification for Rev 5-6
    fn verify_owner_password_rev5_6(
        &self,
        password: &[u8]
    ) -> Result<Zeroizing<Vec<u8>>, PDFCryptoError> {
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(&self.o_value[32..40]); // Validation salt
        hasher.update(&self.u_value[..48]);   // User validation + key salt
        let mut hash = hasher.finalize().to_vec();
        
        // Perform 100 rounds of SHA-256
        for _ in 0..100 {
            let mut hasher = Sha256::new();
            hasher.update(&hash);
            hash = hasher.finalize().to_vec();
        }
        
        if constant_time_eq(&hash, &self.o_value[..32]) {
            // Generate encryption key
            let mut hasher = Sha256::new();
            hasher.update(password);
            hasher.update(&self.o_value[40..48]); // Key salt
            hasher.update(&self.u_value[..48]);   // User validation + key salt
            let mut key = hasher.finalize().to_vec();
            
            // Perform 100 rounds of SHA-256
            for _ in 0..100 {
                let mut hasher = Sha256::new();
                hasher.update(&key);
                key = hasher.finalize().to_vec();
            }
            
            Ok(Zeroizing::new(key))
        } else {
            Err(PDFCryptoError::AuthenticationFailed)
        }
    }
}

impl PublicKeySecurityHandler {
    /// Authenticate using certificate
    pub fn authenticate_with_certificate(
        &self,
        certificate_data: &[u8],
        private_key_data: &[u8]
    ) -> Result<Zeroizing<Vec<u8>>, PDFCryptoError> {
        // Parse X.509 certificate
        let (_, cert) = X509Certificate::from_der(certificate_data)
            .map_err(|e| PDFCryptoError::CertificateError(e.to_string()))?;
        
        // Find matching recipient
        let recipient = self.recipients.iter()
            .find(|r| r.certificate == certificate_data)
            .ok_or(PDFCryptoError::CertificateNotFound)?;
        
        // Parse private key
        let private_key = RsaPrivateKey::from_pkcs8_der(private_key_data)
            .map_err(|e| PDFCryptoError::PrivateKeyError(e.to_string()))?;
        
        // Decrypt the file encryption key
        let decrypted = private_key.decrypt(
            Pkcs1v15Encrypt,
            &recipient.encrypted_key
        ).map_err(|e| PDFCryptoError::DecryptionError(e.to_string()))?;
        
        // Verify permissions
        if !self.verify_permissions(&decrypted, recipient.permissions) {
            return Err(PDFCryptoError::InvalidPermissions);
        }
        
        Ok(Zeroizing::new(decrypted))
    }

    /// Verify decrypted permissions match the recipient's permissions
    fn verify_permissions(&self, decrypted: &[u8], expected: u32) -> bool {
        if decrypted.len() < 24 {
            return false;
        }
        
        let perms = u32::from_be_bytes([
            decrypted[20], decrypted[21], decrypted[22], decrypted[23]
        ]);
        
        perms == expected
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_password_authentication() {
        let handler = StandardSecurityHandler::new(
            EncryptionAlgorithm::AES_128,
            0xFFFFFFFF,
            b"user",
            b"owner"
        ).unwrap();

        let result = handler.authenticate_user_password(b"user", &handler.u_value);
        assert!(result.is_ok());

        let result = handler.authenticate_user_password(b"wrong", &handler.u_value);
        assert!(result.is_err());
    }

    #[test]
    fn test_owner_password_authentication() {
        let handler = StandardSecurityHandler::new(
            EncryptionAlgorithm::AES_256,
            0xFFFFFFFF,
            b"user",
            b"owner"
        ).unwrap();

        let result = handler.authenticate_owner_password(b"owner");
        assert!(result.is_ok());

        let result = handler.authenticate_owner_password(b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_authentication() {
        // This would require actual certificate and private key data
        // Mock test with dummy data
        let mut handler = PublicKeySecurityHandler::new(
            EncryptionAlgorithm::AES_256,
            super::KeyEncryptionAlgorithm::RSA_V15
        );

        let cert_data = vec![0u8; 32];
        let key_data = vec![0u8; 32];
        
        handler.add_recipient(cert_data.clone(), 0xFFFFFFFF).unwrap();
        
        let result = handler.authenticate_with_certificate(&cert_data, &key_data);
        assert!(result.is_err()); // Should fail with dummy data
    }
}
