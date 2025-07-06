use super::{PDFCryptoError, EncryptionAlgorithm, StandardSecurityHandler};
use md5::{Md5, Digest as Md5Digest};
use sha2::{Sha256, Digest as Sha256Digest};
use zeroize::Zeroize;

impl StandardSecurityHandler {
    /// PDF 1.7 Spec Algorithm 2: Computing encryption key
    pub fn compute_encryption_key(
        &self,
        password: &[u8],
        o_value: &[u8],
        p_value: u32,
        file_id: &[u8]
    ) -> Result<Vec<u8>, PDFCryptoError> {
        match self.revision {
            2 | 3 => self.compute_key_rev2_3(password, o_value, p_value, file_id),
            4 => self.compute_key_rev4(password, o_value, p_value, file_id),
            5 | 6 => self.compute_key_rev5_6(password, o_value, p_value, file_id),
            _ => Err(PDFCryptoError::UnsupportedRevision(self.revision))
        }
    }

    /// Algorithm 2.A for Revision 2-3
    fn compute_key_rev2_3(
        &self,
        password: &[u8],
        o_value: &[u8],
        p_value: u32,
        file_id: &[u8]
    ) -> Result<Vec<u8>, PDFCryptoError> {
        let mut hasher = Md5::new();
        
        // Step 1: Pad password to 32 bytes
        let mut padded_pass = [0u8; 32];
        let pass_len = password.len().min(32);
        padded_pass[..pass_len].copy_from_slice(&password[..pass_len]);
        padded_pass[pass_len..].copy_from_slice(&PADDING[..32-pass_len]);
        
        // Step 2-4: Add O value, P value, and file ID
        hasher.update(&padded_pass);
        hasher.update(o_value);
        hasher.update(&p_value.to_le_bytes());
        hasher.update(file_id);
        
        let mut key = hasher.finalize().to_vec();
        
        // Step 5: Additional rounds for revision 3
        if self.revision >= 3 {
            for _ in 0..50 {
                let mut hasher = Md5::new();
                hasher.update(&key[..self.key_length/8]);
                key = hasher.finalize().to_vec();
            }
        }
        
        Ok(key[..self.key_length/8].to_vec())
    }

    /// Algorithm 2.B for Revision 4 (AES-128)
    fn compute_key_rev4(
        &self,
        password: &[u8],
        o_value: &[u8],
        p_value: u32,
        file_id: &[u8]
    ) -> Result<Vec<u8>, PDFCryptoError> {
        let mut key = self.compute_key_rev2_3(password, o_value, p_value, file_id)?;
        
        // Add AES specific processing
        let mut hasher = Sha256::new();
        hasher.update(&key);
        key = hasher.finalize()[..16].to_vec();
        
        Ok(key)
    }

    /// Algorithm 2.B for Revision 5-6 (AES-256)
    fn compute_key_rev5_6(
        &self,
        password: &[u8],
        o_value: &[u8],
        _p_value: u32,
        _file_id: &[u8]
    ) -> Result<Vec<u8>, PDFCryptoError> {
        let mut hasher = Sha256::new();
        
        // Hash password with owner validation salt
        hasher.update(password);
        hasher.update(&o_value[32..40]); // Salt from O value
        let mut key = hasher.finalize().to_vec();
        
        // Perform 100 rounds of SHA-256
        for _ in 0..100 {
            let mut hasher = Sha256::new();
            hasher.update(&key);
            key = hasher.finalize().to_vec();
        }
        
        Ok(key[..32].to_vec())
    }

    /// Compute O value for revisions 2-4
    fn compute_o_value_rev2_3_4(
        &self,
        owner_password: &[u8],
        user_password: &[u8]
    ) -> Result<Vec<u8>, PDFCryptoError> {
        let mut hasher = Md5::new();
        
        // Step 1: Pad owner password
        let mut padded_owner = [0u8; 32];
        let owner_len = owner_password.len().min(32);
        padded_owner[..owner_len].copy_from_slice(&owner_password[..owner_len]);
        padded_owner[owner_len..].copy_from_slice(&PADDING[..32-owner_len]);
        
        // Step 2: Create RC4 key
        hasher.update(&padded_owner);
        let mut rc4_key = hasher.finalize().to_vec();
        
        if self.revision >= 3 {
            for _ in 0..50 {
                let mut hasher = Md5::new();
                hasher.update(&rc4_key);
                rc4_key = hasher.finalize().to_vec();
            }
        }
        
        // Step 3: Create O value
        let mut o_value = [0u8; 32];
        let user_len = user_password.len().min(32);
        o_value[..user_len].copy_from_slice(&user_password[..user_len]);
        o_value[user_len..].copy_from_slice(&PADDING[..32-user_len]);
        
        // Step 4: Encrypt with RC4
        let mut cipher = rc4::Rc4::new(&rc4_key[..self.key_length/8]);
        cipher.apply_keystream(&mut o_value);
        
        // Step 5: Additional processing for revision 3
        if self.revision >= 3 {
            for i in 0..19 {
                let mut key = rc4_key.clone();
                for byte in &mut key {
                    *byte ^= (i + 1) as u8;
                }
                let mut cipher = rc4::Rc4::new(&key[..self.key_length/8]);
                cipher.apply_keystream(&mut o_value);
            }
        }
        
        Ok(o_value.to_vec())
    }

    /// Compute O value for revisions 5-6
    fn compute_o_value_rev5_6(
        &self,
        owner_password: &[u8],
        user_password: &[u8]
    ) -> Result<Vec<u8>, PDFCryptoError> {
        let mut hasher = Sha256::new();
        
        // Generate random validation salt and key salt
        let mut validation_salt = [0u8; 8];
        let mut key_salt = [0u8; 8];
        rand::fill(&mut validation_salt)?;
        rand::fill(&mut key_salt)?;
        
        // Hash owner password with validation salt
        hasher.update(owner_password);
        hasher.update(&validation_salt);
        let mut key = hasher.finalize().to_vec();
        
        // Perform 100 rounds of SHA-256
        for _ in 0..100 {
            let mut hasher = Sha256::new();
            hasher.update(&key);
            key = hasher.finalize().to_vec();
        }
        
        // Create O value
        let mut o_value = Vec::with_capacity(48);
        o_value.extend_from_slice(&key[..32]);
        o_value.extend_from_slice(&validation_salt);
        o_value.extend_from_slice(&key_salt);
        
        Ok(o_value)
    }
}

// Standard padding string from PDF spec
const PADDING: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
    0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_rev2() {
        let handler = StandardSecurityHandler::new(
            EncryptionAlgorithm::RC4_40,
            0xFFFFFFFF,
            b"user",
            b"owner"
        ).unwrap();

        let key = handler.compute_encryption_key(
            b"test",
            &[0u8; 32],
            0xFFFFFFFF,
            &[0u8; 16]
        ).unwrap();

        assert_eq!(key.len(), 5); // 40-bit key
    }

    #[test]
    fn test_key_derivation_rev3() {
        let handler = StandardSecurityHandler::new(
            EncryptionAlgorithm::RC4_128,
            0xFFFFFFFF,
            b"user",
            b"owner"
        ).unwrap();

        let key = handler.compute_encryption_key(
            b"test",
            &[0u8; 32],
            0xFFFFFFFF,
            &[0u8; 16]
        ).unwrap();

        assert_eq!(key.len(), 16); // 128-bit key
    }

    #[test]
    fn test_o_value_computation() {
        let handler = StandardSecurityHandler::new(
            EncryptionAlgorithm::AES_128,
            0xFFFFFFFF,
            b"user",
            b"owner"
        ).unwrap();

        let o_value = handler.compute_o_value_rev2_3_4(
            b"owner",
            b"user"
        ).unwrap();

        assert_eq!(o_value.len(), 32);
    }
}
