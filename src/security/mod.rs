use std::fmt;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy)]
pub enum EncryptionAlgorithm {
    RC4_40,    // PDF 1.3
    RC4_128,   // PDF 1.4
    AES_128,   // PDF 1.6
    AES_256,   // PDF 1.7+/2.0
}

#[derive(Debug)]
pub struct StandardSecurityHandler {
    version: u8,         // 1-5
    revision: u8,        // 2-6
    key_length: usize,   // 40-256 bits
    algorithm: EncryptionAlgorithm,
    permissions: u32,
    o_value: Vec<u8>,    // Owner password validation
    u_value: Vec<u8>,    // User password validation
    file_id: Vec<u8>,    // PDF file identifier
}

impl StandardSecurityHandler {
    pub fn new(
        algorithm: EncryptionAlgorithm,
        permissions: u32,
        user_password: &[u8],
        owner_password: &[u8],
    ) -> Result<Self, PDFCryptoError> {
        let (version, revision, key_length) = match algorithm {
            EncryptionAlgorithm::RC4_40 => (1, 2, 40),
            EncryptionAlgorithm::RC4_128 => (2, 3, 128),
            EncryptionAlgorithm::AES_128 => (4, 4, 128),
            EncryptionAlgorithm::AES_256 => (5, 6, 256),
        };

        let mut handler = Self {
            version,
            revision,
            key_length,
            algorithm,
            permissions,
            o_value: Vec::new(),
            u_value: Vec::new(),
            file_id: Vec::new(),
        };

        // Generate O and U values
        handler.o_value = handler.compute_o_value(owner_password, user_password)?;
        handler.u_value = handler.compute_u_value(user_password)?;

        Ok(handler)
    }

    /// Compute O value (Owner Password validation)
    fn compute_o_value(&self, owner_password: &[u8], user_password: &[u8]) -> Result<Vec<u8>, PDFCryptoError> {
        match self.revision {
            2 | 3 | 4 => self.compute_o_value_rev2_3_4(owner_password, user_password),
            5 | 6 => self.compute_o_value_rev5_6(owner_password, user_password),
            _ => Err(PDFCryptoError::UnsupportedRevision(self.revision))
        }
    }

    /// Compute U value (User Password validation)
    fn compute_u_value(&self, user_password: &[u8]) -> Result<Vec<u8>, PDFCryptoError> {
        match self.revision {
            2 => self.compute_u_value_rev2(user_password),
            3 | 4 => self.compute_u_value_rev3_4(user_password),
            5 | 6 => self.compute_u_value_rev5_6(user_password),
            _ => Err(PDFCryptoError::UnsupportedRevision(self.revision))
        }
    }
}

// Implement Drop to securely clear sensitive data
impl Drop for StandardSecurityHandler {
    fn drop(&mut self) {
        self.o_value.zeroize();
        self.u_value.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct Recipient {
    certificate: Vec<u8>,
    permissions: u32,
    encrypted_key: Vec<u8>,
}

#[derive(Debug)]
pub struct PublicKeySecurityHandler {
    recipients: Vec<Recipient>,
    encryption_algorithm: EncryptionAlgorithm,
    key_encryption_algorithm: KeyEncryptionAlgorithm,
}

#[derive(Debug, Clone, Copy)]
pub enum KeyEncryptionAlgorithm {
    RSA_V15,
    RSA_V21,
}

impl PublicKeySecurityHandler {
    pub fn new(
        encryption_algorithm: EncryptionAlgorithm,
        key_encryption_algorithm: KeyEncryptionAlgorithm,
    ) -> Self {
        Self {
            recipients: Vec::new(),
            encryption_algorithm,
            key_encryption_algorithm,
        }
    }

    pub fn add_recipient(&mut self, certificate: Vec<u8>, permissions: u32) -> Result<(), PDFCryptoError> {
        // Validate certificate
        if let Err(e) = x509_parser::parse_x509_certificate(&certificate) {
            return Err(PDFCryptoError::CertificateError(e.to_string()));
        }

        self.recipients.push(Recipient {
            certificate,
            permissions,
            encrypted_key: Vec::new(),
        });

        Ok(())
    }
}

#[derive(Debug)]
pub enum PDFCryptoError {
    AuthenticationFailed,
    UnsupportedFilter(String),
    UnsupportedRevision(u8),
    InvalidKeyLength(usize),
    MalformedPDF,
    CertificateError(String),
    CryptoError(String),
}

impl std::error::Error for PDFCryptoError {}

impl fmt::Display for PDFCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => write!(f, "Authentication failed"),
            Self::UnsupportedFilter(filter) => write!(f, "Unsupported encryption filter: {}", filter),
            Self::UnsupportedRevision(rev) => write!(f, "Unsupported revision: {}", rev),
            Self::InvalidKeyLength(len) => write!(f, "Invalid key length: {}", len),
            Self::MalformedPDF => write!(f, "Malformed PDF structure"),
            Self::CertificateError(err) => write!(f, "Certificate error: {}", err),
            Self::CryptoError(err) => write!(f, "Cryptographic operation failed: {}", err),
        }
    }
}
