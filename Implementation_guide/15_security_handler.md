# Module 15: SecurityHandler - PDF Security Parameters

## Overview
The `SecurityHandler` module manages PDF security parameters and access controls. This module implements complete security handling logic for PDF encryption parameters, permissions, and security validation with full business logic.

## Module Requirements
- **Dependencies**: Depends on EncryptionParams from DecryptionHandler
- **Compilation**: Must compile with complete business logic implementation
- **Purpose**: Handle PDF security parameters and validation
- **Critical Rule**: COMPLETE implementation - no placeholders or todos

## Implementation Guide

### Step 1: Create Module File
Create `src/security_handler.rs`:

```rust
//! SecurityHandler Module
//! 
//! Manages PDF security parameters and access controls.
//! Complete implementation with full business logic for security operations.

use std::collections::HashMap;
use crate::silent_debug;
use crate::decryption_handler::{EncryptionParams, SecurityHandler as SecurityHandlerType, EncryptionAlgorithm};

/// PDF Security handler for managing security parameters
pub struct SecurityHandler {
    /// Current security parameters
    security_params: Option<EncryptionParams>,
    /// Permission flags
    permissions: SecurityPermissions,
    /// Access validation rules
    access_rules: HashMap<String, AccessLevel>,
    /// Security statistics
    stats: SecurityStats,
}

/// Security permissions structure
#[derive(Debug, Clone)]
pub struct SecurityPermissions {
    /// Allow printing
    pub print_allowed: bool,
    /// Allow document modification
    pub modify_allowed: bool,
    /// Allow copying/extraction
    pub copy_allowed: bool,
    /// Allow annotations
    pub annotate_allowed: bool,
    /// Allow form filling
    pub form_fill_allowed: bool,
    /// Allow accessibility extraction
    pub accessibility_allowed: bool,
    /// Allow document assembly
    pub assemble_allowed: bool,
    /// Allow high quality printing
    pub print_high_quality_allowed: bool,
    /// Raw permission value
    pub raw_permissions: u32,
}

/// Access levels for security validation
#[derive(Debug, Clone, PartialEq)]
pub enum AccessLevel {
    NoAccess,
    ReadOnly,
    Limited,
    Full,
}

impl SecurityHandler {
    /// Create new security handler
    pub fn new() -> Self {
        Self {
            security_params: None,
            permissions: SecurityPermissions::default(),
            access_rules: HashMap::new(),
            stats: SecurityStats::new(),
        }
    }

    /// Set security parameters from encryption data
    pub fn set_security_parameters(&mut self, params: EncryptionParams) -> Result<(), SecurityError> {
        silent_debug!("Setting security parameters");

        // Parse permissions from parameters
        self.permissions = self.parse_permissions(params.permissions)?;
        
        // Validate security handler type
        self.validate_security_handler(&params.handler)?;
        
        // Set encryption algorithm validation
        self.validate_encryption_algorithm(&params.algorithm)?;
        
        self.security_params = Some(params);
        self.stats.security_params_set = true;
        
        silent_debug!("Security parameters set successfully");
        Ok(())
    }

    /// Parse permissions from raw permission value
    fn parse_permissions(&self, raw_permissions: u32) -> Result<SecurityPermissions, SecurityError> {
        // PDF permissions are stored as negative values with specific bit flags
        let permissions = SecurityPermissions {
            print_allowed: (raw_permissions & 0x04) != 0,
            modify_allowed: (raw_permissions & 0x08) != 0,
            copy_allowed: (raw_permissions & 0x10) != 0,
            annotate_allowed: (raw_permissions & 0x20) != 0,
            form_fill_allowed: (raw_permissions & 0x100) != 0,
            accessibility_allowed: (raw_permissions & 0x200) != 0,
            assemble_allowed: (raw_permissions & 0x400) != 0,
            print_high_quality_allowed: (raw_permissions & 0x800) != 0,
            raw_permissions,
        };

        self.stats.permissions_parsed += 1;
        Ok(permissions)
    }

    /// Validate security handler type
    fn validate_security_handler(&self, handler: &SecurityHandlerType) -> Result<(), SecurityError> {
        match handler {
            SecurityHandlerType::Standard => {
                silent_debug!("Validated standard security handler");
                Ok(())
            }
            SecurityHandlerType::Adobe => {
                silent_debug!("Validated Adobe security handler");
                Ok(())
            }
            SecurityHandlerType::Unknown(name) => {
                let handler_name = String::from_utf8_lossy(name);
                silent_debug!("Unknown security handler: {}", handler_name);
                Err(SecurityError::UnsupportedHandler(handler_name.to_string()))
            }
        }
    }

    /// Validate encryption algorithm
    fn validate_encryption_algorithm(&self, algorithm: &EncryptionAlgorithm) -> Result<(), SecurityError> {
        match algorithm {
            EncryptionAlgorithm::RC4 { key_length } => {
                if *key_length < 40 || *key_length > 128 {
                    return Err(SecurityError::InvalidKeyLength(*key_length));
                }
                silent_debug!("Validated RC4 encryption with {} bit key", key_length);
            }
            EncryptionAlgorithm::AES128 => {
                silent_debug!("Validated AES-128 encryption");
            }
            EncryptionAlgorithm::AES256 => {
                silent_debug!("Validated AES-256 encryption");
            }
        }
        Ok(())
    }

    /// Check if operation is allowed by permissions
    pub fn is_operation_allowed(&self, operation: &SecurityOperation) -> bool {
        match operation {
            SecurityOperation::Print => self.permissions.print_allowed,
            SecurityOperation::Modify => self.permissions.modify_allowed,
            SecurityOperation::Copy => self.permissions.copy_allowed,
            SecurityOperation::Annotate => self.permissions.annotate_allowed,
            SecurityOperation::FormFill => self.permissions.form_fill_allowed,
            SecurityOperation::Accessibility => self.permissions.accessibility_allowed,
            SecurityOperation::Assemble => self.permissions.assemble_allowed,
            SecurityOperation::PrintHighQuality => self.permissions.print_high_quality_allowed,
        }
    }

    /// Validate access level for user
    pub fn validate_access(&self, user_type: &str, operation: &SecurityOperation) -> Result<AccessLevel, SecurityError> {
        // Check if operation is allowed by permissions
        if !self.is_operation_allowed(operation) {
            return Ok(AccessLevel::NoAccess);
        }

        // Check user-specific access rules
        if let Some(access_level) = self.access_rules.get(user_type) {
            Ok(access_level.clone())
        } else {
            // Default access based on permissions
            if self.permissions.modify_allowed {
                Ok(AccessLevel::Full)
            } else if self.permissions.copy_allowed {
                Ok(AccessLevel::Limited)
            } else {
                Ok(AccessLevel::ReadOnly)
            }
        }
    }

    /// Set access rule for user type
    pub fn set_access_rule(&mut self, user_type: String, access_level: AccessLevel) {
        self.access_rules.insert(user_type, access_level);
        self.stats.access_rules_defined += 1;
    }

    /// Generate security constraints for PDF processing
    pub fn generate_security_constraints(&self) -> Result<SecurityConstraints, SecurityError> {
        let params = self.security_params.as_ref()
            .ok_or(SecurityError::NoSecurityParams)?;

        let constraints = SecurityConstraints {
            encryption_required: true,
            minimum_key_length: self.get_minimum_key_length(&params.algorithm),
            allowed_operations: self.get_allowed_operations(),
            handler_type: params.handler.clone(),
            revision_level: params.revision,
            permission_flags: params.permissions,
        };

        silent_debug!("Generated security constraints");
        Ok(constraints)
    }

    /// Get minimum key length for algorithm
    fn get_minimum_key_length(&self, algorithm: &EncryptionAlgorithm) -> usize {
        match algorithm {
            EncryptionAlgorithm::RC4 { key_length } => *key_length,
            EncryptionAlgorithm::AES128 => 128,
            EncryptionAlgorithm::AES256 => 256,
        }
    }

    /// Get list of allowed operations
    fn get_allowed_operations(&self) -> Vec<SecurityOperation> {
        let mut operations = Vec::new();
        
        if self.permissions.print_allowed {
            operations.push(SecurityOperation::Print);
        }
        if self.permissions.modify_allowed {
            operations.push(SecurityOperation::Modify);
        }
        if self.permissions.copy_allowed {
            operations.push(SecurityOperation::Copy);
        }
        if self.permissions.annotate_allowed {
            operations.push(SecurityOperation::Annotate);
        }
        if self.permissions.form_fill_allowed {
            operations.push(SecurityOperation::FormFill);
        }
        if self.permissions.accessibility_allowed {
            operations.push(SecurityOperation::Accessibility);
        }
        if self.permissions.assemble_allowed {
            operations.push(SecurityOperation::Assemble);
        }
        if self.permissions.print_high_quality_allowed {
            operations.push(SecurityOperation::PrintHighQuality);
        }
        
        operations
    }

    /// Validate password strength
    pub fn validate_password_strength(&self, password: &str) -> PasswordStrength {
        let length = password.len();
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        let score = length as u32 +
                   if has_upper { 10 } else { 0 } +
                   if has_lower { 10 } else { 0 } +
                   if has_digit { 10 } else { 0 } +
                   if has_special { 20 } else { 0 };

        match score {
            0..=20 => PasswordStrength::Weak,
            21..=40 => PasswordStrength::Fair,
            41..=60 => PasswordStrength::Good,
            _ => PasswordStrength::Strong,
        }
    }

    /// Generate permission flags for specific access level
    pub fn generate_permission_flags(&self, access_level: &AccessLevel) -> u32 {
        match access_level {
            AccessLevel::NoAccess => 0x00000000,
            AccessLevel::ReadOnly => 0x00000004, // Print only
            AccessLevel::Limited => 0x00000014,  // Print + Copy
            AccessLevel::Full => 0x0000FFFC,     // All permissions
        }
    }

    /// Create security profile for user
    pub fn create_security_profile(&self, user_id: &str, access_level: AccessLevel) -> SecurityProfile {
        let permission_flags = self.generate_permission_flags(&access_level);
        let allowed_operations = self.operations_for_permissions(permission_flags);

        SecurityProfile {
            user_id: user_id.to_string(),
            access_level,
            permission_flags,
            allowed_operations,
            created_timestamp: std::time::SystemTime::now(),
        }
    }

    /// Get operations allowed for permission flags
    fn operations_for_permissions(&self, flags: u32) -> Vec<SecurityOperation> {
        let mut operations = Vec::new();
        
        if (flags & 0x04) != 0 {
            operations.push(SecurityOperation::Print);
        }
        if (flags & 0x08) != 0 {
            operations.push(SecurityOperation::Modify);
        }
        if (flags & 0x10) != 0 {
            operations.push(SecurityOperation::Copy);
        }
        if (flags & 0x20) != 0 {
            operations.push(SecurityOperation::Annotate);
        }
        if (flags & 0x100) != 0 {
            operations.push(SecurityOperation::FormFill);
        }
        if (flags & 0x200) != 0 {
            operations.push(SecurityOperation::Accessibility);
        }
        if (flags & 0x400) != 0 {
            operations.push(SecurityOperation::Assemble);
        }
        if (flags & 0x800) != 0 {
            operations.push(SecurityOperation::PrintHighQuality);
        }
        
        operations
    }

    /// Audit security operation
    pub fn audit_operation(&mut self, operation: &SecurityOperation, user_id: &str, allowed: bool) {
        let audit_entry = SecurityAuditEntry {
            operation: operation.clone(),
            user_id: user_id.to_string(),
            timestamp: std::time::SystemTime::now(),
            allowed,
        };

        self.stats.audit_entries.push(audit_entry);
        
        if allowed {
            self.stats.operations_allowed += 1;
        } else {
            self.stats.operations_denied += 1;
        }
    }

    /// Get security summary
    pub fn get_security_summary(&self) -> SecuritySummary {
        let params = self.security_params.as_ref();
        
        SecuritySummary {
            has_security: params.is_some(),
            handler_type: params.map(|p| p.handler.clone()),
            encryption_algorithm: params.map(|p| p.algorithm.clone()),
            key_length: params.map(|p| p.key_length).unwrap_or(0),
            permissions_summary: self.permissions.clone(),
            total_access_rules: self.access_rules.len(),
            security_level: self.calculate_security_level(),
        }
    }

    /// Calculate overall security level
    fn calculate_security_level(&self) -> SecurityLevel {
        let params = match &self.security_params {
            Some(p) => p,
            None => return SecurityLevel::None,
        };

        let key_length = params.key_length;
        let has_restrictions = !self.permissions.modify_allowed || !self.permissions.copy_allowed;

        match &params.algorithm {
            EncryptionAlgorithm::RC4 { key_length } if *key_length < 128 => SecurityLevel::Low,
            EncryptionAlgorithm::RC4 { .. } => SecurityLevel::Medium,
            EncryptionAlgorithm::AES128 if has_restrictions => SecurityLevel::High,
            EncryptionAlgorithm::AES128 => SecurityLevel::Medium,
            EncryptionAlgorithm::AES256 => SecurityLevel::VeryHigh,
        }
    }

    /// Export security parameters
    pub fn export_security_parameters(&self) -> Result<Vec<u8>, SecurityError> {
        let params = self.security_params.as_ref()
            .ok_or(SecurityError::NoSecurityParams)?;

        let mut export_data = Vec::new();
        
        // Export handler type
        let handler_bytes = match &params.handler {
            SecurityHandlerType::Standard => b"Standard".to_vec(),
            SecurityHandlerType::Adobe => b"Adobe.PPKLite".to_vec(),
            SecurityHandlerType::Unknown(name) => name.clone(),
        };
        export_data.extend_from_slice(&handler_bytes);
        export_data.push(0); // Separator

        // Export algorithm
        let algo_bytes = match &params.algorithm {
            EncryptionAlgorithm::RC4 { key_length } => format!("RC4-{}", key_length).into_bytes(),
            EncryptionAlgorithm::AES128 => b"AES-128".to_vec(),
            EncryptionAlgorithm::AES256 => b"AES-256".to_vec(),
        };
        export_data.extend_from_slice(&algo_bytes);
        export_data.push(0); // Separator

        // Export permissions
        export_data.extend_from_slice(&params.permissions.to_le_bytes());

        // Export key length
        export_data.extend_from_slice(&(params.key_length as u32).to_le_bytes());

        // Export revision
        export_data.extend_from_slice(&params.revision.to_le_bytes());

        silent_debug!("Exported security parameters: {} bytes", export_data.len());
        Ok(export_data)
    }

    /// Import security parameters
    pub fn import_security_parameters(&mut self, data: &[u8]) -> Result<(), SecurityError> {
        if data.len() < 16 {
            return Err(SecurityError::InvalidData("Data too short".to_string()));
        }

        let mut offset = 0;
        
        // Parse handler type
        let handler_end = data[offset..].iter().position(|&b| b == 0)
            .ok_or(SecurityError::InvalidData("Handler type not found".to_string()))?;
        let handler_bytes = &data[offset..offset + handler_end];
        offset += handler_end + 1;

        let handler = match handler_bytes {
            b"Standard" => SecurityHandlerType::Standard,
            b"Adobe.PPKLite" => SecurityHandlerType::Adobe,
            other => SecurityHandlerType::Unknown(other.to_vec()),
        };

        // Parse algorithm
        let algo_end = data[offset..].iter().position(|&b| b == 0)
            .ok_or(SecurityError::InvalidData("Algorithm not found".to_string()))?;
        let algo_bytes = &data[offset..offset + algo_end];
        offset += algo_end + 1;

        let algorithm = if algo_bytes.starts_with(b"RC4-") {
            let key_str = std::str::from_utf8(&algo_bytes[4..])
                .map_err(|_| SecurityError::InvalidData("Invalid RC4 key length".to_string()))?;
            let key_length = key_str.parse::<usize>()
                .map_err(|_| SecurityError::InvalidData("Invalid RC4 key length".to_string()))?;
            EncryptionAlgorithm::RC4 { key_length }
        } else if algo_bytes == b"AES-128" {
            EncryptionAlgorithm::AES128
        } else if algo_bytes == b"AES-256" {
            EncryptionAlgorithm::AES256
        } else {
            return Err(SecurityError::InvalidData("Unknown algorithm".to_string()));
        };

        // Parse permissions
        if offset + 4 > data.len() {
            return Err(SecurityError::InvalidData("Permissions data missing".to_string()));
        }
        let permissions = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        offset += 4;

        // Parse key length
        if offset + 4 > data.len() {
            return Err(SecurityError::InvalidData("Key length data missing".to_string()));
        }
        let key_length = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
        offset += 4;

        // Parse revision
        if offset + 4 > data.len() {
            return Err(SecurityError::InvalidData("Revision data missing".to_string()));
        }
        let revision = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);

        // Create encryption parameters
        let params = EncryptionParams {
            handler,
            algorithm,
            key_length,
            permissions,
            user_key: Vec::new(), // These would be loaded separately
            owner_key: Vec::new(),
            file_id: Vec::new(),
            revision,
        };

        self.set_security_parameters(params)?;
        silent_debug!("Imported security parameters successfully");
        Ok(())
    }

    /// Get security statistics
    pub fn get_statistics(&self) -> &SecurityStats {
        &self.stats
    }

    /// Get current permissions
    pub fn get_permissions(&self) -> &SecurityPermissions {
        &self.permissions
    }

    /// Reset security handler
    pub fn reset(&mut self) {
        self.security_params = None;
        self.permissions = SecurityPermissions::default();
        self.access_rules.clear();
        self.stats = SecurityStats::new();
    }
}

impl Default for SecurityHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Security operations that can be controlled
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityOperation {
    Print,
    Modify,
    Copy,
    Annotate,
    FormFill,
    Accessibility,
    Assemble,
    PrintHighQuality,
}

/// Password strength levels
#[derive(Debug, Clone, PartialEq)]
pub enum PasswordStrength {
    Weak,
    Fair,
    Good,
    Strong,
}

/// Security level assessment
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityLevel {
    None,
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Security constraints for PDF processing
#[derive(Debug, Clone)]
pub struct SecurityConstraints {
    pub encryption_required: bool,
    pub minimum_key_length: usize,
    pub allowed_operations: Vec<SecurityOperation>,
    pub handler_type: SecurityHandlerType,
    pub revision_level: u32,
    pub permission_flags: u32,
}

/// Security profile for a user
#[derive(Debug, Clone)]
pub struct SecurityProfile {
    pub user_id: String,
    pub access_level: AccessLevel,
    pub permission_flags: u32,
    pub allowed_operations: Vec<SecurityOperation>,
    pub created_timestamp: std::time::SystemTime,
}

/// Security audit entry
#[derive(Debug, Clone)]
pub struct SecurityAuditEntry {
    pub operation: SecurityOperation,
    pub user_id: String,
    pub timestamp: std::time::SystemTime,
    pub allowed: bool,
}

/// Security summary
#[derive(Debug, Clone)]
pub struct SecuritySummary {
    pub has_security: bool,
    pub handler_type: Option<SecurityHandlerType>,
    pub encryption_algorithm: Option<EncryptionAlgorithm>,
    pub key_length: usize,
    pub permissions_summary: SecurityPermissions,
    pub total_access_rules: usize,
    pub security_level: SecurityLevel,
}

/// Security statistics
#[derive(Debug, Clone)]
pub struct SecurityStats {
    pub security_params_set: bool,
    pub permissions_parsed: usize,
    pub access_rules_defined: usize,
    pub operations_allowed: usize,
    pub operations_denied: usize,
    pub audit_entries: Vec<SecurityAuditEntry>,
}

impl SecurityStats {
    fn new() -> Self {
        Self {
            security_params_set: false,
            permissions_parsed: 0,
            access_rules_defined: 0,
            operations_allowed: 0,
            operations_denied: 0,
            audit_entries: Vec::new(),
        }
    }
}

impl Default for SecurityPermissions {
    fn default() -> Self {
        Self {
            print_allowed: true,
            modify_allowed: true,
            copy_allowed: true,
            annotate_allowed: true,
            form_fill_allowed: true,
            accessibility_allowed: true,
            assemble_allowed: true,
            print_high_quality_allowed: true,
            raw_permissions: 0xFFFFFFFC, // All permissions enabled
        }
    }
}

/// Security errors
#[derive(Debug, Clone)]
pub enum SecurityError {
    NoSecurityParams,
    UnsupportedHandler(String),
    InvalidKeyLength(usize),
    InvalidData(String),
    AccessDenied(String),
    ValidationFailed(String),
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityError::NoSecurityParams => write!(f, "No security parameters available"),
            SecurityError::UnsupportedHandler(handler) => write!(f, "Unsupported security handler: {}", handler),
            SecurityError::InvalidKeyLength(length) => write!(f, "Invalid key length: {}", length),
            SecurityError::InvalidData(msg) => write!(f, "Invalid security data: {}", msg),
            SecurityError::AccessDenied(msg) => write!(f, "Access denied: {}", msg),
            SecurityError::ValidationFailed(msg) => write!(f, "Security validation failed: {}", msg),
        }
    }
}

impl std::error::Error for SecurityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_handler_creation() {
        let handler = SecurityHandler::new();
        assert!(handler.security_params.is_none());
        assert!(!handler.stats.security_params_set);
    }

    #[test]
    fn test_permission_parsing() {
        let handler = SecurityHandler::new();
        let permissions = handler.parse_permissions(0xFFFFFFFC).unwrap();
        
        assert!(permissions.print_allowed);
        assert!(permissions.modify_allowed);
        assert!(permissions.copy_allowed);
        assert!(permissions.annotate_allowed);
    }

    #[test]
    fn test_password_strength_validation() {
        let handler = SecurityHandler::new();
        
        assert_eq!(handler.validate_password_strength("123"), PasswordStrength::Weak);
        assert_eq!(handler.validate_password_strength("password123"), PasswordStrength::Fair);
        assert_eq!(handler.validate_password_strength("Password123"), PasswordStrength::Good);
        assert_eq!(handler.validate_password_strength("Password123!@#"), PasswordStrength::Strong);
    }

    #[test]
    fn test_permission_flag_generation() {
        let handler = SecurityHandler::new();
        
        assert_eq!(handler.generate_permission_flags(&AccessLevel::NoAccess), 0x00000000);
        assert_eq!(handler.generate_permission_flags(&AccessLevel::ReadOnly), 0x00000004);
        assert_eq!(handler.generate_permission_flags(&AccessLevel::Full), 0x0000FFFC);
    }

    #[test]
    fn test_security_level_calculation() {
        let mut handler = SecurityHandler::new();
        assert_eq!(handler.calculate_security_level(), SecurityLevel::None);
        
        // Test with parameters would require setting up EncryptionParams
        // This is a basic test to ensure the method works
    }

    #[test]
    fn test_operations_for_permissions() {
        let handler = SecurityHandler::new();
        let operations = handler.operations_for_permissions(0x14); // Print + Copy
        
        assert!(operations.contains(&SecurityOperation::Print));
        assert!(operations.contains(&SecurityOperation::Copy));
        assert!(!operations.contains(&SecurityOperation::Modify));
    }
}
```

### Step 2: Update lib.rs
Add to `src/lib.rs`:

```rust
pub mod security_handler;
pub use security_handler::{SecurityHandler, SecurityError, SecurityPermissions, SecurityOperation, AccessLevel};
```

### Step 3: Validation Commands
```bash
cargo check --lib
cargo build --lib
cargo test security_handler
```

Let me continue with the remaining modules 16-19...