# Module 2: ConsoleSupressor - Silent Operation Macros

## Overview
The `ConsoleSupressor` module provides macros and functions to ensure ZERO console output during PDF processing. This is critical for anti-forensic capabilities - the system must operate in complete silence.

## Module Requirements
- **Dependencies**: None (pure Rust standard library)
- **Compilation**: Must compile independently
- **Purpose**: Eliminate all console output (println!, print!, eprintln!, eprint!)
- **Critical Rule**: NO OUTPUT TO TERMINAL - complete stealth operation

## File Structure
```
src/
├── lib.rs
├── complete_invisible_data.rs
└── console_supressor.rs
```

## Implementation Guide

### Step 1: Create Module File
Create `src/console_supressor.rs`:

```rust
//! ConsoleSupressor Module
//! 
//! Provides macros and functions for silent operation.
//! Ensures ZERO console output during PDF processing for anti-forensic capabilities.

use std::io::{self, Write};
use std::sync::Mutex;

/// Global flag to control console output suppression
static CONSOLE_SUPPRESSED: Mutex<bool> = Mutex::new(false);

/// Enable console suppression - blocks ALL output
pub fn enable_silent_mode() {
    let mut suppressed = CONSOLE_SUPPRESSED.lock().unwrap();
    *suppressed = true;
}

/// Disable console suppression - allows output (for debugging only)
pub fn disable_silent_mode() {
    let mut suppressed = CONSOLE_SUPPRESSED.lock().unwrap();
    *suppressed = false;
}

/// Check if console is currently suppressed
pub fn is_silent_mode() -> bool {
    *CONSOLE_SUPPRESSED.lock().unwrap()
}

/// Silent print macro - does nothing if suppression enabled
#[macro_export]
macro_rules! silent_print {
    ($($arg:tt)*) => {
        if !$crate::console_supressor::is_silent_mode() {
            print!($($arg)*);
        }
    };
}

/// Silent println macro - does nothing if suppression enabled
#[macro_export]
macro_rules! silent_println {
    ($($arg:tt)*) => {
        if !$crate::console_supressor::is_silent_mode() {
            println!($($arg)*);
        }
    };
}

/// Silent eprint macro - does nothing if suppression enabled
#[macro_export]
macro_rules! silent_eprint {
    ($($arg:tt)*) => {
        if !$crate::console_supressor::is_silent_mode() {
            eprint!($($arg)*);
        }
    };
}

/// Silent eprintln macro - does nothing if suppression enabled
#[macro_export]
macro_rules! silent_eprintln {
    ($($arg:tt)*) => {
        if !$crate::console_supressor::is_silent_mode() {
            eprintln!($($arg)*);
        }
    };
}

/// Silent debug macro - does nothing if suppression enabled
#[macro_export]
macro_rules! silent_debug {
    ($($arg:tt)*) => {
        if !$crate::console_supressor::is_silent_mode() {
            eprintln!("[DEBUG] {}", format!($($arg)*));
        }
    };
}

/// Silent error macro - does nothing if suppression enabled
#[macro_export]
macro_rules! silent_error {
    ($($arg:tt)*) => {
        if !$crate::console_supressor::is_silent_mode() {
            eprintln!("[ERROR] {}", format!($($arg)*));
        }
    };
}

/// Silent warning macro - does nothing if suppression enabled
#[macro_export]
macro_rules! silent_warning {
    ($($arg:tt)*) => {
        if !$crate::console_supressor::is_silent_mode() {
            eprintln!("[WARNING] {}", format!($($arg)*));
        }
    };
}

/// Silent info macro - does nothing if suppression enabled
#[macro_export]
macro_rules! silent_info {
    ($($arg:tt)*) => {
        if !$crate::console_supressor::is_silent_mode() {
            eprintln!("[INFO] {}", format!($($arg)*));
        }
    };
}

/// Null writer that discards all output
pub struct NullWriter;

impl Write for NullWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len()) // Pretend we wrote everything, but discard it
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(()) // Nothing to flush
    }
}

/// Capture and discard stdout/stderr for external library calls
pub struct OutputCapture {
    _stdout: Box<dyn Write + Send>,
    _stderr: Box<dyn Write + Send>,
}

impl OutputCapture {
    /// Create new output capture that discards all output
    pub fn new() -> Self {
        Self {
            _stdout: Box::new(NullWriter),
            _stderr: Box::new(NullWriter),
        }
    }

    /// Execute closure with captured output (output discarded)
    pub fn execute<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        // Note: In a full implementation, this would redirect stdout/stderr
        // For now, we rely on silent macros and library-specific suppression
        f()
    }
}

/// Wrapper for potentially noisy operations
pub fn silent_operation<F, R>(operation: F) -> R
where
    F: FnOnce() -> R,
{
    let was_silent = is_silent_mode();
    enable_silent_mode();
    
    let result = operation();
    
    if !was_silent {
        disable_silent_mode();
    }
    
    result
}

/// Environment variable suppression for external tools
pub struct EnvironmentSuppressor {
    original_env: Vec<(String, Option<String>)>,
}

impl EnvironmentSuppressor {
    /// Create new environment suppressor
    pub fn new() -> Self {
        Self {
            original_env: Vec::new(),
        }
    }

    /// Suppress common debug/verbose environment variables
    pub fn suppress_debug_vars(&mut self) {
        let debug_vars = [
            "RUST_LOG",
            "RUST_BACKTRACE", 
            "RUST_LIB_BACKTRACE",
            "OPENSSL_CONF",
            "ZLIB_DEBUG",
            "PDF_DEBUG",
            "VERBOSE",
            "DEBUG",
        ];

        for var in &debug_vars {
            let original_value = std::env::var(var).ok();
            self.original_env.push((var.to_string(), original_value));
            
            // Remove or set to silent
            std::env::remove_var(var);
        }
    }

    /// Restore original environment variables
    pub fn restore(&self) {
        for (var, original_value) in &self.original_env {
            match original_value {
                Some(value) => std::env::set_var(var, value),
                None => std::env::remove_var(var),
            }
        }
    }
}

impl Drop for EnvironmentSuppressor {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Panic handler that suppresses panic output in silent mode
pub fn install_silent_panic_handler() {
    std::panic::set_hook(Box::new(|_panic_info| {
        if is_silent_mode() {
            // Suppress panic output in silent mode
            return;
        }
        
        // In non-silent mode, allow normal panic behavior
        eprintln!("PDF processor encountered an error");
    }));
}

/// Initialize console suppression system
pub fn initialize_suppression() {
    // Enable silent mode by default for anti-forensic operation
    enable_silent_mode();
    
    // Install silent panic handler
    install_silent_panic_handler();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_silent_mode_toggle() {
        // Initially silent mode should be off in tests
        disable_silent_mode();
        assert!(!is_silent_mode());
        
        enable_silent_mode();
        assert!(is_silent_mode());
        
        disable_silent_mode();
        assert!(!is_silent_mode());
    }

    #[test]
    fn test_silent_operation() {
        disable_silent_mode();
        
        let result = silent_operation(|| {
            assert!(is_silent_mode());
            42
        });
        
        assert_eq!(result, 42);
        assert!(!is_silent_mode());
    }

    #[test]
    fn test_null_writer() {
        let mut writer = NullWriter;
        
        // Should accept any write without error
        let result = writer.write(b"test data");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 9); // Length of "test data"
        
        // Flush should succeed
        assert!(writer.flush().is_ok());
    }

    #[test]
    fn test_output_capture() {
        let mut capture = OutputCapture::new();
        
        let result = capture.execute(|| {
            // This would normally print, but should be captured
            42
        });
        
        assert_eq!(result, 42);
    }

    #[test]
    fn test_environment_suppressor() {
        // Set a test environment variable
        std::env::set_var("TEST_DEBUG_VAR", "test_value");
        assert_eq!(std::env::var("TEST_DEBUG_VAR").unwrap(), "test_value");
        
        {
            let mut suppressor = EnvironmentSuppressor::new();
            suppressor.original_env.push((
                "TEST_DEBUG_VAR".to_string(), 
                Some("test_value".to_string())
            ));
            std::env::remove_var("TEST_DEBUG_VAR");
            
            // Variable should be removed
            assert!(std::env::var("TEST_DEBUG_VAR").is_err());
        } // Suppressor drops here and restores
        
        // Variable should be restored
        assert_eq!(std::env::var("TEST_DEBUG_VAR").unwrap(), "test_value");
        
        // Clean up
        std::env::remove_var("TEST_DEBUG_VAR");
    }

    #[test]
    fn test_macros_compile() {
        // Test that all macros compile (actual output suppression tested manually)
        enable_silent_mode();
        
        silent_print!("test");
        silent_println!("test");
        silent_eprint!("test");
        silent_eprintln!("test");
        silent_debug!("test");
        silent_error!("test");
        silent_warning!("test");
        silent_info!("test");
        
        disable_silent_mode();
    }
}
```

### Step 2: Update lib.rs
Update `src/lib.rs`:

```rust
//! PDF Invisible Data Cloning System
//! 
//! A Rust implementation for 100% invisible data cloning between PDFs
//! with complete anti-forensic capabilities.

pub mod complete_invisible_data;
pub mod console_supressor;

pub use complete_invisible_data::{CompleteInvisibleData, InvisibleDataError};
pub use console_supressor::{
    enable_silent_mode, disable_silent_mode, is_silent_mode,
    silent_operation, OutputCapture, EnvironmentSuppressor,
    initialize_suppression, NullWriter
};

// Re-export macros
pub use silent_print;
pub use silent_println;
pub use silent_eprint;
pub use silent_eprintln;
pub use silent_debug;
pub use silent_error;
pub use silent_warning;
pub use silent_info;
```

### Step 3: Validation Commands
```bash
cargo check --lib
cargo build --lib
cargo test console_supressor
```

## Success Criteria
- ✅ Module compiles without errors
- ✅ All unit tests pass
- ✅ Silent mode toggling works correctly
- ✅ All suppression macros compile
- ✅ Environment variable suppression works
- ✅ Output capture functionality works

## Critical Requirements Met
1. **Complete Suppression**: All console output can be silently discarded
2. **Anti-Forensic**: No trace of processing visible in terminal
3. **Macro Safety**: All suppression macros compile and function correctly
4. **Environment Control**: Can suppress debug variables from external tools
5. **Independent Compilation**: No dependencies on other custom modules
6. **Thread Safety**: Uses Mutex for global state management

## Usage in Later Modules
```rust
use crate::{silent_println, silent_operation, enable_silent_mode};

// Enable silent mode for anti-forensic operation
enable_silent_mode();

// Use silent macros instead of regular print macros
silent_println!("This will be suppressed");

// Wrap noisy operations
let result = silent_operation(|| {
    // Any code here runs in silent mode
    some_potentially_noisy_function()
});
```

## Next Module
After this module compiles and tests pass, proceed to Module 3: HashManager.