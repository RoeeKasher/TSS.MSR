//! Error types for TPM operations

use std::fmt;
use std::error::Error;

/// TPM Error types
#[derive(Debug)]
pub enum TpmError {
    /// Buffer underflow occurred during deserialization
    BufferUnderflow,
    
    /// Buffer overflow occurred during serialization
    BufferOverflow,
    
    /// Invalid array size
    InvalidArraySize,
    
    /// Invalid enum value
    InvalidEnumValue,
    
    /// Invalid union type
    InvalidUnion,
    
    /// Incorrect tag value
    IncorrectTag(u32, u32), // expected, actual
    
    /// I/O error
    IoError(std::io::Error),
    
    /// Device communication error
    DeviceError(String),
    
    /// Generic TPM error
    GenericError(String),
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BufferUnderflow => write!(f, "Buffer underflow during deserialization"),
            Self::BufferOverflow => write!(f, "Buffer overflow during serialization"),
            Self::InvalidArraySize => write!(f, "Invalid array size"),
            Self::InvalidEnumValue => write!(f, "Invalid enum value"),
            Self::InvalidUnion => write!(f, "Invalid union type"),
            Self::IncorrectTag(expected, actual) => write!(f, "Incorrect tag: expected 0x{:X}, got 0x{:X}", expected, actual),
            Self::IoError(err) => write!(f, "I/O error: {}", err),
            Self::DeviceError(msg) => write!(f, "Device error: {}", msg),
            Self::GenericError(msg) => write!(f, "TPM error: {}", msg),
        }
    }
}

impl Error for TpmError {}

impl From<std::io::Error> for TpmError {
    fn from(error: std::io::Error) -> Self {
        TpmError::IoError(error)
    }
}