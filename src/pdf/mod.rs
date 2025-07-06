//! PDF parsing and manipulation module

mod parser;
mod objects;
mod xref;
mod dict;
mod stream;
mod filter;

pub use parser::PDFParser;
pub use dict::Dictionary;
use objects::{PDFObject, ObjectType};
use xref::XRefTable;
use stream::Stream;
use filter::Filter;

use std::collections::HashMap;
use std::io::{self, Read, Write, Seek};
use log::{debug, trace, warn};
use crate::error::{PDFCryptoError, PDFCryptoResult};

/// Common traits for PDF objects
pub(crate) trait PDFObjectCommon {
    /// Get object type
    fn get_type(&self) -> ObjectType;
    
    /// Write object to output
    fn write_to(&self, output: &mut Vec<u8>);
    
    /// Clone object
    fn clone_object(&self) -> Box<dyn PDFObjectCommon>;
}
