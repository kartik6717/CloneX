//! PDF parsing and manipulation module

mod parser;
mod objects;
mod xref;
mod dict;

pub use parser::PDFParser;
use objects::{PDFObject, PDFObjectType};
use xref::XRefTable;
use dict::Dictionary;

use std::collections::HashMap;
use std::io::{self, Read, Write, Seek};
use crate::error::PDFCryptoError;
