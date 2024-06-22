use crate::blob::{Blob, BinaryType};
use thiserror::Error;

type Result<T> = std::result::Result<T, PeError>;

#[derive(Error, Debug)]
pub enum PeError {
    #[error("no pe binary")]
    NoPeBinary,
}

pub struct PeBinary {
    _blob: Blob
}

impl PeBinary {
    pub fn new(blob: Blob) -> Result<Self> {
        if !matches!(blob.bin_type, BinaryType::Pe) {
            Err(PeError::NoPeBinary)
        } else {
            Ok(Self { _blob:blob })
        }
    }

    pub fn header_info(&self) -> Result<String> {
        Ok("Windows PE binary".to_string())
    }
}

