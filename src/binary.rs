use crate::blob::{BinaryType, Blob, BlobError};
use crate::elf::{self, ElfIdent};
use crate::pe;
use std::fmt::{self, Display};
use thiserror::Error;
use std::fs;
use std::path::Path;

#[derive(Error, Debug)]
pub enum BinaryError {
    #[error("corrupt binary")]
    NoPeBinary(#[from] pe::PeError),
    #[error("corrupt binary")]
    NoElfBinary(#[from] elf::ElfError),
    #[error("corrupt binary")]
    BlobCorrupted(#[from] BlobError),
}

type Result<T> = std::result::Result<T, BinaryError>;

pub enum Binary {
    Elf(ElfIdent),
    Pe,
    Unknown,
}

impl Binary {
    pub fn from_file(file_name: &Path) -> Result<Self> {
        let data = fs::read(file_name).map_err(|_| BlobError::FileNotFound)?;
        let blob = Blob::new(data)?;
        Self::new(blob)
    }

    pub fn new(blob: Blob) -> Result<Self> {
        match blob.bin_type {
            BinaryType::Elf(elf_ident) => {
                Ok(Self::Elf(elf_ident))
            }
            BinaryType::Pe => Ok(Self::Pe),
            _ => Ok(Self::Unknown),
        }
    }
}

impl Display for Binary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::result::Result<(), fmt::Error> {
        match self {
            Binary::Elf(elf_ident) => {
                write!(f, "elf")?;
                write!(f, "{elf_ident}")
            }
            Binary::Pe => write!(f, "pe"),
            Binary::Unknown => write!(f, "unknown"),
        }
    }
}

impl Default for Binary {
    fn default() -> Self {
        Self::Unknown
    }
}