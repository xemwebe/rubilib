pub mod blob;
pub mod elf;
pub mod table;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct EmptyPayload {}
