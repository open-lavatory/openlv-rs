pub mod asymmetric;
pub mod handshake;
pub mod hash;

pub use asymmetric::{parse_encryption_key, DecryptionKey, EncryptionKey, KeyPair};
pub use handshake::HandshakeKey;
pub use hash::{hash_public_key, init_hash, validate_public_key_hash, InitHash, PublicKeyHash};

use crate::errors::OpenLvError;

pub(crate) fn to_base64(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data)
}

pub(crate) fn from_base64(value: &str) -> Result<Vec<u8>, OpenLvError> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        .map_err(|error| OpenLvError::Encryption(error.to_string()))
}
