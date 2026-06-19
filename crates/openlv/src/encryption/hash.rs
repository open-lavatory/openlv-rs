use sha2::{Digest, Sha256};

use super::asymmetric::EncryptionKey;
use crate::errors::OpenLvError;

const HASH_LENGTH: usize = 16;

#[derive(Debug, PartialEq, Clone)]
pub struct PublicKeyHash(pub String);

impl From<&EncryptionKey> for PublicKeyHash {
    fn from(public_key: &EncryptionKey) -> Self {
        PublicKeyHash(hash_public_key(public_key))
    }
}

pub fn hash_public_key(public_key: &EncryptionKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key.to_string().as_bytes());
    let digest = hasher.finalize();
    let hash_hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    hash_hex.chars().take(HASH_LENGTH).collect()
}

pub fn validate_public_key_hash(
    public_key: &EncryptionKey,
    expected_hash: &str,
) -> Result<bool, OpenLvError> {
    Ok(hash_public_key(public_key) == expected_hash)
}

pub struct InitHash {
    pub hash: String,
    pub is_host: bool,
}

pub fn init_hash(
    initial_hash: Option<&str>,
    encryption_key: &EncryptionKey,
) -> Result<InitHash, OpenLvError> {
    let our_hash = hash_public_key(encryption_key);
    let hash = initial_hash.unwrap_or(&our_hash).to_string();
    let is_host = hash == our_hash;

    Ok(InitHash { hash, is_host })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::KeyPair;

    #[test]
    fn test_hash_length() {
        let key_pair = KeyPair::generate().unwrap();
        let hash = hash_public_key(&key_pair.encryption_key);
        assert_eq!(hash.len(), 16);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_init_hash_host_detection() {
        let key_pair = KeyPair::generate().unwrap();
        let hash = hash_public_key(&key_pair.encryption_key);
        let host = init_hash(None, &key_pair.encryption_key).unwrap();
        assert!(host.is_host);
        assert_eq!(host.hash, hash);

        let client = init_hash(Some(&hash), &KeyPair::generate().unwrap().encryption_key).unwrap();
        assert!(!client.is_host);
        assert_eq!(client.hash, hash);
    }
}
