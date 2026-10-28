use super::*;
use crate::encryption::{KeyPair, to_base64};

#[test]
fn test_hash_uses_raw_key_bytes() {
    // sha256 of the 32 raw key bytes, not of the base64 serialization.
    let mut key_bytes = [0u8; 32];
    for (i, b) in key_bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let expected_hex: String = Sha256::digest(key_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let key = EncryptionKey::from_base64(&to_base64(&key_bytes)).unwrap();
    let hash = hash_public_key(&key);
    assert_eq!(hash, expected_hex[..16]);
    assert_eq!(hash, "630dcd2966c43366");
    assert_ne!(
        hash,
        Sha256::digest(key.to_string().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()[..16]
    );
}

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
