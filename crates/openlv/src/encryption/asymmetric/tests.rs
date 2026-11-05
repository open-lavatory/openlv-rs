use super::*;

#[test]
fn test_key_pair_generation() {
    let key_pair = KeyPair::generate().unwrap();
    assert_eq!(key_pair.encryption_key.as_bytes().len(), 32);
    assert_eq!(from_base64(key_pair.decryption_key.to_string()).unwrap().len(), 32);
}

#[test]
fn test_restored_keys_are_canonical() {
    let key_pair = KeyPair::generate().unwrap();
    let public = EncryptionKey::from_base64(key_pair.encryption_key.to_string()).unwrap();
    let secret = DecryptionKey::from_base64(key_pair.decryption_key.to_string()).unwrap();
    assert_eq!(public.to_string(), key_pair.encryption_key.to_string());
    assert_eq!(secret.to_string(), key_pair.decryption_key.to_string());
}

#[test]
fn test_rejects_low_order_peer_keys() {
    let key_pair = KeyPair::generate().unwrap();
    let low_order = EncryptionKey::from_bytes([0; 32]).unwrap();
    assert!(key_pair.decryption_key.shared_secret(&low_order).is_err());
}
