use super::*;

#[test]
fn test_key_pair_generation() {
    let key_pair = KeyPair::generate().unwrap();
    assert!(!key_pair.encryption_key.to_string().is_empty());
    assert!(!key_pair.decryption_key.to_string().is_empty());
}

#[test]
fn test_encrypt_decrypt_round_trip() {
    let key_pair = KeyPair::generate().unwrap();
    let encrypted = key_pair.encryption_key.encrypt("test").unwrap();
    let decrypted = key_pair.decryption_key.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, "test");
}

#[test]
fn test_parsed_key_encrypts_to_holder() {
    let key_pair = KeyPair::generate().unwrap();
    let parsed = parse_encryption_key(key_pair.encryption_key.to_string()).unwrap();
    let encrypted = parsed.encrypt("test").unwrap();
    let decrypted = key_pair.decryption_key.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, "test");
}
