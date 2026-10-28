use super::*;

#[test]
fn test_generate_handshake_key() {
    let key = HandshakeKey::generate().unwrap();
    assert_eq!(key.to_hex().len(), 32);
}

#[test]
fn test_encrypt_decrypt_round_trip() {
    let key = HandshakeKey::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let encrypted = key.encrypt("hello").unwrap();
    let decrypted = key.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, "hello");
}

#[test]
fn test_derive_key_is_deterministic() {
    let key_a = HandshakeKey::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let key_b = HandshakeKey::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let encrypted = key_a.encrypt("hello").unwrap();
    assert_eq!(key_b.decrypt(&encrypted).unwrap(), "hello");
}
