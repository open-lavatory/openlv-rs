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
    assert_eq!(key.decrypt(&encrypted).unwrap(), "hello");
}

#[test]
fn test_tampering_and_wrong_key_are_rejected() {
    let key = HandshakeKey::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let other = HandshakeKey::from_hex("101112131415161718191a1b1c1d1e1f").unwrap();
    let encrypted = key.encrypt("hello").unwrap();
    assert!(other.decrypt(&encrypted).is_err());

    let mut bytes = from_base64(&encrypted).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    assert!(key.decrypt(&to_base64(&bytes)).is_err());
}

#[test]
fn test_debug_does_not_expose_key_material() {
    let key = HandshakeKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
    assert!(!format!("{key:?}").contains(key.to_hex()));
}
