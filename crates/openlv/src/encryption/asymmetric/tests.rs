use super::*;

#[test]
fn test_key_pair_generation() {
    let key_pair = KeyPair::generate().unwrap();
    assert!(!key_pair.encryption_key.to_string().is_empty());
    assert!(!key_pair.decryption_key.to_string().is_empty());
}

#[test]
fn test_encrypt_decrypt_round_trip() {
    let alice = KeyPair::generate().unwrap();
    let bob = KeyPair::generate().unwrap();
    let encrypted = alice
        .decryption_key
        .encrypt("test", &bob.encryption_key)
        .unwrap();
    let decrypted = bob
        .decryption_key
        .decrypt(&encrypted, Some(&alice.encryption_key))
        .unwrap();
    assert_eq!(decrypted, "test");
}

#[test]
fn test_parsed_key_encrypts_to_holder() {
    let alice = KeyPair::generate().unwrap();
    let bob = KeyPair::generate().unwrap();
    let parsed = parse_encryption_key(bob.encryption_key.to_string()).unwrap();
    let encrypted = alice.decryption_key.encrypt("test", &parsed).unwrap();
    let decrypted = bob.decryption_key.decrypt(&encrypted, None).unwrap();
    assert_eq!(decrypted, "test");
}

#[test]
fn test_decrypts_shared_test_vector() {
    // Same bytes as the TypeScript test: sender secret 0x01 * 32, receiver secret 0x02 * 32, nonce 0x03 * 12.
    let receiver =
        DecryptionKey::from_base64("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=").unwrap();
    let sender = parse_encryption_key("pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk=").unwrap();
    let ciphertext = "pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogkDAwMDAwMDAwMDAwOL3klAuRZ1a2kM5EryzNjgXIUN6C2hj8Att8QbUqi3iEg5GNHlNL2Q3C//";

    assert_eq!(
        receiver.decrypt(ciphertext, Some(&sender)).unwrap(),
        "openlv peer-key test vector"
    );
}

#[test]
fn test_rejects_ciphertext_from_different_sender_key() {
    let alice = KeyPair::generate().unwrap();
    let bob = KeyPair::generate().unwrap();
    let mallory = KeyPair::generate().unwrap();
    let ciphertext = mallory
        .decryption_key
        .encrypt("test", &bob.encryption_key)
        .unwrap();

    assert_eq!(
        bob.decryption_key
            .decrypt(&ciphertext, Some(&mallory.encryption_key))
            .unwrap(),
        "test"
    );
    assert!(
        bob.decryption_key
            .decrypt(&ciphertext, Some(&alice.encryption_key))
            .is_err()
    );
}

#[test]
fn test_rejects_ciphertext_reflected_back_to_its_sender() {
    let alice = KeyPair::generate().unwrap();
    let bob = KeyPair::generate().unwrap();
    let ciphertext = alice
        .decryption_key
        .encrypt("test", &bob.encryption_key)
        .unwrap();
    let mut reflected = from_base64(&ciphertext).unwrap();
    reflected[..PUBLIC_KEY_BYTES].copy_from_slice(bob.encryption_key.as_bytes());

    assert!(
        alice
            .decryption_key
            .decrypt(&to_base64(&reflected), Some(&bob.encryption_key))
            .is_err()
    );
}
