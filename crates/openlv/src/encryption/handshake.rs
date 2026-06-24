use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;

use super::{from_base64, to_base64};
use crate::errors::OpenLvError;

const IV_LENGTH: usize = 12;

#[derive(Clone)]
pub struct HandshakeKey {
    hex: String,
    cipher: Aes128Gcm,
}

impl std::fmt::Debug for HandshakeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeKey")
            .field("hex", &self.hex)
            .finish()
    }
}

impl PartialEq for HandshakeKey {
    fn eq(&self, other: &Self) -> bool {
        self.hex == other.hex
    }
}

impl HandshakeKey {
    pub fn from_hex(hex: &str) -> Result<Self, OpenLvError> {
        if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(OpenLvError::Encryption(
                "handshake key must be 32 lowercase hex characters".into(),
            ));
        }

        let mut key_bytes = [0u8; 16];
        for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let value = std::str::from_utf8(chunk)
                .map_err(|error| OpenLvError::Encryption(error.to_string()))?;
            key_bytes[index] = u8::from_str_radix(value, 16)
                .map_err(|error| OpenLvError::Encryption(error.to_string()))?;
        }

        let cipher = Aes128Gcm::new_from_slice(&key_bytes)
            .map_err(|error| OpenLvError::Encryption(error.to_string()))?;

        Ok(Self {
            hex: hex.to_ascii_lowercase(),
            cipher,
        })
    }

    pub fn generate() -> Result<Self, OpenLvError> {
        let mut key_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let hex = key_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Self::from_hex(&hex)
    }

    pub fn to_hex(&self) -> &str {
        &self.hex
    }

    pub fn encrypt(&self, message: &str) -> Result<String, OpenLvError> {
        let mut iv = [0u8; IV_LENGTH];
        rand::thread_rng().fill_bytes(&mut iv);
        let nonce = Nonce::from_slice(&iv);
        let ciphertext = self
            .cipher
            .encrypt(nonce, message.as_bytes())
            .map_err(|error| OpenLvError::Encryption(error.to_string()))?;

        let mut combined = Vec::with_capacity(IV_LENGTH + ciphertext.len());
        combined.extend_from_slice(&iv);
        combined.extend_from_slice(&ciphertext);

        Ok(to_base64(&combined))
    }

    pub fn decrypt(&self, message: &str) -> Result<String, OpenLvError> {
        let combined = from_base64(message)?;
        if combined.len() < IV_LENGTH {
            return Err(OpenLvError::Encryption(
                "encrypted payload is too short".into(),
            ));
        }

        let (iv, encrypted) = combined.split_at(IV_LENGTH);
        let nonce = Nonce::from_slice(iv);
        let plaintext = self
            .cipher
            .decrypt(nonce, encrypted)
            .map_err(|error| OpenLvError::Encryption(error.to_string()))?;

        String::from_utf8(plaintext).map_err(|error| OpenLvError::Encryption(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
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
}
