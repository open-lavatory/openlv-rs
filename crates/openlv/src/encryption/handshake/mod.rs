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

impl std::fmt::Display for HandshakeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex)
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
mod tests;
