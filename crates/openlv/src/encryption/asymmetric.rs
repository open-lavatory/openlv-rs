use std::fmt;

use aead::{Aead, KeyInit};
use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};
use rand::RngCore;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use super::{from_base64, to_base64};
use crate::errors::OpenLvError;

const PUBLIC_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;

#[derive(Clone)]
pub struct EncryptionKey {
    public_key: [u8; PUBLIC_KEY_BYTES],
    serialized: String,
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionKey").finish_non_exhaustive()
    }
}

pub struct DecryptionKey {
    secret_key: StaticSecret,
    serialized: String,
}

impl Clone for DecryptionKey {
    fn clone(&self) -> Self {
        Self {
            secret_key: StaticSecret::from(self.secret_key.to_bytes()),
            serialized: self.serialized.clone(),
        }
    }
}

impl fmt::Debug for DecryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptionKey").finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct KeyPair {
    pub encryption_key: EncryptionKey,
    pub decryption_key: DecryptionKey,
}

impl EncryptionKey {
    pub fn from_base64(serialized: &str) -> Result<Self, OpenLvError> {
        let bytes = from_base64(serialized)?;
        if bytes.len() != PUBLIC_KEY_BYTES {
            return Err(OpenLvError::Encryption(
                "public key must be 32 bytes".into(),
            ));
        }

        let mut public_key = [0u8; PUBLIC_KEY_BYTES];
        public_key.copy_from_slice(&bytes);

        Ok(Self {
            public_key,
            serialized: serialized.to_string(),
        })
    }

    pub fn to_string(&self) -> &str {
        &self.serialized
    }

    pub fn encrypt(&self, message: &str) -> Result<String, OpenLvError> {
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        let remote_public = X25519PublicKey::from(self.public_key);
        let shared_secret = ephemeral_secret.diffie_hellman(&remote_public);

        let mut nonce = [0u8; NONCE_BYTES];
        rand::thread_rng().fill_bytes(&mut nonce);

        let key = Key::from_slice(shared_secret.as_bytes());
        let cipher = XSalsa20Poly1305::new(key);
        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce, message.as_bytes())
            .map_err(|error| OpenLvError::Encryption(error.to_string()))?;

        let mut payload =
            Vec::with_capacity(PUBLIC_KEY_BYTES + NONCE_BYTES + ciphertext.len());
        payload.extend_from_slice(ephemeral_public.as_bytes());
        payload.extend_from_slice(nonce);
        payload.extend_from_slice(&ciphertext);

        Ok(to_base64(&payload))
    }
}

impl DecryptionKey {
    pub fn from_base64(serialized: &str) -> Result<Self, OpenLvError> {
        let bytes = from_base64(serialized)?;
        if bytes.len() != PUBLIC_KEY_BYTES {
            return Err(OpenLvError::Encryption(
                "secret key must be 32 bytes".into(),
            ));
        }

        let mut secret_bytes = [0u8; PUBLIC_KEY_BYTES];
        secret_bytes.copy_from_slice(&bytes);

        Ok(Self {
            secret_key: StaticSecret::from(secret_bytes),
            serialized: serialized.to_string(),
        })
    }

    pub fn to_string(&self) -> &str {
        &self.serialized
    }

    pub fn decrypt(&self, message: &str) -> Result<String, OpenLvError> {
        if message.is_empty() {
            return Err(OpenLvError::Encryption(
                "cannot decrypt an empty payload".into(),
            ));
        }

        let bytes = from_base64(message)?;
        if bytes.len() <= PUBLIC_KEY_BYTES + NONCE_BYTES {
            return Err(OpenLvError::Encryption(
                "encrypted payload is malformed".into(),
            ));
        }

        let ephemeral_public = X25519PublicKey::from(
            <[u8; PUBLIC_KEY_BYTES]>::try_from(&bytes[..PUBLIC_KEY_BYTES])
                .map_err(|_| OpenLvError::Encryption("invalid ephemeral public key".into()))?,
        );
        let nonce = &bytes[PUBLIC_KEY_BYTES..PUBLIC_KEY_BYTES + NONCE_BYTES];
        let ciphertext = &bytes[PUBLIC_KEY_BYTES + NONCE_BYTES..];

        let shared_secret = self.secret_key.diffie_hellman(&ephemeral_public);
        let key = Key::from_slice(shared_secret.as_bytes());
        let cipher = XSalsa20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|error| OpenLvError::Encryption(error.to_string()))?;

        String::from_utf8(plaintext)
            .map_err(|error| OpenLvError::Encryption(error.to_string()))
    }
}

impl KeyPair {
    pub fn generate() -> Result<Self, OpenLvError> {
        let secret_key = StaticSecret::random_from_rng(rand::thread_rng());
        let public_key = X25519PublicKey::from(&secret_key);
        let secret_bytes = secret_key.to_bytes();

        Ok(Self {
            encryption_key: EncryptionKey {
                public_key: *public_key.as_bytes(),
                serialized: to_base64(public_key.as_bytes()),
            },
            decryption_key: DecryptionKey {
                secret_key,
                serialized: to_base64(&secret_bytes),
            },
        })
    }
}

pub fn parse_encryption_key(serialized: &str) -> Result<EncryptionKey, OpenLvError> {
    EncryptionKey::from_base64(serialized)
}

#[cfg(test)]
mod tests {
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
}
