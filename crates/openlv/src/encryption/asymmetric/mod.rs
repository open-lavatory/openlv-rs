use std::fmt;

use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use super::{from_base64, to_base64};
use crate::errors::OpenLvError;

const PUBLIC_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const KEY_INFO: &[u8] = b"openlv/1 peer-key";

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
    public_key: [u8; PUBLIC_KEY_BYTES],
    serialized: String,
}

impl Clone for DecryptionKey {
    fn clone(&self) -> Self {
        Self {
            secret_key: StaticSecret::from(self.secret_key.to_bytes()),
            public_key: self.public_key,
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

    pub fn from_ciphertext(ciphertext: &str) -> Result<Self, OpenLvError> {
        let bytes = from_base64(ciphertext)?;
        let sender = bytes
            .get(..PUBLIC_KEY_BYTES)
            .ok_or_else(|| OpenLvError::Encryption("encrypted payload is malformed".into()))?;

        Self::from_base64(&to_base64(sender))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.public_key
    }

    pub fn to_string(&self) -> &str {
        &self.serialized
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
        let secret_key = StaticSecret::from(secret_bytes);

        Ok(Self {
            public_key: *X25519PublicKey::from(&secret_key).as_bytes(),
            secret_key,
            serialized: serialized.to_string(),
        })
    }

    pub fn to_string(&self) -> &str {
        &self.serialized
    }

    fn cipher(&self, peer_public_key: &[u8], info: &[u8]) -> Result<Aes256Gcm, OpenLvError> {
        let peer_public_key = <[u8; PUBLIC_KEY_BYTES]>::try_from(peer_public_key)
            .map_err(|_| OpenLvError::Encryption("public key must be 32 bytes".into()))?;
        let shared_secret = self
            .secret_key
            .diffie_hellman(&X25519PublicKey::from(peer_public_key));
        if !shared_secret.was_contributory() {
            return Err(OpenLvError::Encryption(
                "peer public key yields an all-zero shared secret".into(),
            ));
        }

        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(None, shared_secret.as_bytes())
            .expand(info, &mut key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");

        Ok(Aes256Gcm::new(&key.into()))
    }

    pub fn encrypt(&self, message: &str, peer: &EncryptionKey) -> Result<String, OpenLvError> {
        let cipher = self.cipher(
            &peer.public_key,
            &[KEY_INFO, &self.public_key, &peer.public_key].concat(),
        )?;

        let mut nonce = [0u8; NONCE_BYTES];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), message.as_bytes())
            .map_err(|error| OpenLvError::Encryption(error.to_string()))?;

        let mut payload = Vec::with_capacity(PUBLIC_KEY_BYTES + NONCE_BYTES + ciphertext.len());
        payload.extend_from_slice(&self.public_key);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);

        Ok(to_base64(&payload))
    }

    pub fn decrypt(
        &self,
        message: &str,
        peer: Option<&EncryptionKey>,
    ) -> Result<String, OpenLvError> {
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

        let (sender, rest) = bytes.split_at(PUBLIC_KEY_BYTES);
        let (nonce, ciphertext) = rest.split_at(NONCE_BYTES);
        if peer.is_some_and(|peer| peer.as_bytes() != sender) {
            return Err(OpenLvError::Encryption(
                "sender key does not match the peer key".into(),
            ));
        }

        let plaintext = self
            .cipher(sender, &[KEY_INFO, sender, &self.public_key].concat())?
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|error| OpenLvError::Encryption(error.to_string()))?;

        String::from_utf8(plaintext).map_err(|error| OpenLvError::Encryption(error.to_string()))
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
                public_key: *public_key.as_bytes(),
                serialized: to_base64(&secret_bytes),
            },
        })
    }
}

pub fn parse_encryption_key(serialized: &str) -> Result<EncryptionKey, OpenLvError> {
    EncryptionKey::from_base64(serialized)
}

#[cfg(test)]
mod tests;
