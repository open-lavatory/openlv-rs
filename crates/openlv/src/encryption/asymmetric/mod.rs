use std::fmt;

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use super::{from_base64, to_base64};
use crate::errors::OpenLvError;

const PUBLIC_KEY_BYTES: usize = 32;
const SECRET_KEY_BYTES: usize = 32;

#[derive(Clone)]
pub struct EncryptionKey {
    public_key: [u8; PUBLIC_KEY_BYTES],
    serialized: String,
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptionKey")
            .finish_non_exhaustive()
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecryptionKey")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct KeyPair {
    pub encryption_key: EncryptionKey,
    pub decryption_key: DecryptionKey,
}

fn shared_secret(
    secret_key: &StaticSecret,
    peer_public_key: &[u8],
) -> Result<[u8; SECRET_KEY_BYTES], OpenLvError> {
    let peer_public_key = <[u8; PUBLIC_KEY_BYTES]>::try_from(peer_public_key)
        .map_err(|_| OpenLvError::Encryption("public key must be 32 bytes".into()))?;
    let shared = secret_key.diffie_hellman(&X25519PublicKey::from(peer_public_key));
    if !shared.was_contributory() {
        return Err(OpenLvError::Encryption(
            "peer public key yields an all-zero shared secret".into(),
        ));
    }

    Ok(*shared.as_bytes())
}

impl EncryptionKey {
    pub fn from_base64(serialized: &str) -> Result<Self, OpenLvError> {
        let bytes = from_base64(serialized)?;
        Self::from_bytes(
            bytes
                .try_into()
                .map_err(|_| OpenLvError::Encryption("public key must be 32 bytes".into()))?,
        )
    }

    pub(crate) fn from_bytes(public_key: [u8; PUBLIC_KEY_BYTES]) -> Result<Self, OpenLvError> {
        Ok(Self {
            serialized: to_base64(&public_key),
            public_key,
        })
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
        let secret_bytes: [u8; SECRET_KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| OpenLvError::Encryption("secret key must be 32 bytes".into()))?;
        let secret_key = StaticSecret::from(secret_bytes);

        Ok(Self {
            secret_key,
            serialized: to_base64(&secret_bytes),
        })
    }

    pub fn to_string(&self) -> &str {
        &self.serialized
    }

    pub(crate) fn shared_secret(
        &self,
        peer_key: &EncryptionKey,
    ) -> Result<[u8; SECRET_KEY_BYTES], OpenLvError> {
        shared_secret(&self.secret_key, peer_key.as_bytes())
    }
}

impl KeyPair {
    pub fn generate() -> Result<Self, OpenLvError> {
        let secret_key = StaticSecret::random_from_rng(rand::thread_rng());
        let public_key = X25519PublicKey::from(&secret_key);
        let secret_bytes = secret_key.to_bytes();

        Ok(Self {
            encryption_key: EncryptionKey::from_bytes(*public_key.as_bytes())?,
            decryption_key: DecryptionKey {
                secret_key,
                serialized: to_base64(&secret_bytes),
            },
        })
    }

    pub fn from_base64(public_key: &str, secret_key: &str) -> Result<Self, OpenLvError> {
        let encryption_key = EncryptionKey::from_base64(public_key)?;
        let decryption_key = DecryptionKey::from_base64(secret_key)?;
        let derived_public = X25519PublicKey::from(&decryption_key.secret_key);
        if derived_public.as_bytes() != encryption_key.as_bytes() {
            return Err(OpenLvError::Encryption(
                "secret key does not match public key".into(),
            ));
        }

        Ok(Self {
            encryption_key,
            decryption_key,
        })
    }
}

pub fn parse_encryption_key(serialized: &str) -> Result<EncryptionKey, OpenLvError> {
    EncryptionKey::from_base64(serialized)
}

#[cfg(test)]
mod tests;
