//! Peer-public-key authenticated encryption used after bootstrap.
//!
//! Each message carries the sender's static X25519 public key. The receiver
//! derives a direction-specific AES-256-GCM key from the X25519 shared secret
//! and rejects frames whose embedded sender key is not the pinned peer key.

use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

use super::{EncryptionKey, KeyPair, from_base64, to_base64};
use crate::errors::OpenLvError;

const PUBLIC_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const KEY_INFO: &[u8] = b"openlv/1 peer-key";

#[derive(Clone)]
pub struct PeerCipher {
    local_public_key: [u8; PUBLIC_KEY_BYTES],
    peer_public_key: [u8; PUBLIC_KEY_BYTES],
    send: Aes256Gcm,
    receive: Aes256Gcm,
}

impl std::fmt::Debug for PeerCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PeerCipher").finish_non_exhaustive()
    }
}

pub struct AcceptedPeer {
    pub peer_key: EncryptionKey,
    pub cipher: PeerCipher,
    pub message: String,
}

impl std::fmt::Debug for AcceptedPeer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcceptedPeer")
            .field("peer_key", &self.peer_key)
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

fn derive_key(
    shared_secret: &[u8; PUBLIC_KEY_BYTES],
    sender: &[u8; PUBLIC_KEY_BYTES],
    recipient: &[u8; PUBLIC_KEY_BYTES],
) -> Result<[u8; PUBLIC_KEY_BYTES], OpenLvError> {
    let mut info = Vec::with_capacity(KEY_INFO.len() + PUBLIC_KEY_BYTES * 2);
    info.extend_from_slice(KEY_INFO);
    info.extend_from_slice(sender);
    info.extend_from_slice(recipient);

    let hkdf = Hkdf::<Sha256>::new(Some(&[]), shared_secret);
    let mut key = [0u8; PUBLIC_KEY_BYTES];
    hkdf.expand(&info, &mut key)
        .map_err(|_| OpenLvError::Encryption("failed to derive peer key".into()))?;
    Ok(key)
}

fn decode_ciphertext(ciphertext: &str) -> Result<([u8; PUBLIC_KEY_BYTES], [u8; NONCE_BYTES], Vec<u8>), OpenLvError> {
    let bytes = from_base64(ciphertext)?;
    if bytes.len() < PUBLIC_KEY_BYTES + NONCE_BYTES + TAG_BYTES {
        return Err(OpenLvError::Encryption("ciphertext is malformed".into()));
    }

    let peer_key = bytes[..PUBLIC_KEY_BYTES]
        .try_into()
        .map_err(|_| OpenLvError::Encryption("ciphertext peer key is malformed".into()))?;
    let nonce = bytes[PUBLIC_KEY_BYTES..PUBLIC_KEY_BYTES + NONCE_BYTES]
        .try_into()
        .map_err(|_| OpenLvError::Encryption("ciphertext nonce is malformed".into()))?;
    Ok((peer_key, nonce, bytes[PUBLIC_KEY_BYTES + NONCE_BYTES..].to_vec()))
}

impl PeerCipher {
    pub fn encrypt(&self, message: &str) -> Result<String, OpenLvError> {
        let mut nonce = [0u8; NONCE_BYTES];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = self
            .send
            .encrypt(Nonce::from_slice(&nonce), message.as_bytes())
            .map_err(|error| OpenLvError::Encryption(error.to_string()))?;

        let mut payload = Vec::with_capacity(PUBLIC_KEY_BYTES + NONCE_BYTES + ciphertext.len());
        payload.extend_from_slice(&self.local_public_key);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);
        Ok(to_base64(&payload))
    }

    pub fn decrypt(&self, ciphertext: &str) -> Result<String, OpenLvError> {
        let (sender, nonce, ciphertext) = decode_ciphertext(ciphertext)?;
        if sender != self.peer_public_key {
            return Err(OpenLvError::Encryption("ciphertext is not from the peer".into()));
        }

        let plaintext = self
            .receive
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|error| OpenLvError::Encryption(error.to_string()))?;
        String::from_utf8(plaintext).map_err(|error| OpenLvError::Encryption(error.to_string()))
    }
}

pub fn create_peer_cipher(key_pair: &KeyPair, peer_key: &EncryptionKey) -> Result<PeerCipher, OpenLvError> {

    let shared_secret = key_pair.decryption_key.shared_secret(peer_key)?;
    let local_public_key: [u8; PUBLIC_KEY_BYTES] = key_pair
        .encryption_key
        .as_bytes()
        .try_into()
        .map_err(|_| OpenLvError::Encryption("local public key is malformed".into()))?;
    let peer_public_key: [u8; PUBLIC_KEY_BYTES] = peer_key
        .as_bytes()
        .try_into()
        .map_err(|_| OpenLvError::Encryption("peer public key is malformed".into()))?;
    let send_key = derive_key(&shared_secret, &local_public_key, &peer_public_key)?;
    let receive_key = derive_key(&shared_secret, &peer_public_key, &local_public_key)?;
    let send = Aes256Gcm::new_from_slice(&send_key)
        .map_err(|error| OpenLvError::Encryption(error.to_string()))?;
    let receive = Aes256Gcm::new_from_slice(&receive_key)
        .map_err(|error| OpenLvError::Encryption(error.to_string()))?;

    Ok(PeerCipher {
        local_public_key,
        peer_public_key,
        send,
        receive,
    })
}

pub fn accept_peer(key_pair: &KeyPair, ciphertext: &str) -> Result<AcceptedPeer, OpenLvError> {
    let (peer_public_key, _, _) = decode_ciphertext(ciphertext)?;
    let peer_key = EncryptionKey::from_bytes(peer_public_key)?;
    let cipher = create_peer_cipher(key_pair, &peer_key)?;
    let message = cipher.decrypt(ciphertext)?;
    Ok(AcceptedPeer {
        peer_key,
        cipher,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_directional_authenticated_ciphers() {
        let host = KeyPair::generate().unwrap();
        let client = KeyPair::generate().unwrap();
        let host_cipher = create_peer_cipher(&host, &client.encryption_key).unwrap();
        let client_cipher = create_peer_cipher(&client, &host.encryption_key).unwrap();

        let ciphertext = client_cipher.encrypt("private").unwrap();
        assert_eq!(host_cipher.decrypt(&ciphertext).unwrap(), "private");
        assert!(client_cipher.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn accepts_first_peer_from_embedded_sender_key() {
        let host = KeyPair::generate().unwrap();
        let client = KeyPair::generate().unwrap();
        let client_cipher = create_peer_cipher(&client, &host.encryption_key).unwrap();
        let ciphertext = client_cipher.encrypt("pubkey").unwrap();

        let accepted = accept_peer(&host, &ciphertext).unwrap();
        assert_eq!(accepted.peer_key.as_bytes(), client.encryption_key.as_bytes());
        assert_eq!(accepted.message, "pubkey");
    }

    #[test]
    fn rejects_tampering_and_wrong_peer_key() {
        let host = KeyPair::generate().unwrap();
        let client = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let client_cipher = create_peer_cipher(&client, &host.encryption_key).unwrap();
        let ciphertext = client_cipher.encrypt("private").unwrap();

        let other_cipher = create_peer_cipher(&other, &host.encryption_key).unwrap();
        assert!(other_cipher.decrypt(&ciphertext).is_err());

        let mut tampered = from_base64(&ciphertext).unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(host_cipher(&host, &client).decrypt(&to_base64(&tampered)).is_err());
    }

    fn host_cipher(host: &KeyPair, client: &KeyPair) -> PeerCipher {
        create_peer_cipher(host, &client.encryption_key).unwrap()
    }

    #[test]
    fn decrypts_the_upstream_test_vector() {
        let key_pair = KeyPair::from_base64(
            "zo060cy2M+x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk=",
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        )
        .unwrap();
        let peer_key =
            EncryptionKey::from_base64("pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk=")
                .unwrap();
        let cipher = create_peer_cipher(&key_pair, &peer_key).unwrap();
        let ciphertext = "pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogkDAwMDAwMDAwMDAwOL3klAuRZ1a2kM5EryzNjgXIUN6C2hj8Att8QbUqi3iEg5GNHlNL2Q3C//";
        assert_eq!(cipher.decrypt(ciphertext).unwrap(), "openlv peer-key test vector");
    }
}
