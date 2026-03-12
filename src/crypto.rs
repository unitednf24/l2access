use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn generate_keypair() -> (StaticSecret, [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    (secret, *public.as_bytes())
}

pub fn diffie_hellman(secret: &StaticSecret, their_pub_bytes: &[u8; 32]) -> [u8; 32] {
    let their_pub = PublicKey::from(*their_pub_bytes);
    let shared = secret.diffie_hellman(&their_pub);
    *shared.as_bytes()
}

/// Derive a 32-byte key from a shared secret using HKDF-SHA256.
pub fn derive_key(shared: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key).expect("HKDF expand");
    key
}

pub fn random_nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

pub fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|e| anyhow::anyhow!("encrypt: {:?}", e))
}

pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| anyhow::anyhow!("decrypt: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_exchange() {
        let (s1, p1) = generate_keypair();
        let (s2, p2) = generate_keypair();

        let shared1 = diffie_hellman(&s1, &p2);
        let shared2 = diffie_hellman(&s2, &p1);

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = random_key();
        let nonce = random_nonce();
        let plaintext = b"hello world secure msg";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
