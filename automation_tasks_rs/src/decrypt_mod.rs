// decrypt_mod.rs

use cargo_auto_lib::RED;
use cargo_auto_lib::RESET;
use secrecy::ExposeSecret;

/// The secrets must not leave this crate.
/// They are never going into an external library crate.
/// This crate is "user code" and is easy to review and inspect.
pub(crate) struct Decryptor<'a> {
    secret_string: secrecy::SecretString,
    secret_passcode_bytes: &'a secrecy::SecretVec<u8>,
}

impl <'a>Decryptor<'a> {
    pub (crate) fn new_for_decrypt(secret_passcode_bytes: &'a secrecy::SecretVec<u8>) -> Self {
        Decryptor {
            secret_string: secrecy::SecretString::new("".to_string()),
            secret_passcode_bytes,
        }
    }
    pub(crate) fn return_secret_string(&self) -> &secrecy::SecretString {
        &self.secret_string
    }

    /// Decrypts encrypted_string with secret_passcode_bytes
    ///
    /// secret_passcode_bytes must be 32 bytes or more
    /// Returns the secret_string
    pub(crate) fn decrypt_symmetric(&mut self, encrypted_string: &cargo_auto_encrypt_secret_lib::EncryptedString) {
        let encrypted_bytes = <base64ct::Base64 as base64ct::Encoding>::decode_vec(&encrypted_string.0).unwrap();
        //only first 32 bytes
        let mut secret_passcode_32bytes = [0u8; 32];
        secret_passcode_32bytes.copy_from_slice(&self.secret_passcode_bytes.expose_secret()[0..32]);

        let cipher = <aes_gcm::Aes256Gcm as aes_gcm::KeyInit>::new(&secret_passcode_32bytes.into());
        // nonce is salt
        let nonce = rsa::sha2::digest::generic_array::GenericArray::from_slice(&encrypted_bytes[..12]);
        let cipher_text = &encrypted_bytes[12..];

        let Ok(decrypted_bytes) = aes_gcm::aead::Aead::decrypt(&cipher, nonce, cipher_text) else {
            panic!("{RED}Error: Decryption failed. {RESET}");
        };
        let decrypted_string = String::from_utf8(decrypted_bytes).unwrap();
        self.secret_string = secrecy::SecretString::new(decrypted_string)
    }
}
