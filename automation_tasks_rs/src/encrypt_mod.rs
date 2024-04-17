// encrypt_mod.rs

use cargo_auto_lib::RED;
use cargo_auto_lib::RESET;

// bring trait to scope
use secrecy::ExposeSecret;

/// The secrets must not leave this crate.
/// They are never going into an external library crate.
/// This crate is "user code" and is easy to review and inspect.
pub(crate) struct Encryptor<'a> {
    secret_string: secrecy::SecretString,
    secret_passcode_bytes: &'a secrecy::SecretVec<u8>,
}

impl <'a>Encryptor<'a> {
    pub(crate) fn new_for_encrypt(secret_string: secrecy::SecretString, secret_passcode_bytes: &'a secrecy::SecretVec<u8>) -> Self {
        Encryptor { secret_string, secret_passcode_bytes }
    }

    /// Encrypts secret_string with secret_passcode_bytes
    ///
    /// secret_passcode_bytes must be 32 bytes or more
    /// returns the encrypted_string
    pub (crate) fn encrypt_symmetric(&self) -> Option<cargo_auto_encrypt_secret_lib::EncryptedString> {
        //only first 32 bytes
        let mut secret_passcode_32bytes = [0u8; 32];
        secret_passcode_32bytes.copy_from_slice(&self.secret_passcode_bytes.expose_secret()[0..32]);

        let cipher = <aes_gcm::Aes256Gcm as aes_gcm::KeyInit>::new(&secret_passcode_32bytes.into());
        // nonce is salt
        let nonce = <aes_gcm::Aes256Gcm as aes_gcm::AeadCore>::generate_nonce(&mut aes_gcm::aead::OsRng);

        let Ok(cipher_text) = aes_gcm::aead::Aead::encrypt(&cipher, &nonce, self.secret_string.expose_secret().as_bytes()) else {
            panic!("{RED}Error: Encryption failed. {RESET}");
        };

        let mut encrypted_bytes = nonce.to_vec();
        encrypted_bytes.extend_from_slice(&cipher_text);
        let encrypted_string = <base64ct::Base64 as base64ct::Encoding>::encode_string(&encrypted_bytes);
        Some(cargo_auto_encrypt_secret_lib::EncryptedString(encrypted_string))
    }
}
