// symmetric_mod.rs

// bring trait into scope
use secrecy::ExposeSecret;

/// A simple wrapper new-type around String just to show intent that it is already encrypted
pub struct EncryptedString(pub String);

/// Encrypts secret_string with secret_passcode_bytes
///
/// secret_passcode_bytes must be 32 bytes or more
/// returns the encrypted_string
pub fn encrypt_symmetric(secret_string: &secrecy::SecretString, secret_passcode_bytes: &secrecy::SecretVec<u8>) -> Option<EncryptedString> {
    //only first 32 bytes
    let mut secret_passcode_32bytes = [0u8; 32];
    secret_passcode_32bytes.copy_from_slice(&secret_passcode_bytes.expose_secret()[0..32]);

    let cipher = <aes_gcm::Aes256Gcm as aes_gcm::KeyInit>::new(&secret_passcode_32bytes.into());
    // nonce is salt
    let nonce = <aes_gcm::Aes256Gcm as aes_gcm::AeadCore>::generate_nonce(&mut aes_gcm::aead::OsRng);

    let Ok(ciphertext) = aes_gcm::aead::Aead::encrypt(&cipher, &nonce, secret_string.expose_secret().as_bytes()) else {
        return None;
    };

    let mut encrypted_bytes = nonce.to_vec();
    encrypted_bytes.extend_from_slice(&ciphertext);
    let encrypted_string = <base64ct::Base64 as base64ct::Encoding>::encode_string(&encrypted_bytes);
    Some(EncryptedString(encrypted_string))
}

/// Decrypts encrypted_string with secret_passcode_bytes
///
/// secret_passcode_bytes must be 32 bytes or more
/// Returns the secret_string
pub fn decrypt_symmetric(encrypted_string: &EncryptedString, secret_passcode_bytes: &secrecy::SecretVec<u8>) -> Option<secrecy::SecretString> {
    let encrypted_bytes = <base64ct::Base64 as base64ct::Encoding>::decode_vec(&encrypted_string.0).unwrap();
    //only first 32 bytes
    let mut secret_passcode_32bytes = [0u8; 32];
    secret_passcode_32bytes.copy_from_slice(&secret_passcode_bytes.expose_secret()[0..32]);

    let cipher = <aes_gcm::Aes256Gcm as aes_gcm::KeyInit>::new(&secret_passcode_32bytes.into());
    // nonce is salt
    let nonce = rsa::sha2::digest::generic_array::GenericArray::from_slice(&encrypted_bytes[..12]);
    let ciphertext = &encrypted_bytes[12..];

    let Ok(decrypted_bytes) = aes_gcm::aead::Aead::decrypt(&cipher, nonce, ciphertext) else {
        return None;
    };
    let decrypted_string = String::from_utf8(decrypted_bytes).unwrap();
    Some(secrecy::SecretString::new(decrypted_string))
}

/// Converts a human readable password to a bytes passcode
///
/// passcode is 32 bytes
fn password_to_passcode(secret_password: &str) -> secrecy::SecretVec<u8> {
    use argon2::Argon2;
    // the salt in this case can be constant
    let salt = b"constant_salt";

    let mut secret_passcode = [0u8; 32];
    Argon2::default().hash_password_into(secret_password.as_bytes(), salt, &mut secret_passcode).unwrap();

    secrecy::SecretVec::new(secret_passcode.to_vec())
}

/// Encrypts secret_string with secret_password
///
/// returns an Encrypted string
pub fn encrypt_symmetric_with_password(secret_string: &secrecy::SecretString, secret_password: &secrecy::SecretString) -> Option<EncryptedString> {
    let secret_passcode_bytes = password_to_passcode(secret_password.expose_secret());
    encrypt_symmetric(secret_string, &secret_passcode_bytes)
}

/// Decrypts encrypted_string with secret_password
///
/// Returns the secret_string
pub fn decrypt_symmetric_with_password(encrypted_string: &EncryptedString, secret_password: &secrecy::SecretString) -> Option<secrecy::SecretString> {
    let secret_passcode_bytes = password_to_passcode(secret_password.expose_secret());
    decrypt_symmetric(encrypted_string, &secret_passcode_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let secret_string = secrecy::SecretString::new("test test test".to_string());
        let secret_password = secrecy::SecretString::new("password".to_string());
        let encrypted_string = encrypt_symmetric_with_password(&secret_string, &secret_password).unwrap();
        let decrypted_string = decrypt_symmetric_with_password(&encrypted_string, &secret_password).unwrap();
        assert_eq!(decrypted_string.expose_secret(), secret_string.expose_secret());
    }
}
