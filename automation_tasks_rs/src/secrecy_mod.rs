// secrecy_mod.rs

//! The crate secrecy is probably great.
//! But I want to encrypt the content, so I will make a wrapper.
//! The secrets must always be moved to secrecy types as soon as possible.

use cargo_auto_encrypt_secret_lib::EncryptedString;

pub struct SecretEncryptedString{
    encrypted_string: EncryptedString,
}

impl SecretEncryptedString{

    pub fn new_with_secret_string(secret_string: secrecy::SecretString,session_passcode:&secrecy::SecretVec<u8>)->Self{
        let encryptor = crate::encrypt_mod::Encryptor::new_for_encrypt(secret_string, &session_passcode);
        let encrypted_string = encryptor.encrypt_symmetric().unwrap();

        SecretEncryptedString{
                encrypted_string
        }
    }

    pub fn new_with_string(secret_string: String,session_passcode:&secrecy::SecretVec<u8>)->Self{
        let secret_string=secrecy::SecretString::new(secret_string);
        Self::new_with_secret_string(secret_string,session_passcode)
    }

    pub fn expose_decrypted_secret(&self,session_passcode:&secrecy::SecretVec<u8>)->secrecy::SecretString{
        let mut decryptor = crate::decrypt_mod::Decryptor::new_for_decrypt(&session_passcode);
        decryptor.decrypt_symmetric(&self.encrypted_string);
        decryptor.return_secret_string().clone()
    }

    
}