// ssh_sign_crypt_mod.rs

// region: auto_md_to_doc_comments include doc_comments/ssh_sign_crypt_mod.md A //!
//! How to save a GitHub TOKEN securely inside a file?
//!
//! GitHub TOKEN is used by GitHub API to gain access (authentication and authorization) to your GitHub.  
//! A TOKEN is a secret just like a password and it must be protected.  
//! If the TOKEN is leaked, a mal-intentioned can gain access to everything, using the API.  
//! Never store TOKENS in plain text anywhere!
//!
//! The TOKEN must be encrypted before storing it.  
//!
//! ## SSH keys
//!
//! We already use SSH keys to connect to GitHub. And we use ssh-agent for easy work with SSH identities.  
//! I want to use the SSH key inside ssh-agent to encrypt the TOKEN and save it in a file.
//!
//! The easy solution: encrypt with the Public key and then decrypt with the Private key.  
//! Problem: ssh-agent can only sign a message with the private key. Nothing more.  
//! It cannot decrypt with private key, because it would be a security risk.
//!
//! The security is based on the assumption that only the owner of the[]SSHprivate key can sign the message.  
//! The user already uses theSSHprivate key and it uses ssh-agent to connect over SSH to GitHub.  
//! So the user already knows how important are SSH private keys and to keep them secure.
//!
//! This could work also for other TOKENS, not just GitHub.
//!
//! Encryption
//!
//! 1. ssh-agent must contain the chosen SSH identity. Use ssh-add for this.  
//! 2. Create a random message that will be used only by this code. It is not a secret.  
//! 3. Sign this message. This will become the password for symmetric encryption. It is a secret.  
//! 4. Input the token interactively in hidden input. It is a secret.  
//! 5. Use the password to symmetric encrypt the token.  
//! 6. Zeroize the token and password.  
//! 7. Save the message and the encrypted token in a json file.
//!
//! Decryption
//!
//! 1. ssh-agent must contain the SSH identity. Use ssh-add for this.  
//! 2. Read the json file, get the ssh_identity_file_path, message and the encrypted token.  
//! 3. Find the right identity inside ssh-agent.  
//! 4. Sign the message. This will become the password for symmetric decryption. It is a secret.  
//! 5. Use this password to symmetric decrypt the token.  
//! 6. Get the token.  
//! 7. Zeroize the token and password.
//!
// endregion: auto_md_to_doc_comments include doc_comments/ssh_sign_crypt_mod.md A //!

#[allow(unused_imports)]
use crate::utils_mod::BLUE;
use crate::utils_mod::RED;
use crate::utils_mod::RESET;
use crate::utils_mod::YELLOW;

/// Encrypt token with the chosen ssh_identity and save as json encoded in Base64
///
/// For better user-experience, use ssh-add to put SSH identity into ssh-agent.
/// WARNING: using ssh-agent is less secure explicitly because there is no need for user interaction.
pub fn encrypt_with_ssh_interactive_save_file(identity_file_path: &camino::Utf8Path, encrypted_string_file_path: &camino::Utf8Path) {
    /// Internal function Generate a random passcode
    fn random_byte_passcode() -> [u8; 32] {
        let mut password = [0_u8; 32];
        use aes_gcm::aead::rand_core::RngCore;
        aes_gcm::aead::OsRng.fill_bytes(&mut password);
        password
    }
    /// Internal function used only for test configuration
    ///
    /// It is not interactive, but reads from a env var.
    #[cfg(test)]
    fn get_token() -> secrecy::SecretString {
        secrecy::SecretString::new(std::env::var("TEST_TOKEN").unwrap())
    }
    /// Internal function get_passphrase interactively ask user to type the passphrase
    ///
    /// This is used for normal code execution.
    #[cfg(not(test))]
    fn get_token() -> secrecy::SecretString {
        eprintln!(" ");
        eprintln!("   {BLUE}Enter the API token to encrypt:{RESET}");
        secrecy::SecretString::new(
            inquire::Password::new("")
                .without_confirmation()
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .prompt()
                .unwrap(),
        )
    }

    let identity_file_path_expanded = crate::utils_mod::file_path_home_expand(identity_file_path);
    if !camino::Utf8Path::new(&identity_file_path_expanded).exists() {
        panic!("{RED}Error: File {identity_file_path_expanded} does not exist! {RESET}");
    }

    let seed_bytes_not_a_secret = random_byte_passcode();
    let seed_string_not_a_secret = <base64ct::Base64 as base64ct::Encoding>::encode_string(&seed_bytes_not_a_secret);

    let signature_is_the_new_secret_password = crate::ssh_mod::sign_with_ssh_agent_or_identity_file(identity_file_path, &seed_bytes_not_a_secret);

    let token_is_a_secret = get_token();

    // use this signed as password for symmetric encryption
    let encrypted_text = crate::encrypt_symmetric(&token_is_a_secret, &signature_is_the_new_secret_password).unwrap();
    // make json with 3 fields: fingerprint, seed, encrypted
    let json_value = serde_json::json!(
    {
        "identity": identity_file_path.as_str(),
        "seed": seed_string_not_a_secret,
        "encrypted":encrypted_text.0,
    });
    let file_text = serde_json::to_string_pretty(&json_value).unwrap();
    let file_text = <base64ct::Base64 as base64ct::Encoding>::encode_string(file_text.as_bytes());

    let encrypted_string_file_path = crate::utils_mod::file_path_home_expand(encrypted_string_file_path);
    let encrypted_file = camino::Utf8Path::new(&encrypted_string_file_path);
    std::fs::write(encrypted_file, file_text).unwrap();
    println!("    {YELLOW}Encrypted text saved in file for future use.{RESET}")
}

/// Decrypt token from file (json encoded in Base64) with the chosen ssh_identity
///
/// For better user-experience, use ssh-add to put SSH identity into ssh-agent.
/// WARNING: using ssh-agent is less secure explicitly because there is no need for user interaction.
pub fn decrypt_with_ssh_interactive_from_file(encrypted_string_file_path: &camino::Utf8Path) -> Option<secrecy::SecretString> {
    let encrypted_string_file_path_expanded = crate::utils_mod::file_path_home_expand(encrypted_string_file_path);
    if !camino::Utf8Path::new(&encrypted_string_file_path_expanded).exists() {
        panic!("{RED}Error: File {encrypted_string_file_path_expanded} does not exist! {RESET}");
    }

    let file_text = std::fs::read_to_string(encrypted_string_file_path_expanded).unwrap();
    let file_text = <base64ct::Base64 as base64ct::Encoding>::decode_vec(&file_text).unwrap();
    let file_text = String::from_utf8(file_text).unwrap();
    let json_value: serde_json::Value = serde_json::from_str(&file_text).unwrap();
    let identity_file_path: &str = json_value.get("identity").unwrap().as_str().unwrap();
    let seed_for_password_not_a_secret: &str = json_value.get("seed").unwrap().as_str().unwrap();
    let encrypted_string: &str = json_value.get("encrypted").unwrap().as_str().unwrap();
    let encrypted_string = crate::EncryptedString(encrypted_string.to_string());

    let identity_file_path = camino::Utf8Path::new(identity_file_path);
    let identity_file_path_expanded = crate::utils_mod::file_path_home_expand(identity_file_path);
    if !camino::Utf8Path::new(&identity_file_path_expanded).exists() {
        eprintln!("{RED}Error: File {identity_file_path_expanded} does not exist! {RESET}");
        // early exit
        return None;
    }

    let seed_bytes_not_a_secret = <base64ct::Base64 as base64ct::Encoding>::decode_vec(seed_for_password_not_a_secret).unwrap();
    let seed_bytes_not_a_secret: [u8; 32] = seed_bytes_not_a_secret[..32].try_into().unwrap();
    let signature_is_the_new_secret_password = crate::ssh_mod::sign_with_ssh_agent_or_identity_file(identity_file_path, &seed_bytes_not_a_secret);

    // use this signed as password for symmetric decryption
    let token_is_a_secret = crate::decrypt_symmetric(&encrypted_string, &signature_is_the_new_secret_password);
    // return
    token_is_a_secret
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let token = "test test test";
        std::env::set_var("TEST_PASSPHRASE", "test_passphrase");
        std::env::set_var("TEST_TOKEN", token);

        let identity_file_path = camino::Utf8Path::new("tests/test_github_api_token_ssh_1");
        let encrypted_string_file_path = camino::Utf8Path::new("tests/test_github_api_token_encrypted.txt");
        encrypt_with_ssh_interactive_save_file(&identity_file_path, &encrypted_string_file_path);
        let decrypted_string_is_a_secret = decrypt_with_ssh_interactive_from_file(&encrypted_string_file_path).unwrap();
        assert_eq!(token, decrypted_string_is_a_secret.expose_secret());
    }
}
