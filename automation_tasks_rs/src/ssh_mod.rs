// ssh_mod.rs

#[allow(unused_imports)]
use cargo_auto_lib::BLUE;
use cargo_auto_lib::GREEN;
use cargo_auto_lib::RED;
use cargo_auto_lib::RESET;
use cargo_auto_lib::YELLOW;

// bring trait into scope
use secrecy::ExposeSecret;

pub struct SshContext {
    signed_passcode_is_a_secret: secrecy::SecretVec<u8>,
    decrypted_string: secrecy::SecretString,
}

impl SshContext {
    pub fn new() -> Self {
        SshContext {
            signed_passcode_is_a_secret: secrecy::SecretVec::new(vec![]),
            decrypted_string: secrecy::SecretString::new("".to_string()),
        }
    }
    pub fn get_decrypted_string(&self) -> secrecy::SecretString {
        self.decrypted_string.clone()
    }
}

impl cargo_auto_encrypt_secret_lib::SshContextTrait for SshContext {
    /// decrypt from file data and write the decrypted secret in private field for later use in this crate, not in external library crates
    fn decrypt_from_file_data(&mut self, encrypted_string: &cargo_auto_encrypt_secret_lib::EncryptedString) {
        let mut decryptor = crate::decrypt_mod::Decryptor::new_for_decrypt(&self.signed_passcode_is_a_secret);
        decryptor.decrypt_symmetric(encrypted_string);
        self.decrypted_string = decryptor.return_secret_string().clone();
    }

    /// get token and encrypt
    fn get_token_and_encrypt(&self) -> cargo_auto_encrypt_secret_lib::EncryptedString {
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
        let token_is_a_secret = get_token();
        // use this signed as password for symmetric encryption
        let encryptor = crate::encrypt_mod::Encryptor::new_for_encrypt(token_is_a_secret, &self.signed_passcode_is_a_secret);
        let encrypted_token = encryptor.encrypt_symmetric().unwrap();
        tracing::debug!("{:?}", &encrypted_token.0);
        // return
        encrypted_token
    }

    /// Sign with ssh-agent or with identity_file
    ///
    /// get passphrase interactively
    /// returns secret_password_bytes:Vec u8
    fn sign_with_ssh_agent_or_identity_file(&mut self, identity_private_file_path: &camino::Utf8Path, seed_bytes_not_a_secret: &[u8; 32]) {
        /// Internal function used only for test configuration
        ///
        /// It is not interactive, but reads from a env var.
        #[cfg(test)]
        fn get_passphrase() -> secrecy::SecretString {
            secrecy::SecretString::new(std::env::var("TEST_PASSPHRASE").unwrap())
        }
        /// Internal function get_passphrase interactively ask user to type the passphrase
        ///
        /// This is used for normal code execution.
        #[cfg(not(test))]
        fn get_passphrase() -> secrecy::SecretString {
            eprintln!(" ");
            eprintln!("   {BLUE}Enter the passphrase for the SSH private key:{RESET}");
            secrecy::SecretString::new(
                inquire::Password::new("")
                    .without_confirmation()
                    .with_display_mode(inquire::PasswordDisplayMode::Masked)
                    .prompt()
                    .unwrap(),
            )
        }

        let identity_private_file_path_expanded = cargo_auto_encrypt_secret_lib::file_path_home_expand(identity_private_file_path);
        if !camino::Utf8Path::new(&identity_private_file_path_expanded).exists() {
            panic!("{RED}Error: File {identity_private_file_path_expanded} does not exist! {RESET}");
        }

        let fingerprint_from_file = cargo_auto_encrypt_secret_lib::get_fingerprint_from_file(&identity_private_file_path_expanded);

        let mut ssh_agent_client = cargo_auto_encrypt_secret_lib::crate_ssh_agent_client();
        match cargo_auto_encrypt_secret_lib::ssh_add_list_contains_fingerprint(&mut ssh_agent_client, &fingerprint_from_file) {
            Some(public_key) => {
                // sign with public key from ssh-agent
                let signature_is_the_new_secret_password = ssh_agent_client.sign(&public_key, seed_bytes_not_a_secret).unwrap();
                // only the data part of the signature goes into as_bytes.
                self.signed_passcode_is_a_secret = secrecy::SecretVec::new(signature_is_the_new_secret_password.as_bytes().to_owned());
            }
            None => {
                // ask user to think about adding with ssh-add
                eprintln!("   {YELLOW}SSH key for encrypted GitHub token is not found in the ssh-agent.{RESET}");
                eprintln!("   {YELLOW}Without ssh-agent, you will have to type the private key passphrase every time. This is more secure, but inconvenient.{RESET}");
                eprintln!("   {YELLOW}You can manually add the SSH identity to ssh-agent:{RESET}");
                eprintln!("   {YELLOW}WARNING: using ssh-agent is less secure, because there is no need for user interaction.{RESET}");
                eprintln!("{GREEN}ssh-add -t 1h {identity_private_file_path_expanded}{RESET}");

                // just for test purpose I will use env var to read this passphrase. Don't use it in production.

                let passphrase_is_a_secret = get_passphrase();
                let private_key = ssh_key::PrivateKey::read_openssh_file(identity_private_file_path_expanded.as_std_path()).unwrap();
                let private_key = private_key.decrypt(passphrase_is_a_secret.expose_secret()).unwrap();
                let namespace = "file";
                // The additional signature namespace is used to prevent signature confusion across different domains of use (e.g. file signing vs email signing).
                // Namespaces are arbitrary strings, and may include: “file” for file signing, “email” for email signing or anything for custom uses.
                let ssh_sig = private_key.sign(namespace, ssh_key::HashAlg::default(), seed_bytes_not_a_secret).unwrap();
                let signature_is_the_new_secret_password = ssh_sig.signature();

                // only the data part of the signature goes into as_bytes.
                self.signed_passcode_is_a_secret = secrecy::SecretVec::new(signature_is_the_new_secret_password.as_bytes().to_owned());
            }
        }
    }
}
