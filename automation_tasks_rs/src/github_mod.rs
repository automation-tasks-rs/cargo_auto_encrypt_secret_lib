// github_mod.rs

//! Every api call needs the Github API token. This is a secret important just like a password.
//! I don't want to pass this secret to an "obscure" library crate that is difficult to review.
//! This secret will stay here in this codebase that every developer can easily inspect.
//! Instead of the token, I will pass the struct GitHubClient with the trait SendToGithubApi.
//! This way, the secret token will be encapsulated.

use cargo_auto_github_lib as cgl;

use cargo_auto_lib::BLUE;
use cargo_auto_lib::RED;
use cargo_auto_lib::RESET;

use reqwest::Client;
// bring trait into scope
use secrecy::ExposeSecret;

/// Struct GitHubClient contains only private fields
/// This fields are accessible only to methods in implementation of traits.
pub struct GitHubClient {
    /// Passcode for encrypt the token_is_a_secret to encrypted_token.
    /// So that the secret is in memory as plain text as little as possible.
    /// For every session (program start) a new random passcode is created.
    session_passcode: secrecy::SecretVec<u8>,

    /// private field is set only once in the new() constructor
    encrypted_token: crate::secrecy_mod::SecretEncryptedString,
}

impl GitHubClient {
    /// Create new Github client
    ///
    /// Interactively ask the user to input the GitHub token.
    pub fn new_interactive_input_token() -> Self {
        let mut github_client = Self::new_wo_token();

        println!("{BLUE}Enter the GitHub API token:{RESET}");
        github_client.encrypted_token = crate::secrecy_mod::SecretEncryptedString::new_with_string(inquire::Password::new("").without_confirmation().prompt().unwrap(),&github_client.session_passcode);

        // return
        github_client
    }

    /// Create new Github client
    fn new_wo_token() -> Self {
        /// Internal function Generate a random password
        fn random_byte_passcode() -> [u8; 32] {
            let mut password = [0_u8; 32];
            use aes_gcm::aead::rand_core::RngCore;
            aes_gcm::aead::OsRng.fill_bytes(&mut password);
            password
        }

        let session_passcode = secrecy::SecretVec::new(random_byte_passcode().to_vec());
        let encrypted_token= crate::secrecy_mod::SecretEncryptedString::new_with_string("".to_string(),&session_passcode);

        GitHubClient {
            session_passcode,
            encrypted_token,
        }
    }

    /// Use the stored API token
    ///
    /// If the token not exists ask user to interactively input the token.
    /// To decrypt it, use the SSH passphrase. That is much easier to type than typing the token.
    /// it is then possible also to have the ssh key in ssh-agent and write the passphrase only once.
    /// But this great user experience comes with security concerns. The token is accessible if the attacker is very dedicated.
    pub fn new_with_stored_token() -> Self {
        let encrypted_string_file_path = camino::Utf8Path::new("~/.ssh/github_api_token_encrypted.txt");
        let encrypted_string_file_path_expanded = cargo_auto_encrypt_secret_lib::file_path_home_expand(encrypted_string_file_path);

        let identity_file_path = camino::Utf8Path::new("~/.ssh/github_api_token_ssh_1");
        if !encrypted_string_file_path_expanded.exists() {
            // ask interactive
            println!("    {BLUE}Do you want to store the github api token encrypted with an SSH key? (y/n){RESET}");
            let answer = inquire::Text::new("").prompt().unwrap();
            if answer.to_lowercase() != "y" {
                // enter the token manually, not storing
                return Self::new_interactive_input_token();
            } else {
                // get the token
                let github_client = Self::new_wo_token();
                // encrypt and save the encrypted token
                let mut ssh_context = crate::ssh_mod::SshContext::new();
                cargo_auto_encrypt_secret_lib::encrypt_with_ssh_interactive_save_file(&mut ssh_context, identity_file_path, encrypted_string_file_path);

                return github_client;
            }
        } else {
            // file exists, read the token and decrypt
            let mut github_client = Self::new_wo_token();

            let mut ssh_context = crate::ssh_mod::SshContext::new();
            cargo_auto_encrypt_secret_lib::decrypt_with_ssh_interactive_from_file(&mut ssh_context, encrypted_string_file_path);

            let token_is_a_secret = ssh_context.get_decrypted_string();
            github_client.encrypted_token = crate::secrecy_mod::SecretEncryptedString::new_with_secret_string(token_is_a_secret,&github_client.session_passcode);

            return github_client;
        }
    }

    /// decrypts the secret token in memory
    pub fn decrypt_token_in_memory(&self) -> secrecy::SecretString {
        self.encrypted_token.expose_decrypted_secret(&self.session_passcode)
    }
}

/// trait from the crate library, so the 2 crates can share a function
impl cgl::SendToGitHubApi for GitHubClient {
    /// Send github api request
    ///
    /// This function encapsulates the secret API token.
    /// The RequestBuilder is created somewhere in the library crate.
    /// The client can be passed to the library. It will not reveal the secret token.
    fn send_to_github_api(&self, req: reqwest::blocking::RequestBuilder) -> serde_json::Value {
        // I must build the request to be able then to inspect it.
        let req = req.bearer_auth(self.decrypt_token_in_memory().expose_secret()).build().unwrap();

        // region: Assert the correct url and https
        // It is important that the request coming from a external crate/library
        // is only sent always and only to github api and not some other malicious url,
        // because the request contains the secret GitHub API token.
        // And it must always use https
        let host_str = req.url().host_str().unwrap();
        assert!(host_str == "api.github.com", "{RED}Error: Url is not correct: {host_str}. It must be always api.github.com.{RESET}");
        let scheme = req.url().scheme();
        assert!(scheme == "https", "{RED}Error: Scheme is not correct: {scheme}. It must be always https.{RESET}");
        // endregion: Assert the correct url and https

        let reqwest_client = reqwest::blocking::Client::new();
        let response_text = reqwest_client.execute(req).unwrap().text().unwrap();

        let json_value: serde_json::Value = serde_json::from_str(&response_text).unwrap();

        // panic if "message": String("Bad credentials"),
        if let Some(m) = json_value.get("message") {
            if m == "Bad credentials" {
                panic!("{RED}Error: Bad credentials for GitHub api. {RESET}");
            }
        }

        // return
        json_value
    }

    /// Upload to github
    ///
    /// This function encapsulates the secret API token.
    /// The RequestBuilder is created somewhere in the library crate.
    /// The client can be passed to the library. It will not reveal the secret token.
    /// This is basically an async fn, but use of `async fn` in public traits is discouraged...
    async fn upload_to_github(&self, req: reqwest::RequestBuilder) -> serde_json::Value {
        // I must build the request to be able then to inspect it.
        let req = req.bearer_auth(self.decrypt_token_in_memory().expose_secret()).build().unwrap();

        // region: Assert the correct url and https
        // It is important that the request coming from a external crate/library
        // is only sent always and only to github uploads and not some other malicious url,
        // because the request contains the secret GitHub API token.
        // And it must always use https
        let host_str = req.url().host_str().unwrap();
        assert!(host_str == "uploads.github.com", "{RED}Error: Url is not correct: {host_str}. It must be always api.github.com.{RESET}");
        let scheme = req.url().scheme();
        assert!(scheme == "https", "{RED}Error: Scheme is not correct: {scheme}. It must be always https.{RESET}");
        // endregion: Assert the correct url and https

        let reqwest_client = Client::new();
        let response_text = reqwest_client.execute(req).await.unwrap().text().await.unwrap();

        let json_value: serde_json::Value = serde_json::from_str(&response_text).unwrap();

        // panic if "message": String("Bad credentials"),
        if let Some(m) = json_value.get("message") {
            if m == "Bad credentials" {
                panic!("{RED}Error: Bad credentials for GitHub api. {RESET}");
            }
        }

        // return
        json_value
    }
}
