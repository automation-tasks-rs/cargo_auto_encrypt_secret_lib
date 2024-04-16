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
    encrypted_token: encrypt_secret::EncryptedString,
}

impl GitHubClient {
    /// Create new Github client
    ///
    /// Interactively ask the user to input the GitHub token.
    pub fn new() -> Self {
        /// Internal function Generate a random password
        fn random_byte_passcode() -> [u8; 32] {
            let mut password = [0_u8; 32];
            use aes_gcm::aead::rand_core::RngCore;
            aes_gcm::aead::OsRng.fill_bytes(&mut password);
            password
        }

        let session_passcode = secrecy::SecretVec::new(random_byte_passcode().to_vec());

        println!("{BLUE}Enter the GitHub API token:{RESET}");
        let token_is_a_secret = secrecy::SecretString::from(inquire::Password::new("").without_confirmation().prompt().unwrap());

        let token_is_a_secret = encrypt_secret::encrypt_symmetric(&token_is_a_secret, &session_passcode).unwrap();

        GitHubClient {
            session_passcode,
            encrypted_token: token_is_a_secret,
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
        let identity_file_path = camino::Utf8Path::new("~/.ssh/github_api_token_ssh_1");
        if !encrypted_string_file_path.exists() {
            // ask interactive
            println!("    {BLUE}Do you want to store the github api token encrypted with an SSH key? (y/n){RESET}");
            let answer = inquire::Text::new("").prompt().unwrap();
            if answer.to_lowercase() != "y" {
                // enter the token manually, not storing
                return Self::new();
            } else {
                // store the token
                let client = Self::new();
                // TODO: encrypt and save the token
                return client;
            }
        } else {
            // TODO: file exists, read the token
            Self::new()
        }
    }

    /// decrypts the secret token in memory
    pub fn decrypt_token_in_memory(&self) -> secrecy::SecretString {
        encrypt_secret::decrypt_symmetric(&self.encrypted_token, &self.session_passcode).unwrap()
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
