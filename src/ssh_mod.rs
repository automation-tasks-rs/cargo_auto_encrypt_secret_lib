// ssh_mod.rs

/// A simple type-alias for String just to show intent that it is a fingerprint
pub type FingerprintString = String;

use secrecy::ExposeSecret;

#[allow(unused_imports)]
use crate::utils_mod::BLUE;
use crate::utils_mod::GREEN;
use crate::utils_mod::RESET;
use crate::utils_mod::YELLOW;

/// Get the fingerprint of a public key
///
/// The parameter is the filepath of the private key.
/// But the code then uses the public key to calculate the fingerprint.
pub(crate) fn get_fingerprint_from_file(identity_private_file_path: &camino::Utf8Path) -> FingerprintString {
    let identity_public_file_path = format!("{identity_private_file_path}.pub");

    let public_key = ssh_key::PublicKey::read_openssh_file(camino::Utf8Path::new(&identity_public_file_path).as_std_path()).unwrap();
    let fingerprint = public_key.fingerprint(Default::default());
    let fingerprint = fingerprint.to_string();
    // return
    fingerprint
}

/// The work with ssh_agent_client_rs starts with the client object
pub fn crate_ssh_agent_client() -> ssh_agent_client_rs::Client {
    let path = std::env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let client = ssh_agent_client_rs::Client::connect(camino::Utf8Path::new(&path).as_std_path()).unwrap();
    // return
    client
}

/// Returns the public_key inside ssh-add or None
pub(crate) fn ssh_add_list_contains_fingerprint(client: &mut ssh_agent_client_rs::Client, fingerprint_from_file: &str) -> Option<ssh_key::PublicKey> {
    let vec_public_key = client.list_identities().unwrap();

    for public_key in vec_public_key.iter() {
        let fingerprint_from_agent = public_key.key_data().fingerprint(Default::default()).to_string();

        if fingerprint_from_agent == fingerprint_from_file {
            return Some(public_key.to_owned());
        }
    }
    None
}

/// Sign with ssh-agent or with identity_file
///
/// returns secret_password_bytes:Vec u8
pub fn sign_with_ssh_agent_or_identity_file(identity_private_file_path: &camino::Utf8Path, seed_bytes_not_a_secret: &[u8; 32]) -> secrecy::SecretVec<u8> {
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

    let fingerprint_from_file = crate::ssh_mod::get_fingerprint_from_file(identity_private_file_path);

    let mut ssh_agent_client = crate::ssh_mod::crate_ssh_agent_client();
    match crate::ssh_mod::ssh_add_list_contains_fingerprint(&mut ssh_agent_client, &fingerprint_from_file) {
        Some(public_key) => {
            // sign with public key from ssh-agent
            let signature_is_the_new_secret_password = ssh_agent_client.sign(&public_key, seed_bytes_not_a_secret).unwrap();
            // only the data part of the signature goes into as_bytes.
            secrecy::SecretVec::new(signature_is_the_new_secret_password.as_bytes().to_owned())
        }
        None => {
            // ask user to think about adding with ssh-add
            eprintln!("   {YELLOW}SSH key for encrypted GitHub token is not found in the ssh-agent.{RESET}");
            eprintln!("   {YELLOW}Without ssh-agent, you will have to type the private key passphrase every time. This is more secure, but inconvenient.{RESET}");
            eprintln!("   {YELLOW}You can manually add the SSH identity to ssh-agent:{RESET}");
            eprintln!("   {YELLOW}WARNING: using ssh-agent is less secure, because there is no need for user interaction.{RESET}");
            eprintln!("{GREEN}ssh-add -t 1h {identity_private_file_path}{RESET}");

            // just for test purpose I will use env var to read this passphrase. Don't use it in production.

            let passphrase_is_a_secret = get_passphrase();
            let private_key = ssh_key::PrivateKey::read_openssh_file(identity_private_file_path.as_std_path()).unwrap();
            let private_key = private_key.decrypt(passphrase_is_a_secret.expose_secret()).unwrap();
            let namespace = "file";
            // The additional signature namespace is used to prevent signature confusion across different domains of use (e.g. file signing vs email signing).
            // Namespaces are arbitrary strings, and may include: “file” for file signing, “email” for email signing or anything for custom uses.
            let ssh_sig = private_key.sign(namespace, ssh_key::HashAlg::default(), seed_bytes_not_a_secret).unwrap();
            let signature_is_the_new_secret_password = ssh_sig.signature();

            // only the data part of the signature goes into as_bytes.
            secrecy::SecretVec::new(signature_is_the_new_secret_password.as_bytes().to_owned())
        }
    }
}
