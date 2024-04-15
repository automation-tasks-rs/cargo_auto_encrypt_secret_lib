// examples/decrypt_from_file.rs

use secrecy::ExposeSecret;

/// cargo run --example decrypt_from_file
///
/// type interactively: TEST_PASSPHRASE = test_passphrase
fn main() {
    let encrypted_string_file_path = camino::Utf8Path::new("tests/test_github_api_token_encrypted.txt");
    let decrypted_string = encrypt_secret::decrypt_with_ssh_interactive_from_file(encrypted_string_file_path).unwrap();
    println!("{}", decrypted_string.expose_secret());
}
