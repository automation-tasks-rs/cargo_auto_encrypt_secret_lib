// examples/encrypt_to_file.rs

/// cargo run --example encrypt_to_file
///
/// type interactively: TEST_PASSPHRASE = test_passphrase , TEST_TOKEN = test test test
fn main() {
    let identity_file_path = camino::Utf8Path::new("tests/test_github_api_token_ssh_1");
    let encrypted_string_file_path = camino::Utf8Path::new("tests/test_github_api_token_encrypted.txt");
    encrypt_secret::encrypt_with_ssh_interactive_save_file(&identity_file_path, &encrypted_string_file_path);
}
