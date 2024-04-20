[//]: # (auto_md_to_doc_comments segment start A)

# cargo_auto_encrypt_secret_lib

[//]: # (auto_cargo_toml_to_md start)

**Library to encrypt/decrypt secrets**  
***version: 1.0.9 date: 2024-04-20 author: [bestia.dev](https://bestia.dev) repository: [GitHub](https://github.com/automation-tasks-rs/cargo_auto_encrypt_secret_lib)***

 ![rust](https://img.shields.io/badge/rust-orange)
 ![maintained](https://img.shields.io/badge/maintained-green)
 ![ready_for_use](https://img.shields.io/badge/ready_for_use-orange)

[//]: # (auto_cargo_toml_to_md end)

 [![crates.io](https://img.shields.io/crates/v/cargo_auto_encrypt_secret_lib.svg)](https://crates.io/crates/cargo_auto_encrypt_secret_lib)
 [![Documentation](https://docs.rs/cargo_auto_encrypt_secret_lib/badge.svg)](https://docs.rs/cargo_auto_encrypt_secret_lib/)
 [![Lib.rs](https://img.shields.io/badge/Lib.rs-rust-orange.svg)](https://lib.rs/crates/cargo_auto_encrypt_secret_lib/)
 [![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/automation-tasks-rs/cargo_auto_encrypt_secret_lib/blob/master/LICENSE)
 [![Rust](https://github.com/automation-tasks-rs/cargo_auto_encrypt_secret_lib/workflows/rust_fmt_auto_build_test/badge.svg)](https://github.com/automation-tasks-rs/cargo_auto_encrypt_secret_lib/)
 ![Hits](https://bestia.dev/webpage_hit_counter/get_svg_image/1785154337.svg)

[//]: # (auto_lines_of_code start)
[![Lines in Rust code](https://img.shields.io/badge/Lines_in_Rust-151-green.svg)](https://github.com/automation-tasks-rs/encrypt_secret/)
[![Lines in Doc comments](https://img.shields.io/badge/Lines_in_Doc_comments-185-blue.svg)](https://github.com/automation-tasks-rs/encrypt_secret/)
[![Lines in Comments](https://img.shields.io/badge/Lines_in_comments-17-purple.svg)](https://github.com/automation-tasks-rs/encrypt_secret/)
[![Lines in examples](https://img.shields.io/badge/Lines_in_examples-0-yellow.svg)](https://github.com/automation-tasks-rs/encrypt_secret/)
[![Lines in tests](https://img.shields.io/badge/Lines_in_tests-1-orange.svg)](https://github.com/automation-tasks-rs/encrypt_secret/)

[//]: # (auto_lines_of_code end)

Hashtags: #rustlang 
My projects on GitHub are more like a tutorial than a finished product: [bestia-dev tutorials](https://github.com/bestia-dev/tutorials_rust_wasm).

## Secrets

When we write an application, every connection to any server needs to work with secrets: passwords, passkeys, passcodes, passphrases, API tokens and more.

Sometimes it is just fine to let the user type the password. Passwords are easy for humans to remember and type. But they are the least secure.

It is much better to have a long random "key" string like the API token, but no human is capable of remembering that. It means we need to store it somewhere.

It is theoretically impossible to store this secret 100% securely using only software. Modern computers use special chips for that. But we can make it hard and not obvious for an attacker to get the secret.

## GitHub API token

The GitHub API token is a secret just like a password. Maybe even greater.  
With this API token, a maleficent actor can change basically anything in your GitHub account. You don't want that.

How to protect this secret?  
Ok, there are some basic recommendations:

- Give the least permission/authorization to the API token to minimize the harm an attacker can do
- Expire the token frequently, so old tokens are of no use
- HTTPS is a no-brainer. Never use HTTP ever again. It is plain text over the wire.
- Never store the token in a file as plain text
- Plain text inside env vars can also be accessed from malware

## Symmetric encryption

We will use encryption [aes_gcm::Aes256Gcm](https://docs.rs/aes-gcm/latest/aes_gcm/index.html) for very short strings like API tokens. So I suppose the performance is not a problem.  
We use a passcode of 32 bytes to encrypt a string.  
We can also enter a string password, that will be internally hashed into a 32-byte passcode.  

## Use SSH key to encrypt token

We are accustomed to working with SSH keys because of Git and SSH connection to the web servers.  
We already know how to create, secure and manage SSH keys. We know all about the private and public keys.  
We know that the private key is secured by a passphrase.  
We already know how to add an SSH key to ssh-agent. And we know that the use of ssh-agent makes life easier, but it has some security concerns. In most cases, this is not critical, but you have to choose your own balance between Convenience and Security.  
All this knowledge is already mastered because of the workflow when developing in Rust.  
We could use the same technique to encrypt the API token.

We will use the private key to sign a random seed and the result will be a new super-secret passcode.
The only way to get to this super-secret passcode is to sign the seed with the private key. We suppose that only the owner can sign with his/her private key. This is the basis of SSH key security.

The super-secret passcode will be used to symmetrically encrypt the token and write it to a file as text. It is much simpler to work with text files.

Never commit secrets to your repository. GitHub is regularly scanned for uploaded secrets. That is a big no-no. I prefer to store the encrypted token in the `~/.ssh` directory near to other secret and encrypted keys.

## Create an SSH key

It is recommended to encrypt every API token with its dedicated SSH key. This way you have granular control over how to use it.

```bash
ssh-keygen -t ed25519 -C "github api token"
# for test type these interactively:
# file name: tests/test_github_api_token_ssh_1
# passphrase: test_passphrase
# repeat passphrase: test_passphrase
```

## Balance between Convenience and Security

First thing first: it is theoretically impossible to secure a secret 100% only with software. If an attacker gets privileged or physical access to the computer, he can do anything. But that does not mean it is easy and quick. We can make it harder and harder to find a secret. Finally, we have to choose a balance between Convenience and Security.

You can choose to type the API key into the terminal every time. This is very inconvenient. You cannot remember the API key, you have to store it somewhere on the computer. And then use copy-paste. This is also a security concern. This secret token will stay in the clipboard and that is easy to extract.

Never store secret tokens in plain text. Nor in files nor environment variables. Files and env var are easy to upload to a malicious website. Use some kind of secret manager or encryption.

When the token is encrypted with SSH, it must be decrypted using the private key. The private key is secured with a passphrase. This passphrase is easy to remember and type. You can choose to type the passphrase on every use of the token. This is pretty secure but inconvenient.

Ultimately you can use ssh-agent to decrypt the private key only once typing the passphrase. It will work in the background for a specific time like 1 hour or until the end of the terminal session. This is not secure, because an attacker could use the same open-source code to extract the token from ssh-agent in unencrypted form. But it is tricky to do and it is time-limited.

Just to mention the token could be extracted from memory while in use. Or that the attacker could install a key logger and send all typed passwords and passphrases to a malicious website. There are really no limits to software exploits once the attacker has enough privilege.

Finally, your choice.

## Open-source and free as a beer

My open-source projects are free as a beer (MIT license).  
I just love programming.  
But I need also to drink. If you find my projects and tutorials helpful, please buy me a beer by donating to my [PayPal](https://paypal.me/LucianoBestia).  
You know the price of a beer in your local bar ;-)  
So I can drink a free beer for your health :-)  
[Na zdravje!](https://translate.google.com/?hl=en&sl=sl&tl=en&text=Na%20zdravje&op=translate) [Alla salute!](https://dictionary.cambridge.org/dictionary/italian-english/alla-salute) [Prost!](https://dictionary.cambridge.org/dictionary/german-english/prost) [Nazdravlje!](https://matadornetwork.com/nights/how-to-say-cheers-in-50-languages/) 🍻

[//bestia.dev](https://bestia.dev)  
[//github.com/bestia-dev](https://github.com/bestia-dev)  
[//bestiadev.substack.com](https://bestiadev.substack.com)  
[//youtube.com/@bestia-dev-tutorials](https://youtube.com/@bestia-dev-tutorials)  

[//]: # (auto_md_to_doc_comments segment end A)
