[//]: # (auto_md_to_doc_comments segment start A)

# encrypt_secret

[//]: # (auto_cargo_toml_to_md start)

**Library to encrypt/decrypt secrets**  
***version: 0.1.37 date: 2024-04-15 author: [bestia.dev](https://bestia.dev) repository: [Github](https://github.com/bestia-dev/encrypt_secret)***  

[//]: # (auto_cargo_toml_to_md end)

[//]: # (auto_lines_of_code start)
[![Lines in Rust code](https://img.shields.io/badge/Lines_in_Rust-87-green.svg)]()
[![Lines in Doc comments](https://img.shields.io/badge/Lines_in_Doc_comments-78-blue.svg)]()
[![Lines in Comments](https://img.shields.io/badge/Lines_in_comments-11-purple.svg)]()
[![Lines in examples](https://img.shields.io/badge/Lines_in_examples-0-yellow.svg)]()
[![Lines in tests](https://img.shields.io/badge/Lines_in_tests-77-orange.svg)]()

[//]: # (auto_lines_of_code end)

[![crates.io](https://img.shields.io/crates/v/encrypt_secret.svg)](https://crates.io/crates/encrypt_secret) [![Documentation](https://docs.rs/encrypt_secret/badge.svg)](https://docs.rs/encrypt_secret/) [![crev reviews](https://web.crev.dev/rust-reviews/badge/crev_count/encrypt_secret.svg)](https://web.crev.dev/rust-reviews/crate/encrypt_secret/) [![Lib.rs](https://img.shields.io/badge/Lib.rs-rust-orange.svg)](https://lib.rs/crates/encrypt_secret/) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/bestia-dev/encrypt_secret/blob/master/LICENSE) [![Rust](https://github.com/bestia-dev/encrypt_secret/workflows/RustAction/badge.svg)](https://github.com/bestia-dev/encrypt_secret/) ![Hits](https://bestia.dev/webpage_hit_counter/get_svg_image/1785154337.svg)

Hashtags: #rustlang #buildtool #developmenttool #github  
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

We use a passcode to encrypt a string.


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
