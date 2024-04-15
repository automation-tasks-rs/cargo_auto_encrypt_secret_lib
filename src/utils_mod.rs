// utils_mod.rs

//! various utilities

use std::str::FromStr;

// region: Public API constants
// ANSI colors for Linux terminal
// https://github.com/shiena/ansicolor/blob/master/README.md
/// ANSI color
pub const RED: &str = "\x1b[31m";
/// ANSI color
pub const GREEN: &str = "\x1b[32m";
/// ANSI color
pub const YELLOW: &str = "\x1b[33m";
/// ANSI color
pub const BLUE: &str = "\x1b[34m";
/// ANSI color
pub const RESET: &str = "\x1b[0m";
// endregion: Public API constants

/// home_dir() using the home crate
/// panics if HOME not found
pub fn home_dir() -> camino::Utf8PathBuf {
    match home::home_dir() {
        Some(path_buff) => {
            if !path_buff.as_os_str().is_empty() {
                camino::Utf8PathBuf::from_path_buf(path_buff).unwrap()
            } else {
                panic!("{RED}Unable to get your home dir!{RESET}");
            }
        }
        None => panic!("{RED}Unable to get your home dir!{RESET}"),
    }
}

/// Expands the ~ for home_dir and returns expanded path as str
pub fn file_path_home_expand(file_path: &camino::Utf8Path) -> camino::Utf8PathBuf {
    let replaced = file_path.as_str().replace("~", home_dir().as_str());
    camino::Utf8PathBuf::from_str(&replaced).unwrap()
}
