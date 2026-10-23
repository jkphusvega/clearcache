//! Case-insensitive Windows path comparison helpers.

use std::path::{Path, PathBuf};

/// Lowercased, `/`→`\`, verbatim prefix and trailing separators removed. For comparison only.
pub fn norm(path: &Path) -> String {
    let s = path.to_string_lossy().replace('/', "\\");
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let s = s.trim_end_matches('\\');
    s.to_lowercase()
}

/// True if `path` is `root` or lies inside it (component boundary, case-insensitive).
pub fn is_within(path: &Path, root: &Path) -> bool {
    let p = norm(path);
    let r = norm(root);
    if r.is_empty() {
        return false;
    }
    p == r || (p.starts_with(&r) && p.as_bytes().get(r.len()) == Some(&b'\\'))
}

pub fn same_path(a: &Path, b: &Path) -> bool {
    norm(a) == norm(b)
}

/// Drive letter of a path like `C:\...` (uppercase), if any.
pub fn drive_letter(path: &Path) -> Option<char> {
    let s = path.to_string_lossy();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let mut chars = s.chars();
    let letter = chars.next()?;
    (letter.is_ascii_alphabetic() && chars.next() == Some(':')).then(|| letter.to_ascii_uppercase())
}

/// Win32 calls that take a raw path need the verbatim prefix past MAX_PATH.
pub fn long_path(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s.len() < 248 || s.starts_with(r"\\") {
        return path.to_path_buf();
    }
    PathBuf::from(format!(r"\\?\{s}"))
}

pub fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_is_case_insensitive_and_respects_component_boundary() {
        assert!(is_within(
            Path::new(r"C:\Users\A\OneDrive\x"),
            Path::new(r"c:\users\a\onedrive\")
        ));
        assert!(is_within(
            Path::new(r"C:\Users\A\OneDrive"),
            Path::new(r"C:\Users\A\OneDrive")
        ));
        assert!(!is_within(
            Path::new(r"C:\Users\A\OneDrive2"),
            Path::new(r"C:\Users\A\OneDrive")
        ));
        assert!(is_within(
            Path::new(r"\\?\C:\Windows\WinSxS"),
            Path::new(r"C:\Windows")
        ));
    }

    #[test]
    fn drive_letter_parses() {
        assert_eq!(drive_letter(Path::new(r"d:\x")), Some('D'));
        assert_eq!(drive_letter(Path::new(r"\\?\C:\x")), Some('C'));
        assert_eq!(drive_letter(Path::new(r"\\server\share")), None);
    }
}
