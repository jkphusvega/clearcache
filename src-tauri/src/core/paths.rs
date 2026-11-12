//! Windows path helpers. Names compare the way NTFS matches them: ordinal, ignoring case with
//! the OS uppercase table (`CompareStringOrdinal`). `to_lowercase` disagrees on some letters
//! (Greek final sigma, Kelvin sign, …), so nothing here uses it for comparison.

use std::path::{Path, PathBuf};

/// Same name for NTFS: `CompareStringOrdinal(…, bIgnoreCase = TRUE)`. ASCII takes the fast path,
/// which gives the same answer.
pub fn eq_ci(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        return a.eq_ignore_ascii_case(b);
    }
    win::compare_ordinal_ci(a, b)
}

/// `s` ends with `suffix` (an ASCII extension or name) under `eq_ci`.
pub fn ends_with_ci(s: &str, suffix: &str) -> bool {
    s.len() >= suffix.len()
        && s.is_char_boundary(s.len() - suffix.len())
        && eq_ci(&s[s.len() - suffix.len()..], suffix)
}

/// Uppercased with the invariant OS table, for map keys where `eq_ci` cannot be used.
pub fn fold(s: &str) -> String {
    if s.is_ascii() {
        return s.to_ascii_uppercase();
    }
    win::upper_invariant(s)
}

/// Comparison key: `/`→`\`, verbatim prefix and trailing separators removed, case folded.
pub fn norm(path: &Path) -> String {
    let s = path.to_string_lossy().replace('/', "\\");
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    fold(s.trim_end_matches('\\'))
}

fn components(path: &Path) -> Vec<String> {
    let s = path.to_string_lossy().replace('/', "\\");
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
    s.split('\\')
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .collect()
}

/// True if `path` is `root` or lies inside it (component boundary, case-insensitive).
pub fn is_within(path: &Path, root: &Path) -> bool {
    let p = components(path);
    let r = components(root);
    !r.is_empty() && p.len() >= r.len() && p.iter().zip(&r).all(|(a, b)| eq_ci(a, b))
}

pub fn same_path(a: &Path, b: &Path) -> bool {
    let a = components(a);
    let b = components(b);
    a.len() == b.len() && a.iter().zip(&b).all(|(x, y)| eq_ci(x, y))
}

/// Drive letter of a path like `C:\...` (uppercase), if any.
pub fn drive_letter(path: &Path) -> Option<char> {
    let s = path.to_string_lossy();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let mut chars = s.chars();
    let letter = chars.next()?;
    (letter.is_ascii_alphabetic() && chars.next() == Some(':')).then(|| letter.to_ascii_uppercase())
}

/// The `\\?\` form every file-system call takes. Win32 rewrites plain paths before using
/// them: it drops trailing dots and spaces (`evil.` reads `evil`) and stops at MAX_PATH.
/// Paths that are already verbatim or device paths, relative, or contain `.`/`..` (which a
/// verbatim path would take literally) are returned unchanged.
pub fn verbatim(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s.starts_with(r"\\?\") || s.starts_with(r"\\.\") {
        return path.to_path_buf();
    }
    let s = s.replace('/', "\\");
    if s.split('\\').any(|c| c == "." || c == "..") {
        return path.to_path_buf();
    }
    if let Some(unc) = s.strip_prefix(r"\\") {
        return PathBuf::from(format!(r"\\?\UNC\{unc}"));
    }
    let b = s.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
        return PathBuf::from(format!(r"\\?\{s}"));
    }
    path.to_path_buf()
}

pub fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// `GetSystemWindowsDirectoryW`: where Windows is, whatever `%SystemRoot%` says in this process.
pub fn windows_dir() -> Option<PathBuf> {
    win::windows_dir()
}

/// Where a path really is once links (junctions, symlinks) are followed
/// (`GetFinalPathNameByHandleW`), in plain form. `Ok(None)` when nothing exists there;
/// `Err` when it exists but cannot be opened or named (the caller fails closed).
pub fn final_path(path: &Path) -> Result<Option<PathBuf>, String> {
    win::final_path(path)
}

/// Profile and program folders read from the shell (`SHGetKnownFolderPath`), never from the
/// environment, which a process can inherit stale or wrong (focused review 5). Keyed by the
/// variable names rule patterns use, so `%LOCALAPPDATA%\npm-cache` keeps working.
pub const SHELL_FOLDERS: &[(&str, KnownFolder)] = &[
    ("LOCALAPPDATA", KnownFolder::LocalAppData),
    ("APPDATA", KnownFolder::RoamingAppData),
    ("USERPROFILE", KnownFolder::Profile),
    ("ProgramFiles", KnownFolder::ProgramFiles),
    ("ProgramFiles(x86)", KnownFolder::ProgramFilesX86),
];

/// Resolves a variable for the app: the shell folders above from the shell, `SystemRoot` from
/// `GetSystemWindowsDirectoryW`, with no fallback to the environment for either. Any other name
/// (tool locations such as `NVM_HOME`, `OneDrive`) comes from the environment.
pub fn lookup(name: &str) -> Option<PathBuf> {
    if name.eq_ignore_ascii_case("SystemRoot") || name.eq_ignore_ascii_case("windir") {
        return windows_dir();
    }
    match SHELL_FOLDERS
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
    {
        Some((_, folder)) => known_folder(*folder),
        None => env_path(name),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownFolder {
    Documents,
    Desktop,
    Pictures,
    Videos,
    Music,
    LocalAppData,
    RoamingAppData,
    Profile,
    ProgramFiles,
    ProgramFilesX86,
}

/// `SHGetKnownFolderPath`: where the shell keeps a known folder now (redirected or moved
/// included).
pub fn known_folder(folder: KnownFolder) -> Option<PathBuf> {
    win::known_folder(folder)
}

/// The path Windows would use for `path`: `.` and `..` collapsed (`GetFullPathNameW`), and a
/// volume GUID path (`\\?\Volume{…}\x`) turned into the volume's drive letter. Only for
/// absolute drive, UNC and volume paths; `None` for anything else or when it cannot be done.
pub fn resolve(path: &Path) -> Option<PathBuf> {
    let s = path.to_string_lossy().replace('/', "\\");
    if let Some(rest) = s.strip_prefix(r"\\?\Volume{") {
        let end = rest.find('}')?;
        let volume = format!(r"\\?\Volume{{{}}}\", &rest[..end]);
        let tail = rest[end + 1..].trim_start_matches('\\');
        return Some(win::volume_drive(&volume)?.join(tail));
    }
    let b = s.as_bytes();
    let drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    let unc = s.starts_with(r"\\") && !s.starts_with(r"\\?\") && !s.starts_with(r"\\.\");
    if !drive && !unc {
        return None;
    }
    win::full_path(&s)
}

/// The volume GUID path (`\\?\Volume{…}\`) of a mounted drive, e.g. for `C:\`.
#[cfg(test)]
pub fn volume_guid(mount: &str) -> Option<String> {
    win::volume_guid(mount)
}

mod win {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::{Path, PathBuf};
    use windows::Win32::Foundation::LPARAM;
    use windows::Win32::Globalization::{
        CompareStringOrdinal, LCMapStringEx, CSTR_EQUAL, LCMAP_UPPERCASE, LOCALE_NAME_INVARIANT,
    };
    use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

    pub fn compare_ordinal_ci(a: &str, b: &str) -> bool {
        let a: Vec<u16> = a.encode_utf16().collect();
        let b: Vec<u16> = b.encode_utf16().collect();
        unsafe { CompareStringOrdinal(&a, &b, true) == CSTR_EQUAL }
    }

    pub fn upper_invariant(s: &str) -> String {
        let src: Vec<u16> = s.encode_utf16().collect();
        let mut dst = vec![0u16; src.len() * 2 + 1];
        let n = unsafe {
            LCMapStringEx(
                LOCALE_NAME_INVARIANT,
                LCMAP_UPPERCASE,
                &src,
                Some(&mut dst),
                None,
                None,
                LPARAM(0),
            )
        };
        if n <= 0 {
            return s.to_uppercase();
        }
        String::from_utf16_lossy(&dst[..n as usize])
    }

    pub fn full_path(s: &str) -> Option<PathBuf> {
        use windows::Win32::Storage::FileSystem::GetFullPathNameW;
        let src = windows::core::HSTRING::from(s);
        let mut buf = vec![0u16; 520];
        loop {
            let n = unsafe { GetFullPathNameW(&src, Some(&mut buf), None) } as usize;
            if n == 0 {
                return None;
            }
            if n < buf.len() {
                return Some(OsString::from_wide(&buf[..n]).into());
            }
            buf.resize(n, 0);
        }
    }

    /// First drive-letter mount point of a volume (`C:\`).
    pub fn volume_drive(volume: &str) -> Option<PathBuf> {
        use windows::Win32::Storage::FileSystem::GetVolumePathNamesForVolumeNameW;
        let name = windows::core::HSTRING::from(volume);
        let mut buf = vec![0u16; 1024];
        let mut len = 0u32;
        unsafe { GetVolumePathNamesForVolumeNameW(&name, Some(&mut buf), &mut len) }.ok()?;
        // A list of NUL-terminated paths ending in an empty one.
        buf[..len as usize]
            .split(|&c| c == 0)
            .map(String::from_utf16_lossy)
            .find(|p| p.len() == 3 && p.ends_with(r":\"))
            .map(PathBuf::from)
    }

    #[cfg(test)]
    pub fn volume_guid(mount: &str) -> Option<String> {
        use windows::Win32::Storage::FileSystem::GetVolumeNameForVolumeMountPointW;
        let m = windows::core::HSTRING::from(mount);
        let mut buf = vec![0u16; 64];
        unsafe { GetVolumeNameForVolumeMountPointW(&m, &mut buf) }.ok()?;
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }

    /// See `super::final_path`.
    pub fn final_path(path: &Path) -> Result<Option<PathBuf>, String> {
        use windows::core::HSTRING;
        use windows::Win32::Foundation::{
            CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, HANDLE,
        };
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, GetFinalPathNameByHandleW, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            OPEN_EXISTING, VOLUME_NAME_DOS,
        };
        struct Handle(HANDLE);
        impl Drop for Handle {
            fn drop(&mut self) {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
        let wide = HSTRING::from(super::verbatim(path).as_os_str());
        // Folders only need BACKUP_SEMANTICS; no data is read, so cloud files are not recalled.
        let opened = unsafe {
            CreateFileW(
                &wide,
                FILE_READ_ATTRIBUTES.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        };
        let h = match opened {
            Ok(h) => Handle(h),
            Err(e)
                if e.code() == ERROR_FILE_NOT_FOUND.to_hresult()
                    || e.code() == ERROR_PATH_NOT_FOUND.to_hresult() =>
            {
                return Ok(None)
            }
            Err(e) => return Err(e.message()),
        };
        // Sized by what the call asks for, not a fixed buffer (focused review 3).
        let mut buf = vec![0u16; 512];
        let n = loop {
            let n = unsafe { GetFinalPathNameByHandleW(h.0, &mut buf, VOLUME_NAME_DOS) } as usize;
            if n == 0 {
                return Err(windows::core::Error::from_thread().message());
            }
            if n < buf.len() {
                break n;
            }
            buf.resize(n + 1, 0);
        };
        let s = String::from_utf16_lossy(&buf[..n]);
        let s = match s.strip_prefix(r"\\?\UNC\") {
            Some(rest) => format!(r"\\{rest}"),
            None => s.strip_prefix(r"\\?\").unwrap_or(&s).to_string(),
        };
        Ok(Some(PathBuf::from(s)))
    }

    pub fn known_folder(folder: super::KnownFolder) -> Option<PathBuf> {
        use super::KnownFolder as K;
        use windows::Win32::System::Com::CoTaskMemFree;
        use windows::Win32::UI::Shell::{
            FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_LocalAppData, FOLDERID_Music,
            FOLDERID_Pictures, FOLDERID_Profile, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86,
            FOLDERID_RoamingAppData, FOLDERID_Videos, SHGetKnownFolderPath, KF_FLAG_DONT_VERIFY,
        };
        let id = match folder {
            K::Documents => FOLDERID_Documents,
            K::Desktop => FOLDERID_Desktop,
            K::Pictures => FOLDERID_Pictures,
            K::Videos => FOLDERID_Videos,
            K::Music => FOLDERID_Music,
            K::LocalAppData => FOLDERID_LocalAppData,
            K::RoamingAppData => FOLDERID_RoamingAppData,
            K::Profile => FOLDERID_Profile,
            K::ProgramFiles => FOLDERID_ProgramFiles,
            K::ProgramFilesX86 => FOLDERID_ProgramFilesX86,
        };
        unsafe {
            let p = SHGetKnownFolderPath(&id, KF_FLAG_DONT_VERIFY, None).ok()?;
            let path = p.to_string().ok().filter(|s| !s.is_empty());
            CoTaskMemFree(Some(p.0 as *const _));
            path.map(PathBuf::from)
        }
    }

    /// `GetSystemWindowsDirectoryW`: the shared Windows folder even under Terminal Services,
    /// where `GetWindowsDirectoryW` may return a per-user one (2nd audit D2).
    pub fn windows_dir() -> Option<PathBuf> {
        let mut buf = vec![0u16; 260];
        loop {
            let n = unsafe { GetSystemWindowsDirectoryW(Some(&mut buf)) } as usize;
            if n == 0 {
                return None;
            }
            if n < buf.len() {
                return Some(OsString::from_wide(&buf[..n]).into());
            }
            buf.resize(n, 0);
        }
    }
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

    /// Audit 10: `to_lowercase` merges names NTFS keeps apart, so a rule, exclusion or sync
    /// root could match a different folder. These pairs are distinct for `CompareStringOrdinal`
    /// (checked on Windows 11) but equal after `to_lowercase`.
    #[test]
    fn audit_10_names_compare_like_ntfs() {
        for (a, b) in [
            ("straße", "STRAẞE"),
            ("\u{212A}ube", "kube"),   // Kelvin sign
            ("\u{2126}mega", "ωmega"), // Ohm sign
            ("\u{1C5}x", "\u{1C6}x"),  // ǅ and ǆ
        ] {
            assert_eq!(a.to_lowercase(), b.to_lowercase(), "{a} {b}");
            assert!(!eq_ci(a, b), "{a} {b}");
            assert_ne!(fold(a), fold(b), "{a} {b}");
            assert!(!same_path(
                Path::new(&format!(r"C:\Users\me\{a}")),
                Path::new(&format!(r"C:\Users\me\{b}"))
            ));
        }
        // Real case pairs still match, ASCII or not.
        for (a, b) in [("OneDrive", "onedrive"), ("σü", "ΣÜ"), ("ÿ", "Ÿ")] {
            assert!(eq_ci(a, b), "{a} {b}");
            assert_eq!(fold(a), fold(b), "{a} {b}");
        }
        assert!(is_within(
            Path::new(r"C:\Users\me\ΣÜ\x"),
            Path::new(r"c:\users\ME\σü")
        ));
        assert!(ends_with_ci("db.KDBX", ".kdbx"));
        assert!(!ends_with_ci("ü", ".kdbx"));
    }

    #[test]
    fn verbatim_forms() {
        assert_eq!(
            verbatim(Path::new(r"C:\a\b.")),
            PathBuf::from(r"\\?\C:\a\b.")
        );
        assert_eq!(verbatim(Path::new(r"C:\")), PathBuf::from(r"\\?\C:\"));
        assert_eq!(verbatim(Path::new("C:/a/b")), PathBuf::from(r"\\?\C:\a\b"));
        assert_eq!(
            verbatim(Path::new(r"\\srv\share\x")),
            PathBuf::from(r"\\?\UNC\srv\share\x")
        );
        for p in [r"\\?\C:\x", r"\\.\C:", r"rel\x", r"C:\a\..\b", r"C:rel"] {
            assert_eq!(verbatim(Path::new(p)), PathBuf::from(p), "{p}");
        }
    }

    /// Focused review 5: shell folders come from the shell, tool variables from the environment.
    #[test]
    fn review_5_lookup_reads_shell_folders_from_the_shell() {
        for (name, folder) in SHELL_FOLDERS {
            let got = lookup(name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(Some(got.clone()), known_folder(*folder), "{name}");
            assert!(got.is_absolute(), "{name}: {got:?}");
        }
        assert_eq!(lookup("SystemRoot"), windows_dir());
        assert_eq!(lookup("windir"), windows_dir());
        assert_eq!(lookup("NVM_HOME"), env_path("NVM_HOME"));
        assert_eq!(lookup("ClearCacheNoSuchVar"), None);
    }

    /// Audit 13: the Windows folder comes from the OS, not from a variable anyone can set.
    #[test]
    fn audit_13_windows_dir_comes_from_the_os() {
        let w = windows_dir().expect("GetSystemWindowsDirectoryW");
        assert!(w.join("System32").is_dir(), "{w:?}");
    }
}
