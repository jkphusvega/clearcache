//! Cloud sync roots (OneDrive and SyncRootManager providers), collected once per scan.
//! Files inside a sync root are never opened by accounting; M4 blocks quarantine there (S7).
//!
//! Each source reports how many roots it found or why it failed (D14). A missing key or unset
//! variable is "found 0", not a failure; failures are access/read errors.

use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::core::paths;

pub trait SyncRootSource: Send + Sync {
    fn name(&self) -> &'static str;
    fn read(&self) -> Result<Vec<PathBuf>, String>;
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceResult {
    pub source: &'static str,
    pub found: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SyncRootDetection {
    pub sources: Vec<SourceResult>,
    pub roots: Vec<String>,
    /// At least one source failed → UI warning "동기화 폴더 감지 일부 실패".
    pub partial_failure: bool,
    /// Every source failed → accounting inside the user folder is skipped ("미검증").
    pub all_failed: bool,
    #[serde(skip)]
    root_paths: Vec<PathBuf>,
}

impl SyncRootDetection {
    pub fn detect(sources: &[Box<dyn SyncRootSource>]) -> Self {
        let mut det = SyncRootDetection::default();
        for s in sources {
            match s.read() {
                Ok(found) => {
                    det.sources.push(SourceResult {
                        source: s.name(),
                        found: found.len(),
                        error: None,
                    });
                    for p in found {
                        if !det.root_paths.iter().any(|r| paths::same_path(r, &p)) {
                            det.root_paths.push(p);
                        }
                    }
                }
                Err(e) => det.sources.push(SourceResult {
                    source: s.name(),
                    found: 0,
                    error: Some(e),
                }),
            }
        }
        let failed = det.sources.iter().filter(|s| s.error.is_some()).count();
        det.partial_failure = failed > 0;
        det.all_failed = !sources.is_empty() && failed == sources.len();
        det.roots = det
            .root_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        det
    }

    pub fn contains(&self, path: &Path) -> bool {
        self.root_paths.iter().any(|r| paths::is_within(path, r))
    }

    /// For tests and the CLI: a detection with fixed roots and no failures.
    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        struct Fixed(Vec<PathBuf>);
        impl SyncRootSource for Fixed {
            fn name(&self) -> &'static str {
                "fixed"
            }
            fn read(&self) -> Result<Vec<PathBuf>, String> {
                Ok(self.0.clone())
            }
        }
        Self::detect(&[Box::new(Fixed(roots))])
    }
}

pub fn system_sources() -> Vec<Box<dyn SyncRootSource>> {
    vec![
        Box::new(win::SyncRootManager),
        Box::new(win::OneDriveAccounts),
        Box::new(EnvVars),
    ]
}

pub fn detect_system() -> SyncRootDetection {
    SyncRootDetection::detect(&system_sources())
}

struct EnvVars;

impl SyncRootSource for EnvVars {
    fn name(&self) -> &'static str {
        "env"
    }
    fn read(&self) -> Result<Vec<PathBuf>, String> {
        Ok(["OneDrive", "OneDriveConsumer", "OneDriveCommercial"]
            .iter()
            .filter_map(|v| paths::env_path(v))
            .collect())
    }
}

mod win {
    use super::SyncRootSource;
    use std::path::PathBuf;
    use windows::core::{HSTRING, PWSTR};
    use windows::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegGetValueW, RegOpenKeyExW, HKEY,
        HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ, REG_SZ, RRF_RT_REG_SZ,
    };

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    /// `Ok(None)` if the key does not exist.
    fn open(parent: HKEY, sub: &str) -> Result<Option<Key>, String> {
        let mut out = HKEY::default();
        let rc = unsafe { RegOpenKeyExW(parent, &HSTRING::from(sub), None, KEY_READ, &mut out) };
        match rc {
            ERROR_SUCCESS => Ok(Some(Key(out))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            e => Err(format!("{sub}: {}", err(e))),
        }
    }

    fn err(e: WIN32_ERROR) -> String {
        windows::core::Error::from(e.to_hresult()).message()
    }

    fn subkeys(key: &Key) -> Result<Vec<String>, String> {
        let mut names = Vec::new();
        for i in 0.. {
            let mut buf = [0u16; 512];
            let mut len = buf.len() as u32;
            let rc = unsafe {
                RegEnumKeyExW(
                    key.0,
                    i,
                    Some(PWSTR(buf.as_mut_ptr())),
                    &mut len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            match rc {
                ERROR_SUCCESS => names.push(String::from_utf16_lossy(&buf[..len as usize])),
                ERROR_NO_MORE_ITEMS => break,
                e => return Err(err(e)),
            }
        }
        Ok(names)
    }

    /// String values (REG_SZ / REG_EXPAND_SZ) of a key.
    fn string_values(key: &Key) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for i in 0.. {
            let mut name = [0u16; 512];
            let mut name_len = name.len() as u32;
            let mut data = vec![0u8; 4096];
            let mut data_len = data.len() as u32;
            let mut ty = 0u32;
            let rc = unsafe {
                RegEnumValueW(
                    key.0,
                    i,
                    Some(PWSTR(name.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut ty),
                    Some(data.as_mut_ptr()),
                    Some(&mut data_len),
                )
            };
            match rc {
                ERROR_SUCCESS => {
                    if ty == REG_SZ.0 || ty == REG_EXPAND_SZ.0 {
                        let wide: Vec<u16> = data[..data_len as usize]
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|c| u16::from_le_bytes(*c))
                            .take_while(|&c| c != 0)
                            .collect();
                        out.push(String::from_utf16_lossy(&wide));
                    }
                }
                ERROR_NO_MORE_ITEMS => break,
                e => return Err(err(e)),
            }
        }
        Ok(out)
    }

    fn looks_like_path(s: &str) -> bool {
        crate::core::paths::drive_letter(std::path::Path::new(s)).is_some()
    }

    /// `HKLM\...\SyncRootManager\<provider>\UserSyncRoots`: value name = SID, data = path.
    pub struct SyncRootManager;
    impl SyncRootSource for SyncRootManager {
        fn name(&self) -> &'static str {
            "sync_root_manager"
        }
        fn read(&self) -> Result<Vec<PathBuf>, String> {
            let base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager";
            let Some(root) = open(HKEY_LOCAL_MACHINE, base)? else {
                return Ok(vec![]);
            };
            let mut found = Vec::new();
            for provider in subkeys(&root)? {
                if let Some(k) = open(root.0, &format!(r"{provider}\UserSyncRoots"))? {
                    found.extend(
                        string_values(&k)?
                            .into_iter()
                            .filter(|s| looks_like_path(s))
                            .map(PathBuf::from),
                    );
                }
            }
            Ok(found)
        }
    }

    /// `HKCU\Software\Microsoft\OneDrive\Accounts\*\UserFolder`.
    pub struct OneDriveAccounts;
    impl SyncRootSource for OneDriveAccounts {
        fn name(&self) -> &'static str {
            "onedrive_accounts"
        }
        fn read(&self) -> Result<Vec<PathBuf>, String> {
            let Some(accounts) = open(HKEY_CURRENT_USER, r"Software\Microsoft\OneDrive\Accounts")?
            else {
                return Ok(vec![]);
            };
            let mut found = Vec::new();
            for acct in subkeys(&accounts)? {
                let mut buf = [0u16; 1024];
                let mut len = (buf.len() * 2) as u32;
                let rc = unsafe {
                    RegGetValueW(
                        accounts.0,
                        &HSTRING::from(acct.as_str()),
                        &HSTRING::from("UserFolder"),
                        RRF_RT_REG_SZ,
                        None,
                        Some(buf.as_mut_ptr().cast()),
                        Some(&mut len),
                    )
                };
                match rc {
                    ERROR_SUCCESS => {
                        let s = String::from_utf16_lossy(&buf[..(len as usize / 2)]);
                        let s = s.trim_end_matches('\0');
                        if looks_like_path(s) {
                            found.push(PathBuf::from(s));
                        }
                    }
                    ERROR_FILE_NOT_FOUND => {}
                    e => return Err(format!("{acct}: {}", err(e))),
                }
            }
            Ok(found)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake(&'static str, Result<Vec<PathBuf>, String>);
    impl SyncRootSource for Fake {
        fn name(&self) -> &'static str {
            self.0
        }
        fn read(&self) -> Result<Vec<PathBuf>, String> {
            self.1.clone()
        }
    }

    #[test]
    fn syncroots_merge_and_contains() {
        let det = SyncRootDetection::detect(&[
            Box::new(Fake("a", Ok(vec![PathBuf::from(r"C:\Users\me\OneDrive")]))),
            Box::new(Fake("b", Ok(vec![PathBuf::from(r"c:\users\me\onedrive\")]))),
        ]);
        assert_eq!(det.roots.len(), 1);
        assert!(!det.partial_failure && !det.all_failed);
        assert!(det.contains(Path::new(r"C:\Users\me\OneDrive\Docs\a.txt")));
        assert!(!det.contains(Path::new(r"C:\Users\me\OneDriveX")));
    }

    #[test]
    fn syncroots_one_failure_sets_warning() {
        let det = SyncRootDetection::detect(&[
            Box::new(Fake("a", Err("access denied".into()))),
            Box::new(Fake("b", Ok(vec![PathBuf::from(r"C:\OD")]))),
        ]);
        assert!(det.partial_failure);
        assert!(!det.all_failed);
        assert_eq!(det.sources[0].error.as_deref(), Some("access denied"));
        assert_eq!(det.sources[1].found, 1);
    }

    #[test]
    fn syncroots_all_failed() {
        let det = SyncRootDetection::detect(&[
            Box::new(Fake("a", Err("x".into()))),
            Box::new(Fake("b", Err("y".into()))),
        ]);
        assert!(det.partial_failure && det.all_failed);
    }

    #[test]
    fn syncroots_system_sources_run() {
        // Read-only probe of the real registry/env; must not error on a normal machine.
        let det = detect_system();
        assert_eq!(det.sources.len(), 3);
        for s in &det.sources {
            eprintln!("{}: found {} error {:?}", s.source, s.found, s.error);
        }
    }
}
