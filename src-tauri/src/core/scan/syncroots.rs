//! Cloud sync roots (OneDrive and SyncRootManager providers), collected once per scan.
//! Files inside a sync root are never opened by accounting; M4 blocks quarantine there (S7).
//!
//! Each source reports how many roots it found or why it failed (D14). A missing key is "found
//! 0", not a failure; failures are access/read errors and roots that cannot be put in comparison
//! form. Detection fails closed: a source that cannot vouch for an empty answer (environment
//! variables are simply unset when OneDrive is absent) does not count as a success.

use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::core::paths;
use crate::core::protect::CanonPath;

pub trait SyncRootSource: Send + Sync {
    fn name(&self) -> &'static str;
    fn read(&self) -> Result<Vec<PathBuf>, String>;
    /// "Found 0" from this source means there are none. False for sources whose silence
    /// proves nothing; they count as a success only when they find something.
    fn authoritative(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceResult {
    pub source: &'static str,
    pub found: usize,
    pub error: Option<String>,
    /// Counted as a working source for `all_failed`.
    pub succeeded: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SyncRootDetection {
    pub sources: Vec<SourceResult>,
    pub roots: Vec<String>,
    /// At least one source failed → UI warning "동기화 폴더 감지 일부 실패".
    pub partial_failure: bool,
    /// No source succeeded → accounting inside the user folder is skipped ("미검증") and
    /// selection there is refused (D11).
    pub all_failed: bool,
    #[serde(skip)]
    root_paths: Vec<PathBuf>,
}

impl SyncRootDetection {
    pub fn detect(sources: &[Box<dyn SyncRootSource>]) -> Self {
        let mut det = SyncRootDetection::default();
        for s in sources {
            let (found, error) = match s.read() {
                Ok(found) => {
                    // Keep every root in the form the walk compares against. One that only
                    // Windows can resolve (`C:\od\.\root`, `\\?\Volume{…}\od`) is resolved first;
                    // one that cannot be resolved fails its source instead of disappearing.
                    let n = found.len();
                    let mut bad = Vec::new();
                    for p in found {
                        let usable = if CanonPath::new(&p).is_some() {
                            Some(p.clone())
                        } else {
                            paths::resolve(&p).filter(|r| CanonPath::new(r).is_some())
                        };
                        match usable {
                            Some(r) => {
                                if !det.root_paths.iter().any(|x| paths::same_path(x, &r)) {
                                    det.root_paths.push(r);
                                }
                            }
                            None => bad.push(p.to_string_lossy().into_owned()),
                        }
                    }
                    let error = (!bad.is_empty())
                        .then(|| format!("경로를 확인할 수 없음: {}", bad.join(", ")));
                    (n, error)
                }
                Err(e) => (0, Some(e)),
            };
            det.sources.push(SourceResult {
                source: s.name(),
                found,
                succeeded: error.is_none() && (s.authoritative() || found > 0),
                error,
            });
        }
        det.partial_failure = det.sources.iter().any(|s| s.error.is_some());
        det.all_failed = !det.sources.iter().any(|s| s.succeeded);
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
    fn authoritative(&self) -> bool {
        false
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
                        let v = String::from_utf16_lossy(&wide);
                        out.push(if ty == REG_EXPAND_SZ.0 {
                            expand(&v)?
                        } else {
                            v
                        });
                    }
                }
                ERROR_NO_MORE_ITEMS => break,
                e => return Err(err(e)),
            }
        }
        Ok(out)
    }

    /// `%USERPROFILE%\OneDrive` → the real path. A value that does not expand is an error.
    fn expand(s: &str) -> Result<String, String> {
        use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
        let src = HSTRING::from(s);
        let mut buf = vec![0u16; 1024];
        loop {
            let n = unsafe { ExpandEnvironmentStringsW(&src, Some(&mut buf)) } as usize;
            if n == 0 {
                return Err(format!("환경 변수를 펼치지 못함: {s}"));
            }
            if n <= buf.len() {
                let out = String::from_utf16_lossy(&buf[..n - 1]);
                return if out.contains('%') {
                    Err(format!("환경 변수를 펼치지 못함: {s}"))
                } else {
                    Ok(out)
                };
            }
            buf.resize(n, 0);
        }
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
                    // Every value is a root; one that is not a usable path fails this source
                    // in `detect` rather than being skipped here.
                    found.extend(string_values(&k)?.into_iter().map(PathBuf::from));
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
                        found.push(PathBuf::from(s));
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
