//! Protection verdicts (SPEC 안전 규칙): system paths, whole roots, credential paths and files, and
//! the S2·S7·S9·S11 facts the scan lifts to parents. Every "cannot tell" falls toward protection.
//!
//! The scan calls `path_protection` and `file_protection` per entry; `check_item` re-checks one
//! item against the disk as it is now, and M4 calls it again right before quarantine (S3) and
//! restore (S12). Release gate: this file is "시스템 폴더 보호 검사 코드".

use serde::Serialize;
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::core::paths;
use crate::core::scan::attrs::{self, EntryKind};
use crate::core::scan::policy::{QUARANTINE_DIR, ROOT_SYSTEM_FILES};
use crate::core::scan::syncroots::SyncRootDetection;

/// Protected at the root of any drive, with everything below (SPEC 안전 규칙).
pub const SYSTEM_DIRS: &[&str] = &[
    "Windows",
    "Windows.old",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    "System Volume Information",
    "$Recycle.Bin",
    "Recovery",
    "$WinREAgent",
    "PerfLogs",
    "Boot",
    "EFI",
    "Config.Msi",
    "$WINDOWS.~BT",
    "$WINDOWS.~WS",
];

/// `Windows.old.000` and the like, left by repeated upgrades.
pub const WINDOWS_OLD_PREFIX: &str = "Windows.old.";

/// Credential folders matched by name wherever they are (Q2), as runs of components with the
/// name shown for them. They stop at built-in rule folders like credential files (D12).
pub const CREDENTIAL_DIRS: &[(&[&str], &str)] = &[
    (&[".ssh"], ".ssh"),
    (&[".aws"], ".aws"),
    (&[".gnupg"], ".gnupg"),
    (&[".azure"], ".azure"),
    (&[".kube"], ".kube"),
    (&[".docker"], ".docker"),
    (&[".config", "gcloud"], r".config\gcloud"),
];

/// Credential paths matched as a run of components anywhere: browser and mail profiles, and
/// the per-user stores under any profile's `AppData`. These cross rule folders.
pub const CREDENTIAL_SUFFIXES: &[&[&str]] = &[
    &["Google", "Chrome", "User Data"],
    &["Google", "Chrome Beta", "User Data"],
    &["Google", "Chrome Dev", "User Data"],
    &["Google", "Chrome SxS", "User Data"],
    &["Microsoft", "Edge", "User Data"],
    &["Microsoft", "Edge Beta", "User Data"],
    &["Microsoft", "Edge Dev", "User Data"],
    &["Microsoft", "Edge SxS", "User Data"],
    &["Naver", "Naver Whale", "User Data"],
    &["BraveSoftware", "Brave-Browser", "User Data"],
    &["Vivaldi", "User Data"],
    &["Opera Software", "Opera Stable"],
    &["Opera Software", "Opera GX Stable"],
    &["Mozilla", "Firefox", "Profiles"],
    &["Thunderbird", "Profiles"],
    &["AppData", "Local", "Packages"],
    &["AppData", "Local", "Microsoft", "Credentials"],
    &["AppData", "Local", "Microsoft", "Vault"],
    &["AppData", "Local", "1Password"],
    &["AppData", "Roaming", "Microsoft", "Protect"],
    &["AppData", "Roaming", "Microsoft", "Credentials"],
    &["AppData", "Roaming", "Microsoft", "Crypto"],
    &["AppData", "Roaming", "Microsoft", "Vault"],
    &["AppData", "Roaming", "gnupg"],
    &["AppData", "Roaming", "gcloud"],
    &["AppData", "Roaming", "Bitwarden"],
];

/// The same stores anchored on the environment, for a redirected `AppData`.
const CREDENTIAL_ENV: &[(&str, &str)] = &[
    ("LOCALAPPDATA", "Packages"),
    ("LOCALAPPDATA", r"Microsoft\Credentials"),
    ("LOCALAPPDATA", r"Microsoft\Vault"),
    ("LOCALAPPDATA", "1Password"),
    ("APPDATA", r"Microsoft\Protect"),
    ("APPDATA", r"Microsoft\Credentials"),
    ("APPDATA", r"Microsoft\Crypto"),
    ("APPDATA", r"Microsoft\Vault"),
    ("APPDATA", "gnupg"),
    ("APPDATA", "gcloud"),
    ("APPDATA", "Bitwarden"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMatch {
    Ext(&'static str),
    FileName(&'static str),
    /// A folder whose name ends this way is itself the credential store.
    DirExt(&'static str),
}

/// Any one of these makes its folder a credential store regardless of size (D12). The M4
/// re-check uses the same table. Left out for false positives: `.pem` `.key` `.crt` `.cer`
/// (dev projects), `.gpg` `.asc` (public keys; `.gnupg` is a credential path), `.jks`
/// `.keystore` (Android), bare `id_rsa` (`.ssh` is a credential path).
pub const CREDENTIAL_FILES: &[CredentialMatch] = &[
    CredentialMatch::Ext(".kdbx"),
    CredentialMatch::Ext(".kdb"),
    CredentialMatch::Ext(".psafe3"),
    CredentialMatch::Ext(".ppk"),
    CredentialMatch::Ext(".pfx"),
    CredentialMatch::Ext(".p12"),
    CredentialMatch::FileName("wallet.dat"),
    CredentialMatch::DirExt(".opvault"),
];

/// Folders pinned to "사용자 데이터" by the safety rules, with the name used under
/// `%USERPROFILE%` when the shell cannot say where the folder is.
pub const PERSONAL_FOLDERS: &[(KnownFolder, &str)] = &[
    (KnownFolder::Documents, "Documents"),
    (KnownFolder::Desktop, "Desktop"),
    (KnownFolder::Pictures, "Pictures"),
    (KnownFolder::Videos, "Videos"),
    (KnownFolder::Music, "Music"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownFolder {
    Documents,
    Desktop,
    Pictures,
    Videos,
    Music,
}

/// WSL·Docker·Hyper-V·VirtualBox·QEMU disks (S11), protected regardless of size.
pub const VIRTUAL_DISK_EXTS: &[&str] = &[
    ".vhdx", ".vhd", ".avhdx", ".vhds", ".vmdk", ".vdi", ".qcow2",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Reason {
    /// SPEC system path, root system file or `%SystemRoot%`.
    System,
    Quarantine,
    /// Browser profile, `Packages` or a Windows key store, matched by location (Q2).
    CredentialPath,
    /// `.ssh`, `.aws`, … matched by name wherever it is (Q2); `name` is the folder name.
    CredentialDir {
        name: &'static str,
    },
    /// `name` is what matched: `.kdbx`, `wallet.dat`, `.opvault`, … (D12).
    CredentialFile {
        name: &'static str,
    },
    /// A detected sync root or anything inside it (S7).
    SyncRoot,
    /// Cloud-only attributes where no sync root was detected.
    CloudFile,
    /// Junction, symlink or mount point (S9).
    Reparse,
    VirtualDisk,
    DriveRoot,
    /// `C:\Users`, `C:\Users\<name>`, the profile folder and its ancestors.
    UserFolderRoot,
    /// No comparison form: 8.3 lookup failed, `..`, stream syntax, relative or device path.
    Unresolved,
    /// A folder or entry at or below could not be listed, so something protected could hide
    /// there (S2). The scan and `check_item` both block on it ("하위 폴더를 읽지 못해 안전 확인 불가").
    Unreadable,
}

impl Reason {
    /// Found by name inside a "안전"/"아마 안전" rule folder, these block that folder only and
    /// go no higher (D12, the same boundary as `.git`): a library's test fixture must not lock
    /// the whole project.
    pub fn stops_at_rule_folder(&self) -> bool {
        matches!(
            self,
            Reason::CredentialFile { .. } | Reason::CredentialDir { .. }
        )
    }

    /// Credential paths, folders and files: `explain_only` and never selectable (Q2, D12).
    pub fn is_credential(&self) -> bool {
        matches!(
            self,
            Reason::CredentialPath | Reason::CredentialDir { .. } | Reason::CredentialFile { .. }
        )
    }
}

/// D13: `Self_` puts the folder's bytes in "건드리면 안 됨"; `Contains` blocks selection but the
/// bytes keep the folder's own grade and action. Selection checks both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "scope", content = "reason")]
pub enum Protection {
    #[serde(rename = "self")]
    Self_(Reason),
    /// Something protected inside (S2), or a root that cannot go whole.
    Contains(Reason),
}

impl Protection {
    pub fn reason(&self) -> &Reason {
        match self {
            Protection::Self_(r) | Protection::Contains(r) => r,
        }
    }

    pub fn is_self(&self) -> bool {
        matches!(self, Protection::Self_(_))
    }

    /// What the parent inherits (S2). Links (S9) and whole-root blocks are not protection
    /// targets. `stop_folder`: this node is a folder whose "안전"/"아마 안전" rule stops the walk
    /// (see `Reason::stops_at_rule_folder`).
    pub fn lifted(&self, stop_folder: bool) -> Option<Protection> {
        match self.reason() {
            Reason::Reparse | Reason::DriveRoot | Reason::UserFolderRoot => None,
            r if stop_folder && r.stops_at_rule_folder() => None,
            r => Some(Protection::Contains(r.clone())),
        }
    }

    /// `Self_` wins over `Contains`; otherwise the first one stays.
    pub fn merge(a: Option<Protection>, b: Option<Protection>) -> Option<Protection> {
        match (a, b) {
            (Some(Protection::Contains(_)), Some(b @ Protection::Self_(_))) => Some(b),
            (None, b) => b,
            (a, _) => a,
        }
    }
}

/// Comparison form of a path for protection checks: components as written (compared with
/// `paths::eq_ci`, the NTFS rule), no `\\?\` prefix or trailing separator, 8.3 aliases expanded,
/// trailing dots and spaces dropped as Win32 does. M4's quarantine and restore commands compare
/// with this same form.
#[derive(Debug, Clone)]
pub struct CanonPath {
    /// `C:` or `\\server\share`.
    pub root: String,
    pub comps: Vec<String>,
}

impl PartialEq for CanonPath {
    fn eq(&self, other: &Self) -> bool {
        self.comps.len() == other.comps.len() && self.starts_with(other)
    }
}

impl Eq for CanonPath {}

/// `PROGRA~1`, `FILE~12.TXT`: a name Windows may have generated as an 8.3 alias. Only these
/// are looked up, so `$WINDOWS.~BT` or `a~b` are taken as written.
fn looks_short(name: &str) -> bool {
    let (base, ext) = name.rsplit_once('.').unwrap_or((name, ""));
    let Some((_, digits)) = base.rsplit_once('~') else {
        return false;
    };
    base.len() <= 8
        && ext.len() <= 3
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
}

impl CanonPath {
    /// `None` when the path cannot be put in comparison form; callers treat that as protected.
    pub fn new(path: &Path) -> Option<Self> {
        Self::parse(path, true)
    }

    fn parse(path: &Path, expand_short: bool) -> Option<Self> {
        let s = path.to_string_lossy().replace('/', "\\");
        let s = match s.strip_prefix(r"\\?\UNC\") {
            Some(rest) => format!(r"\\{rest}"),
            None => s.strip_prefix(r"\\?\").unwrap_or(&s).to_string(),
        };
        let (root, rest) = split_root(&s)?;
        let mut comps = Vec::new();
        for c in rest.split('\\').filter(|c| !c.is_empty()) {
            if c == "." || c == ".." || c.contains(':') {
                return None;
            }
            let c = c.trim_end_matches(['.', ' ']);
            if c.is_empty() {
                return None;
            }
            comps.push(c.to_string());
        }
        // A real long name can look like an alias; then the lookup returns it unchanged.
        if expand_short && comps.iter().any(|c| looks_short(c)) {
            return Self::parse(&win::long_name(Path::new(&s))?, false);
        }
        Some(Self { root, comps })
    }

    /// `self` is `other` or lies inside it.
    pub fn starts_with(&self, other: &CanonPath) -> bool {
        paths::eq_ci(&self.root, &other.root)
            && self.comps.len() >= other.comps.len()
            && self
                .comps
                .iter()
                .zip(&other.comps)
                .all(|(a, b)| paths::eq_ci(a, b))
    }

    /// Component `i` is `name`.
    pub fn comp_is(&self, i: usize, name: &str) -> bool {
        self.comps.get(i).is_some_and(|c| paths::eq_ci(c, name))
    }

    /// The last components are `names`.
    pub fn ends_with(&self, names: &[impl AsRef<str>]) -> bool {
        self.comps.len() >= names.len()
            && self.comps[self.comps.len() - names.len()..]
                .iter()
                .zip(names)
                .all(|(a, b)| paths::eq_ci(a, b.as_ref()))
    }

    pub fn contains_run(&self, run: &[&str]) -> bool {
        self.comps
            .windows(run.len())
            .any(|w| w.iter().zip(run).all(|(a, b)| paths::eq_ci(a, b)))
    }
}

/// `C:` (followed by `\` or nothing) or `\\server\share`; device paths and `C:relative` fail.
fn split_root(s: &str) -> Option<(String, &str)> {
    if let Some(unc) = s.strip_prefix(r"\\") {
        let mut it = unc.splitn(3, '\\');
        let server = it
            .next()
            .filter(|x| !x.is_empty() && *x != "." && *x != "?")?;
        let share = it.next().filter(|x| !x.is_empty())?;
        return Some((format!(r"\\{server}\{share}"), it.next().unwrap_or("")));
    }
    let b = s.as_bytes();
    let drive = b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':';
    (drive && (b.len() == 2 || b[2] == b'\\')).then(|| (s[..2].to_ascii_uppercase(), &s[2..]))
}

/// Copies that keep a credential file's contents: `db.kdbx.bak` is still a password database.
pub const BACKUP_SUFFIXES: &[&str] = &[".bak", ".old", ".orig", ".backup", ".tmp"];

/// What a file seen in a listing makes of its folder (`Self_`): a credential store (D12) or a
/// virtual disk holder (S11). Size does not matter for either. The name is matched as Win32
/// would open it (trailing dots and spaces dropped: `db.kdbx.`), and also without one backup
/// suffix (`db.kdbx.bak`), audit 9.
pub fn file_protection(name: &str) -> Option<Reason> {
    let name = name.trim_end_matches(['.', ' ']);
    let unbacked = BACKUP_SUFFIXES
        .iter()
        .find(|s| paths::ends_with_ci(name, s))
        .map(|s| name[..name.len() - s.len()].trim_end_matches(['.', ' ']));
    [Some(name), unbacked]
        .into_iter()
        .flatten()
        .find_map(file_protection_exact)
}

fn file_protection_exact(name: &str) -> Option<Reason> {
    if VIRTUAL_DISK_EXTS
        .iter()
        .any(|e| paths::ends_with_ci(name, e))
    {
        return Some(Reason::VirtualDisk);
    }
    CREDENTIAL_FILES.iter().find_map(|m| match *m {
        CredentialMatch::Ext(e) if paths::ends_with_ci(name, e) => {
            Some(Reason::CredentialFile { name: e })
        }
        CredentialMatch::FileName(n) if paths::eq_ci(name, n) => {
            Some(Reason::CredentialFile { name: n })
        }
        _ => None,
    })
}

fn credential_dir(comp: &str) -> Option<&'static str> {
    CREDENTIAL_FILES.iter().find_map(|m| match *m {
        CredentialMatch::DirExt(e) if paths::ends_with_ci(comp, e) => Some(e),
        _ => None,
    })
}

/// Environment and sync roots a verdict depends on. Build a fresh one for each re-check.
#[derive(Debug, Clone, Default)]
pub struct ProtectContext {
    system_root: Option<CanonPath>,
    user_home: Option<CanonPath>,
    personal_folders: Vec<CanonPath>,
    credential_dirs: Vec<CanonPath>,
    sync_roots: Vec<CanonPath>,
    sync_all_failed: bool,
}

impl ProtectContext {
    /// `env` resolves `SystemRoot`, `USERPROFILE`, `LOCALAPPDATA` and `APPDATA`. For tests;
    /// the app uses `from_system`.
    pub fn new(env: impl Fn(&str) -> Option<PathBuf>, sync: &SyncRootDetection) -> Self {
        let canon = |var: &str, rel: &str| env(var).and_then(|p| CanonPath::new(&p.join(rel)));
        Self {
            system_root: canon("SystemRoot", ""),
            user_home: canon("USERPROFILE", ""),
            personal_folders: PERSONAL_FOLDERS
                .iter()
                .filter_map(|(_, name)| canon("USERPROFILE", name))
                .collect(),
            credential_dirs: CREDENTIAL_ENV
                .iter()
                .filter_map(|(var, rel)| canon(var, rel))
                .collect(),
            sync_roots: sync
                .roots
                .iter()
                .filter_map(|r| CanonPath::new(Path::new(r)))
                .collect(),
            sync_all_failed: sync.all_failed,
        }
    }

    pub fn from_system(sync: &SyncRootDetection) -> Self {
        Self::from_shell(paths::env_path, sync)
    }

    /// The Windows folder comes from `GetWindowsDirectoryW`, never `%SystemRoot%`, and personal
    /// folders from `SHGetKnownFolderPath`, so moved ones are found too; a folder the shell
    /// cannot resolve falls back to its name under the profile.
    fn from_shell(env: impl Fn(&str) -> Option<PathBuf>, sync: &SyncRootDetection) -> Self {
        let home = env("USERPROFILE");
        let mut ctx = Self::new(env, sync);
        ctx.system_root = paths::windows_dir().and_then(|w| CanonPath::new(&w));
        let folders = PERSONAL_FOLDERS
            .iter()
            .filter_map(|(id, name)| {
                win::known_folder(id).or_else(|| Some(home.as_ref()?.join(name)))
            })
            .collect();
        ctx.with_personal_folders(folders)
    }

    /// Replaces the personal folders (Documents, Desktop, …) the safety rules pin.
    pub fn with_personal_folders(mut self, folders: Vec<PathBuf>) -> Self {
        self.personal_folders = folders.iter().filter_map(|p| CanonPath::new(p)).collect();
        self
    }

    pub fn personal_folders(&self) -> &[CanonPath] {
        &self.personal_folders
    }

    pub fn system_root(&self) -> Option<&CanonPath> {
        self.system_root.as_ref()
    }

    pub fn user_home(&self) -> Option<&CanonPath> {
        self.user_home.as_ref()
    }

    /// Sync detection cannot clear `path` (S7, D11): no source succeeded and the path is in the
    /// user folder, or there is no user folder to tell inside from outside. Fails closed.
    pub fn sync_unverified(&self, path: &CanonPath) -> bool {
        match &self.user_home {
            None => true,
            Some(home) => self.sync_all_failed && path.starts_with(home),
        }
    }

    /// Protection that follows from the path alone. Contents (S2, credential files, virtual
    /// disks) and links (S9) come from the listing: the scan, or `check_item`.
    pub fn path_protection(&self, path: &Path) -> Option<Protection> {
        match CanonPath::new(path) {
            Some(c) => self.canon_protection(&c),
            None => Some(Protection::Self_(Reason::Unresolved)),
        }
    }

    fn canon_protection(&self, c: &CanonPath) -> Option<Protection> {
        use Protection::{Contains, Self_};
        let first = c.comps.first().map(String::as_str).unwrap_or("");
        if SYSTEM_DIRS.iter().any(|d| paths::eq_ci(first, d))
            || is_windows_old_n(first)
            || (c.comps.len() == 1 && ROOT_SYSTEM_FILES.iter().any(|f| paths::eq_ci(first, f)))
            || self
                .system_root
                .as_ref()
                .is_some_and(|sr| c.starts_with(sr))
        {
            return Some(Self_(Reason::System));
        }
        if paths::eq_ci(first, QUARANTINE_DIR) {
            return Some(Self_(Reason::Quarantine));
        }
        if let Some(name) = c.comps.iter().find_map(|x| credential_dir(x)) {
            return Some(Self_(Reason::CredentialFile { name }));
        }
        // Location first: a `.ssh` inside `Packages` still crosses rule folders.
        if CREDENTIAL_SUFFIXES.iter().any(|run| c.contains_run(run))
            || self.credential_dirs.iter().any(|d| c.starts_with(d))
        {
            return Some(Self_(Reason::CredentialPath));
        }
        if let Some((_, name)) = CREDENTIAL_DIRS.iter().find(|(run, _)| c.contains_run(run)) {
            return Some(Self_(Reason::CredentialDir { name }));
        }
        if self.sync_roots.iter().any(|r| c.starts_with(r)) {
            return Some(Self_(Reason::SyncRoot));
        }
        if c.comps.is_empty() {
            return Some(Contains(Reason::DriveRoot));
        }
        if (paths::eq_ci(first, "Users") && c.comps.len() <= 2)
            || self.user_home.as_ref().is_some_and(|h| h.starts_with(c))
        {
            return Some(Contains(Reason::UserFolderRoot));
        }
        None
    }
}

/// `Windows.old.000` and the like (the root folder name, not a path).
pub fn is_windows_old_n(name: &str) -> bool {
    let n = WINDOWS_OLD_PREFIX.len();
    name.len() > n && name.is_char_boundary(n) && paths::eq_ci(&name[..n], WINDOWS_OLD_PREFIX)
}

/// What the scan recorded for an item that is about to be acted on.
#[derive(Debug, Clone)]
pub struct ItemSnapshot {
    pub is_dir: bool,
    pub protection: Option<Protection>,
    /// The item lies below a stopping rule folder (a Temp member, D23), where the scan matched
    /// no rules; `check_item` then looks for no rule folders inside it either.
    pub below_stop_folder: bool,
}

/// What a rule folder does to everything below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// A "안전"/"아마 안전" rule: the walk stops here (D9).
    Walk,
    /// The same, from a built-in rule: credential findings below stop here too (D12). User rules
    /// never draw that boundary, so a rule someone writes cannot hide a credential.
    Bounded,
}

/// Where the rules stop, so that `check_item` draws its boundaries where the scan drew them.
/// `files` holds the names of the files (not folders) next to `dir`, for `when`.
pub trait StopFolders {
    fn stop(&self, dir: &Path, files: &[String]) -> Option<Stop>;
}

/// No rules loaded: every finding counts.
pub struct NoStopFolders;

impl StopFolders for NoStopFolders {
    fn stop(&self, _: &Path, _: &[String]) -> Option<Stop> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Refusal {
    Protected {
        protection: Protection,
    },
    /// Every sync-root source failed and the item is inside the user folder (S7, D11).
    SyncDetectionFailed,
    /// Gone, or the item itself cannot be read.
    Missing,
    /// A file became a folder, or the other way round, since the scan.
    Changed,
}

/// Full safety re-check of one item against the disk as it is now (S3, S12). Pass a freshly
/// built context. Lists the subtree without following links or opening files (S8); the first
/// finding refuses. A folder inside that cannot be listed refuses too, as it does at selection.
pub fn check_item(
    ctx: &ProtectContext,
    path: &Path,
    snap: &ItemSnapshot,
    stops: &dyn StopFolders,
) -> Result<(), Refusal> {
    let refuse = |p| Err(Refusal::Protected { protection: p });
    if let Some(p) = &snap.protection {
        return refuse(p.clone());
    }
    let Some(c) = CanonPath::new(path) else {
        return refuse(Protection::Self_(Reason::Unresolved));
    };
    if let Some(p) = ctx.canon_protection(&c) {
        return refuse(p);
    }
    if ctx.sync_unverified(&c) {
        return Err(Refusal::SyncDetectionFailed);
    }
    // A link above the item would make a rename act on wherever it points.
    for anc in path.ancestors().skip(1).filter(|a| a.parent().is_some()) {
        let meta = fs::symlink_metadata(paths::verbatim(anc)).map_err(|_| Refusal::Missing)?;
        if meta.file_type().is_symlink() {
            return refuse(Protection::Self_(Reason::Reparse));
        }
    }
    let meta = fs::symlink_metadata(paths::verbatim(path)).map_err(|_| Refusal::Missing)?;
    match attrs::classify(meta.file_attributes(), meta.file_type().is_symlink()) {
        EntryKind::Link => return refuse(Protection::Self_(Reason::Reparse)),
        EntryKind::CloudOnly => return refuse(Protection::Self_(Reason::CloudFile)),
        kind if (kind == EntryKind::Dir) != snap.is_dir => return Err(Refusal::Changed),
        EntryKind::File => {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            return match file_protection(&name) {
                Some(r) => refuse(Protection::Self_(r)),
                None => Ok(()),
            };
        }
        EntryKind::Dir => {}
    }
    if attrs::is_cloud_only(meta.file_attributes()) {
        return refuse(Protection::Self_(Reason::CloudFile));
    }
    check_subtree(ctx, path, snap.below_stop_folder, stops)
}

fn check_subtree(
    ctx: &ProtectContext,
    root: &Path,
    below_stop: bool,
    stops: &dyn StopFolders,
) -> Result<(), Refusal> {
    let found = |r: Reason| {
        Err(Refusal::Protected {
            protection: Protection::Contains(r),
        })
    };
    // Each folder carries whether a rule folder below the item stopped the walk above it (no
    // more rule matching), and whether that was a built-in one, which bounds credential
    // findings (D12): those do not refuse the item.
    let mut stack = vec![(root.to_path_buf(), false, false)];
    while let Some((dir, stopped, bounded)) = stack.pop() {
        let counts = |r: &Reason| !(bounded && r.stops_at_rule_folder());
        let entries = match fs::read_dir(paths::verbatim(&dir)) {
            Ok(entries) => entries,
            Err(_) if dir == root => return Err(Refusal::Missing),
            Err(_) => return found(Reason::Unreadable),
        };
        let mut listed = Vec::new();
        for entry in entries {
            let Ok(entry) = entry else {
                return found(Reason::Unreadable);
            };
            let Ok(meta) = entry.metadata() else {
                return found(Reason::Unreadable);
            };
            listed.push((entry.file_name().to_string_lossy().into_owned(), meta));
        }
        // `when` looks at files only: a folder named `package.json` proves nothing.
        let files: Vec<String> = listed
            .iter()
            .filter(|(_, m)| {
                matches!(
                    attrs::classify(m.file_attributes(), m.file_type().is_symlink()),
                    EntryKind::File | EntryKind::CloudOnly
                )
            })
            .map(|(n, _)| n.clone())
            .collect();
        for (name, meta) in &listed {
            match attrs::classify(meta.file_attributes(), meta.file_type().is_symlink()) {
                EntryKind::Link => {} // removed as a link, never followed (S1)
                EntryKind::CloudOnly => return found(Reason::CloudFile),
                EntryKind::File => {
                    if let Some(r) = file_protection(name).filter(|r| counts(r)) {
                        return found(r);
                    }
                }
                EntryKind::Dir => {
                    if attrs::is_cloud_only(meta.file_attributes()) {
                        return found(Reason::CloudFile);
                    }
                    let child = dir.join(name);
                    if let Some(p) = ctx
                        .path_protection(&child)
                        .and_then(|p| p.lifted(false))
                        .filter(|p| counts(p.reason()))
                    {
                        return Err(Refusal::Protected { protection: p });
                    }
                    let here = (!stopped && !below_stop)
                        .then(|| stops.stop(&child, &files))
                        .flatten();
                    stack.push((
                        child,
                        stopped || here.is_some(),
                        bounded || here == Some(Stop::Bounded),
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn known_folder_for_test(folder: KnownFolder) -> Option<PathBuf> {
    win::known_folder(&folder)
}

mod win {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::{Path, PathBuf};
    use windows::core::HSTRING;
    use windows::Win32::Storage::FileSystem::GetLongPathNameW;

    /// Where the shell keeps a known folder now (redirected or moved included).
    pub fn known_folder(folder: &super::KnownFolder) -> Option<PathBuf> {
        use super::KnownFolder as K;
        use windows::Win32::System::Com::CoTaskMemFree;
        use windows::Win32::UI::Shell::{
            FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Music, FOLDERID_Pictures,
            FOLDERID_Videos, SHGetKnownFolderPath, KF_FLAG_DONT_VERIFY,
        };
        let id = match folder {
            K::Documents => FOLDERID_Documents,
            K::Desktop => FOLDERID_Desktop,
            K::Pictures => FOLDERID_Pictures,
            K::Videos => FOLDERID_Videos,
            K::Music => FOLDERID_Music,
        };
        unsafe {
            let p = SHGetKnownFolderPath(&id, KF_FLAG_DONT_VERIFY, None).ok()?;
            let path = p.to_string().ok().filter(|s| !s.is_empty());
            CoTaskMemFree(Some(p.0 as *const _));
            path.map(PathBuf::from)
        }
    }

    /// `None` when the path does not exist or cannot be read.
    pub fn long_name(path: &Path) -> Option<PathBuf> {
        let wide = HSTRING::from(crate::core::paths::verbatim(path).as_os_str());
        let mut buf = vec![0u16; 512];
        loop {
            let n = unsafe { GetLongPathNameW(&wide, Some(&mut buf)) } as usize;
            if n == 0 {
                return None;
            }
            if n < buf.len() {
                return Some(OsString::from_wide(&buf[..n]).into());
            }
            buf.resize(n, 0);
        }
    }

    #[cfg(test)]
    pub fn short_name(path: &Path) -> Option<PathBuf> {
        use windows::Win32::Storage::FileSystem::GetShortPathNameW;
        let wide = HSTRING::from(path.as_os_str());
        let mut buf = vec![0u16; 512];
        let n = unsafe { GetShortPathNameW(&wide, Some(&mut buf)) } as usize;
        (n > 0 && n < buf.len()).then(|| OsString::from_wide(&buf[..n]).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::syncroots::SyncRootSource;
    use crate::core::testzone::{self, write_file};
    use Protection::{Contains, Self_};

    const HOME: &str = r"C:\Users\me";
    const ENV: &[(&str, &str)] = &[
        ("SystemRoot", r"C:\Windows"),
        ("USERPROFILE", HOME),
        ("LOCALAPPDATA", r"C:\Users\me\AppData\Local"),
        ("APPDATA", r"C:\Users\me\AppData\Roaming"),
    ];

    fn ctx_with(env: &'static [(&'static str, &'static str)], sync: &[&str]) -> ProtectContext {
        let det = SyncRootDetection::with_roots(sync.iter().map(PathBuf::from).collect());
        ProtectContext::new(
            |k| {
                env.iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(k))
                    .map(|(_, v)| PathBuf::from(v))
            },
            &det,
        )
    }

    fn home_env(k: &str) -> Option<PathBuf> {
        (k == "USERPROFILE").then(|| PathBuf::from(HOME))
    }

    fn ctx() -> ProtectContext {
        ctx_with(ENV, &[])
    }

    fn prot(ctx: &ProtectContext, path: &str) -> Option<Protection> {
        ctx.path_protection(Path::new(path))
    }

    #[test]
    fn protect_system_paths_survive_spelling_variants() {
        let ctx = ctx();
        let names = [
            "Windows",
            "Windows.old",
            "Program Files",
            "Program Files (x86)",
            "ProgramData",
            "System Volume Information",
            "$Recycle.Bin",
            "Recovery",
            "$WinREAgent",
            "PerfLogs",
            "pagefile.sys",
            "hiberfil.sys",
            "swapfile.sys",
        ];
        for n in names {
            let up = n.to_uppercase();
            let low = n.to_lowercase();
            for p in [
                format!(r"C:\{n}"),
                format!(r"c:\{up}"),
                format!(r"C:\{low}\"),
                format!(r"C:\{n}\\"),
                format!(r"\\?\C:\{n}"),
                format!(r"\\?\c:\{up}\"),
                format!("C:/{n}"),
                format!(r"C:\{n}."),
                format!(r"D:\{n}"),
            ] {
                assert_eq!(prot(&ctx, &p), Some(Self_(Reason::System)), "{p}");
            }
            if !n.ends_with(".sys") {
                for p in [format!(r"C:\{n}\sub\deeper"), format!(r"\\?\C:\{up}\Sub\")] {
                    assert_eq!(prot(&ctx, &p), Some(Self_(Reason::System)), "{p}");
                }
            }
        }
        // System files are protected at the root only; system folders only at the root.
        assert_eq!(prot(&ctx, r"C:\work\pagefile.sys"), None);
        assert_eq!(prot(&ctx, r"C:\work\Windows"), None);
        assert_eq!(prot(&ctx, r"C:\Windows2"), None);
    }

    #[test]
    fn audit_13_system_root_ignores_the_environment() {
        let det = SyncRootDetection::with_roots(Vec::new());
        let fake = |k: &str| match k {
            "SystemRoot" => Some(PathBuf::from(r"D:\fake-windows")),
            "USERPROFILE" => Some(PathBuf::from(HOME)),
            _ => None,
        };
        let ctx = ProtectContext::from_shell(fake, &det);
        let real = crate::core::paths::windows_dir().unwrap();
        assert_eq!(ctx.system_root(), CanonPath::new(&real).as_ref());
        assert_eq!(ctx.path_protection(Path::new(r"D:\fake-windows\x")), None);
        assert_eq!(
            ctx.path_protection(&real.join("System32")),
            Some(Self_(Reason::System))
        );
    }

    #[test]
    fn protect_system_root_not_on_c() {
        let ctx = ctx_with(&[("SystemRoot", r"D:\WINNT")], &[]);
        assert_eq!(
            prot(&ctx, r"d:\winnt\System32"),
            Some(Self_(Reason::System))
        );
        assert_eq!(prot(&ctx, r"\\?\D:\WINNT\"), Some(Self_(Reason::System)));
        assert_eq!(prot(&ctx, r"D:\WINNT2"), None);
    }

    #[test]
    fn protect_quarantine_root() {
        let ctx = ctx();
        for p in [
            r"C:\ClearCache_Quarantine",
            r"c:\clearcache_quarantine\S-1-5-21\x",
        ] {
            assert_eq!(prot(&ctx, p), Some(Self_(Reason::Quarantine)), "{p}");
        }
    }

    #[test]
    fn protect_short_name_expands_before_comparing() {
        let pf = Path::new(r"C:\Program Files");
        match win::short_name(pf).filter(|s| s.as_path() != pf) {
            Some(short) => {
                assert!(short.to_string_lossy().contains('~'), "{short:?}");
                assert_eq!(CanonPath::new(&short), CanonPath::new(pf));
                assert_eq!(ctx().path_protection(&short), Some(Self_(Reason::System)));
            }
            None => eprintln!("skipped: 8.3 names are disabled on C:"),
        }

        // A sync root registered under its long name still matches its 8.3 spelling.
        let fx = testzone::fixture();
        let root = fx.path().join("Long Sync Root Folder");
        fs::create_dir_all(root.join("inner")).unwrap();
        match win::short_name(&root).filter(|s| *s != root) {
            Some(short) => {
                let det = SyncRootDetection::with_roots(vec![root.clone()]);
                let ctx = ProtectContext::new(|_| None, &det);
                assert_eq!(
                    ctx.path_protection(&short.join("inner")),
                    Some(Self_(Reason::SyncRoot))
                );
            }
            None => eprintln!("skipped: 8.3 names are disabled on the TestZone volume"),
        }
    }

    #[test]
    fn protect_unresolvable_path_is_protected() {
        let ctx = ctx();
        for p in [
            r"C:\NOSUCH~1\x",
            r"C:\work\..\Windows",
            r"C:\work\.\x",
            r"C:\work\file.txt::$DATA",
            r"C:\Windows::$INDEX_ALLOCATION",
            r"relative\path",
            r"C:relative",
            r"\\.\C:\work",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3",
            r"C:\work\...",
            "",
        ] {
            assert_eq!(prot(&ctx, p), Some(Self_(Reason::Unresolved)), "{p:?}");
        }
    }

    #[test]
    fn protect_roots_cannot_go_whole() {
        let ctx = ctx();
        for p in [r"C:\", "C:", r"\\?\C:\", r"d:\"] {
            assert_eq!(prot(&ctx, p), Some(Contains(Reason::DriveRoot)), "{p}");
        }
        for p in [
            r"C:\Users",
            r"C:\Users\",
            r"c:\users\someone",
            HOME,
            r"\\?\C:\USERS\ME\",
        ] {
            assert_eq!(prot(&ctx, p), Some(Contains(Reason::UserFolderRoot)), "{p}");
        }
        // A profile outside C:\Users: the folder and its ancestors.
        let moved = ctx_with(&[("USERPROFILE", r"D:\Profiles\me")], &[]);
        for p in [r"D:\Profiles\me", r"D:\Profiles"] {
            assert_eq!(
                prot(&moved, p),
                Some(Contains(Reason::UserFolderRoot)),
                "{p}"
            );
        }
        assert_eq!(prot(&moved, r"D:\Profiles\me\Documents"), None);
        assert_eq!(prot(&ctx, r"C:\Users\me\Documents"), None);
        assert_eq!(prot(&ctx, r"C:\work"), None);
    }

    #[test]
    fn protect_credential_paths_and_everything_below() {
        let ctx = ctx();
        for (p, name) in [
            (r"C:\Users\me\.ssh", ".ssh"),
            (r"C:\Users\me\.SSH\keys", ".ssh"),
            (r"C:\Users\me\.aws", ".aws"),
            (r"C:\Users\me\.gnupg\private-keys-v1.d", ".gnupg"),
            (r"C:\Users\me\.azure", ".azure"),
            (r"C:\Users\me\.kube\cache", ".kube"),
            (r"D:\backup\.ssh", ".ssh"),
            (r"C:\work\proj\node_modules\pkg\test\.ssh", ".ssh"),
        ] {
            assert_eq!(
                prot(&ctx, p),
                Some(Self_(Reason::CredentialDir { name })),
                "{p}"
            );
        }
        for p in [
            // A location match wins over a name match, so it still crosses rule folders.
            r"C:\Users\me\AppData\Local\Packages\App\LocalState\.ssh",
            r"C:\Users\me\AppData\Local\Google\Chrome\User Data",
            r"C:\Users\me\AppData\Local\Google\Chrome\User Data\Default\Cache",
            r"C:\Users\me\AppData\Local\Microsoft\Edge\User Data\Default",
            r"C:\Users\me\AppData\Roaming\Mozilla\Firefox\Profiles\abc.default",
            r"C:\Users\me\AppData\Local\Packages",
            r"C:\Users\me\AppData\Local\Packages\App_8wekyb3d8bbwe\LocalCache",
            r"C:\Users\me\AppData\Local\Packages\App_8wekyb3d8bbwe\TempState",
            r"C:\Users\me\AppData\Roaming\Microsoft\Protect",
            r"C:\Users\me\AppData\Roaming\Microsoft\Credentials",
            r"C:\Users\me\AppData\Roaming\Microsoft\Crypto\RSA",
            r"C:\Users\me\AppData\Local\Microsoft\Credentials",
            r"C:\Users\other\AppData\Local\Packages\x",
            r"\\?\c:\users\me\appdata\local\packages\",
        ] {
            assert_eq!(prot(&ctx, p), Some(Self_(Reason::CredentialPath)), "{p}");
        }
        // Redirected AppData is still covered through the environment.
        let redirected = ctx_with(
            &[("LOCALAPPDATA", r"E:\Local"), ("APPDATA", r"E:\Roaming")],
            &[],
        );
        for p in [
            r"E:\Local\Packages\x",
            r"E:\Local\Microsoft\Credentials",
            r"E:\Roaming\Microsoft\Protect\S-1-5",
            r"E:\Roaming\Microsoft\Crypto",
        ] {
            assert_eq!(
                prot(&redirected, p),
                Some(Self_(Reason::CredentialPath)),
                "{p}"
            );
        }
        // Names that only look alike.
        for p in [
            r"C:\work\packages",
            r"C:\work\ssh",
            r"C:\work\.ssh2",
            r"C:\Users\me\AppData\Local\Google",
            r"C:\Users\me\AppData\Local\Google\Chrome",
            r"C:\Users\me\AppData\Local\Microsoft",
            r"C:\Users\me\AppData\Local\npm-cache",
        ] {
            assert_eq!(prot(&ctx, p), None, "{p}");
        }
    }

    #[test]
    fn protect_credential_files_table() {
        for name in [
            "a.kdbx",
            "A.KDBX",
            "old.kdb",
            "x.psafe3",
            "putty.ppk",
            "cert.pfx",
            "Cert.P12",
            "wallet.dat",
            "WALLET.DAT",
        ] {
            assert!(
                matches!(file_protection(name), Some(Reason::CredentialFile { .. })),
                "{name}"
            );
        }
        assert_eq!(
            file_protection("db.KDBX"),
            Some(Reason::CredentialFile { name: ".kdbx" })
        );
        for name in [
            "server.pem",
            "tls.key",
            "ca.crt",
            "ca.cer",
            "pub.gpg",
            "sig.asc",
            "release.jks",
            "debug.keystore",
            "id_rsa",
            "mail.pst",
            "mail.ost",
            "my-wallet.dat",
            "notes.txt",
        ] {
            assert_eq!(file_protection(name), None, "{name}");
        }
        for name in ["ext4.vhdx", "disk.VHD", "vm.vmdk"] {
            assert_eq!(file_protection(name), Some(Reason::VirtualDisk), "{name}");
        }
        // Every table entry is covered above or by the vault folder test below.
        for m in CREDENTIAL_FILES {
            let probe = match m {
                CredentialMatch::Ext(e) => format!("x{e}"),
                CredentialMatch::FileName(n) => n.to_string(),
                CredentialMatch::DirExt(_) => continue,
            };
            assert!(file_protection(&probe).is_some(), "{m:?}");
        }
    }

    #[test]
    fn protect_opvault_folder_is_itself_a_credential_store() {
        let ctx = ctx();
        for p in [
            r"C:\Users\me\Dropbox\1Password.opvault",
            r"C:\Users\me\Dropbox\1Password.OPVAULT\default\band_0.js",
        ] {
            assert_eq!(
                prot(&ctx, p),
                Some(Self_(Reason::CredentialFile { name: ".opvault" })),
                "{p}"
            );
        }
        assert_eq!(prot(&ctx, r"C:\Users\me\Dropbox"), None);
    }

    #[test]
    fn s7_sync_root_and_inside_are_self_protected() {
        let ctx = ctx_with(ENV, &[r"C:\Users\me\OneDrive"]);
        for p in [
            r"C:\Users\me\OneDrive",
            r"c:\users\me\onedrive\Docs\x",
            r"\\?\C:\Users\me\OneDrive\",
        ] {
            assert_eq!(prot(&ctx, p), Some(Self_(Reason::SyncRoot)), "{p}");
        }
        assert_eq!(prot(&ctx, r"C:\Users\me\OneDrive2"), None);
    }

    #[test]
    fn s2_lifting_rules() {
        let cf = Reason::CredentialFile { name: ".pfx" };
        // `C:\work\proj\secrets\cert.pfx`: secrets is Self_, proj and work inherit Contains.
        let secrets = Self_(file_protection("cert.pfx").unwrap());
        let proj = secrets.lifted(false).unwrap();
        assert_eq!(proj, Contains(cf.clone()));
        assert_eq!(proj.lifted(false), Some(Contains(cf.clone())));
        // `proj\node_modules\pkg\test\cert.pfx`: stops at the stopping rule folder.
        let node_modules = Contains(cf.clone());
        assert_eq!(node_modules.lifted(true), None);
        // Credential folders found by name stop at the same boundary.
        let ssh = Reason::CredentialDir { name: ".ssh" };
        assert_eq!(
            Self_(ssh.clone()).lifted(false),
            Some(Contains(ssh.clone()))
        );
        assert_eq!(Contains(ssh.clone()).lifted(true), None);
        // Other protection targets cross rule folders.
        for r in [
            Reason::System,
            Reason::Quarantine,
            Reason::CredentialPath,
            Reason::SyncRoot,
            Reason::CloudFile,
            Reason::VirtualDisk,
            Reason::Unresolved,
            Reason::Unreadable,
        ] {
            assert_eq!(Self_(r.clone()).lifted(true), Some(Contains(r)));
        }
        // Links (S9) and whole-root blocks are not protection targets.
        for r in [Reason::Reparse, Reason::DriveRoot, Reason::UserFolderRoot] {
            assert_eq!(Self_(r.clone()).lifted(false), None);
            assert_eq!(Contains(r).lifted(false), None);
        }
    }

    #[test]
    fn protect_merge_prefers_self() {
        let s = Some(Self_(Reason::CredentialPath));
        let c = Some(Contains(Reason::VirtualDisk));
        assert_eq!(Protection::merge(c.clone(), s.clone()), s);
        assert_eq!(Protection::merge(s.clone(), c.clone()), s);
        assert_eq!(Protection::merge(None, c.clone()), c);
        assert_eq!(Protection::merge(c.clone(), None), c);
        assert_eq!(
            Protection::merge(c.clone(), Some(Contains(Reason::SyncRoot))),
            c
        );
    }

    #[test]
    fn protect_serializes_scope_and_reason() {
        let v = serde_json::to_value(Self_(Reason::CredentialFile { name: ".kdbx" })).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"scope": "self", "reason": {"kind": "credential_file", "name": ".kdbx"}})
        );
        let v = serde_json::to_value(Contains(Reason::UserFolderRoot)).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"scope": "contains", "reason": {"kind": "user_folder_root"}})
        );
    }

    // --- check_item (S3, S12) against fixtures under the TestZone ---

    fn dir_snap() -> ItemSnapshot {
        ItemSnapshot {
            is_dir: true,
            protection: None,
            below_stop_folder: false,
        }
    }

    fn check(ctx: &ProtectContext, path: &Path, snap: &ItemSnapshot) -> Result<(), Refusal> {
        check_item(ctx, path, snap, &NoStopFolders)
    }

    /// Stand-in for the built-in rules: `node_modules` next to a `package.json` file stops the
    /// walk and bounds credential findings.
    struct NodeModules;

    impl StopFolders for NodeModules {
        fn stop(&self, dir: &Path, files: &[String]) -> Option<Stop> {
            (dir.file_name()
                .is_some_and(|n| n.eq_ignore_ascii_case("node_modules"))
                && files.iter().any(|n| n.eq_ignore_ascii_case("package.json")))
            .then_some(Stop::Bounded)
        }
    }

    fn refused(r: Result<(), Refusal>) -> Option<Protection> {
        match r {
            Err(Refusal::Protected { protection }) => Some(protection),
            other => panic!("expected a protection refusal, got {other:?}"),
        }
    }

    #[test]
    fn s3_check_item_passes_plain_folder_and_file() {
        let fx = testzone::fixture();
        let item = fx.path().join("proj").join("node_modules");
        write_file(&item.join("pkg").join("index.js"), 1024);
        write_file(&item.join("pkg").join("server.pem"), 1024);
        assert_eq!(check(&ctx(), &item, &dir_snap()), Ok(()));
        let file = item.join("pkg").join("index.js");
        let snap = ItemSnapshot {
            is_dir: false,
            protection: None,
            below_stop_folder: false,
        };
        assert_eq!(check(&ctx(), &file, &snap), Ok(()));
    }

    #[test]
    fn s3_check_item_refuses_what_the_scan_already_protected() {
        let fx = testzone::fixture();
        let snap = ItemSnapshot {
            is_dir: true,
            protection: Some(Contains(Reason::SyncRoot)),
            below_stop_folder: false,
        };
        assert_eq!(
            refused(check(&ctx(), fx.path(), &snap)),
            Some(Contains(Reason::SyncRoot))
        );
    }

    #[test]
    fn s3_check_item_refuses_protected_paths() {
        let ctx = ctx();
        for p in [r"C:\Windows\Temp", r"C:\", r"C:\Users", r"C:\NOSUCH~1"] {
            assert!(
                matches!(
                    check(&ctx, Path::new(p), &dir_snap()),
                    Err(Refusal::Protected { .. })
                ),
                "{p}"
            );
        }
    }

    #[test]
    fn s3_check_item_refuses_missing_and_changed() {
        let fx = testzone::fixture();
        let gone = fx.path().join("gone");
        assert_eq!(check(&ctx(), &gone, &dir_snap()), Err(Refusal::Missing));
        let now_file = fx.path().join("was-a-folder");
        write_file(&now_file, 10);
        assert_eq!(check(&ctx(), &now_file, &dir_snap()), Err(Refusal::Changed));
        let now_dir = fx.path().join("was-a-file");
        fs::create_dir_all(&now_dir).unwrap();
        let snap = ItemSnapshot {
            is_dir: false,
            protection: None,
            below_stop_folder: false,
        };
        assert_eq!(check(&ctx(), &now_dir, &snap), Err(Refusal::Changed));
    }

    #[test]
    fn s9_check_item_refuses_folder_turned_into_junction() {
        let fx = testzone::fixture();
        let target = fx.path().join("elsewhere");
        fs::create_dir_all(&target).unwrap();
        let item = fx.path().join("cache");
        fs::create_dir_all(&item).unwrap();
        assert_eq!(check(&ctx(), &item, &dir_snap()), Ok(()));
        fs::remove_dir(&item).unwrap();
        testzone::junction(&item, &target);
        assert_eq!(
            refused(check(&ctx(), &item, &dir_snap())),
            Some(Self_(Reason::Reparse))
        );
    }

    #[test]
    fn s9_check_item_refuses_link_above_the_item() {
        let fx = testzone::fixture();
        let real = fx.path().join("real");
        fs::create_dir_all(real.join("cache")).unwrap();
        let link = fx.path().join("proj");
        testzone::junction(&link, &real);
        assert_eq!(
            refused(check(&ctx(), &link.join("cache"), &dir_snap())),
            Some(Self_(Reason::Reparse))
        );
    }

    #[test]
    fn s1_check_item_does_not_follow_links_inside() {
        let fx = testzone::fixture();
        let secret = fx.path().join("secret");
        write_file(&secret.join("db.kdbx"), 1024);
        let item = fx.path().join("cache");
        fs::create_dir_all(&item).unwrap();
        testzone::junction(&item.join("link"), &secret);
        assert_eq!(check(&ctx(), &item, &dir_snap()), Ok(()));
    }

    #[test]
    fn s7_check_item_refuses_new_sync_root() {
        let fx = testzone::fixture();
        let item = fx.path().join("proj");
        fs::create_dir_all(item.join("sub").join("synced")).unwrap();
        let root = fx.path().to_string_lossy().into_owned();
        // The item itself is now inside a sync root.
        let around = ctx_with(ENV, &[]);
        assert_eq!(check(&around, &item, &dir_snap()), Ok(()));
        let det = SyncRootDetection::with_roots(vec![PathBuf::from(&root)]);
        let around = ProtectContext::new(home_env, &det);
        assert_eq!(
            refused(check(&around, &item, &dir_snap())),
            Some(Self_(Reason::SyncRoot))
        );
        // A sync root registered somewhere inside the item.
        let det = SyncRootDetection::with_roots(vec![item.join("sub").join("synced")]);
        let inside = ProtectContext::new(home_env, &det);
        assert_eq!(
            refused(check(&inside, &item, &dir_snap())),
            Some(Contains(Reason::SyncRoot))
        );
    }

    #[test]
    fn s7_check_item_refuses_user_folder_when_sync_detection_failed() {
        struct Failing;
        impl SyncRootSource for Failing {
            fn name(&self) -> &'static str {
                "failing"
            }
            fn read(&self) -> Result<Vec<PathBuf>, String> {
                Err("access denied".into())
            }
        }
        let det = SyncRootDetection::detect(&[Box::new(Failing) as Box<dyn SyncRootSource>]);
        assert!(det.all_failed);
        let fx = testzone::fixture();
        let home = fx.path().join("home");
        let inside = home.join("AppData").join("Local").join("npm-cache");
        let outside = fx.path().join("work");
        fs::create_dir_all(&inside).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let home_s = home.clone();
        let ctx = ProtectContext::new(move |k| (k == "USERPROFILE").then(|| home_s.clone()), &det);
        assert_eq!(
            check(&ctx, &inside, &dir_snap()),
            Err(Refusal::SyncDetectionFailed)
        );
        assert_eq!(check(&ctx, &outside, &dir_snap()), Ok(()));
    }

    #[test]
    fn s2_check_item_finds_protected_items_deep_inside() {
        let ctx = ctx();
        let cases: &[(&str, Reason)] = &[
            (r"a\b\cert.pfx", Reason::CredentialFile { name: ".pfx" }),
            (
                r"a\WALLET.DAT",
                Reason::CredentialFile { name: "wallet.dat" },
            ),
            (r"a\b\c\ext4.vhdx", Reason::VirtualDisk),
        ];
        for (rel, reason) in cases {
            let fx = testzone::fixture();
            let item = fx.path().join("proj");
            write_file(&item.join("keep.txt"), 10);
            write_file(&item.join(rel), 1024);
            assert_eq!(
                refused(check(&ctx, &item, &dir_snap())),
                Some(Contains(reason.clone())),
                "{rel}"
            );
        }
        let folders: &[(&str, Reason)] = &[
            (r"a\.ssh", Reason::CredentialDir { name: ".ssh" }),
            (r"a\Google\Chrome\User Data", Reason::CredentialPath),
            (
                r"vault.opvault",
                Reason::CredentialFile { name: ".opvault" },
            ),
        ];
        for (rel, reason) in folders {
            let fx = testzone::fixture();
            let item = fx.path().join("proj");
            fs::create_dir_all(item.join(rel)).unwrap();
            assert_eq!(
                refused(check(&ctx, &item, &dir_snap())),
                Some(Contains(reason.clone())),
                "{rel}"
            );
        }
    }

    #[test]
    fn s2_check_item_credential_in_rule_folder_blocks_that_folder_only() {
        for rel in [r"pkg\test\.ssh", r"pkg\test\db.kdbx", r"pkg\.AWS"] {
            let fx = testzone::fixture();
            let proj = fx.path().join("proj");
            write_file(&proj.join("package.json"), 10);
            let nm = proj.join("node_modules");
            if rel.ends_with(".kdbx") {
                write_file(&nm.join(rel), 1024);
            } else {
                fs::create_dir_all(nm.join(rel)).unwrap();
            }
            // The project stays selectable, as it does in the scan (D12).
            assert_eq!(check_item(&ctx(), &proj, &dir_snap(), &NodeModules), Ok(()));
            // The rule folder itself does not.
            assert!(
                refused(check_item(&ctx(), &nm, &dir_snap(), &NodeModules))
                    .is_some_and(|p| !p.is_self() && p.reason().stops_at_rule_folder()),
                "{rel}"
            );
            // Not a rule folder (no rules known): the finding reaches the project.
            assert!(
                refused(check(&ctx(), &proj, &dir_snap())).is_some(),
                "{rel}"
            );
        }
        // Without `package.json` next to it, `node_modules` is no rule folder.
        let fx = testzone::fixture();
        let proj = fx.path().join("proj");
        fs::create_dir_all(proj.join(r"node_modules\pkg\.ssh")).unwrap();
        assert_eq!(
            refused(check_item(&ctx(), &proj, &dir_snap(), &NodeModules)),
            Some(Contains(Reason::CredentialDir { name: ".ssh" }))
        );
        // Targets that cross rule folders still block the project.
        let fx = testzone::fixture();
        let proj = fx.path().join("proj");
        write_file(&proj.join("package.json"), 10);
        write_file(&proj.join(r"node_modules\pkg\disk.vhdx"), 1024);
        assert_eq!(
            refused(check_item(&ctx(), &proj, &dir_snap(), &NodeModules)),
            Some(Contains(Reason::VirtualDisk))
        );
    }

    #[test]
    fn s2_check_item_below_stop_folder_matches_no_rules() {
        // A Temp member (D23): the scan matched no rules inside it, so neither does the check.
        let fx = testzone::fixture();
        let member = fx.path().join("Temp").join("extract");
        write_file(&member.join("package.json"), 10);
        write_file(&member.join(r"node_modules\a.kdbx"), 1024);
        let snap = ItemSnapshot {
            below_stop_folder: true,
            ..dir_snap()
        };
        assert_eq!(
            refused(check_item(&ctx(), &member, &snap, &NodeModules)),
            Some(Contains(Reason::CredentialFile { name: ".kdbx" }))
        );
        assert_eq!(
            check_item(&ctx(), &member, &dir_snap(), &NodeModules),
            Ok(())
        );
    }

    #[test]
    fn s2_check_item_refuses_unreadable_subfolder() {
        let fx = testzone::fixture();
        let item = fx.path().join("proj");
        let locked = item.join("a").join("locked");
        write_file(&locked.join("x.txt"), 10);
        let _deny = testzone::deny_list(&locked);
        assert_eq!(
            refused(check(&ctx(), &item, &dir_snap())),
            Some(Contains(Reason::Unreadable))
        );
        // Inside a rule folder it still blocks the project: it is not a name-bounded finding.
        let fx2 = testzone::fixture();
        let item = fx2.path().join("proj");
        write_file(&item.join("package.json"), 10);
        let locked_nm = item.join("node_modules").join("pkg");
        write_file(&locked_nm.join("index.js"), 10);
        let _deny_nm = testzone::deny_list(&locked_nm);
        assert_eq!(
            refused(check_item(&ctx(), &item, &dir_snap(), &NodeModules)),
            Some(Contains(Reason::Unreadable))
        );
        // The unreadable folder itself cannot be listed at all.
        assert_eq!(
            check(&ctx(), &locked_nm, &dir_snap()),
            Err(Refusal::Missing)
        );
    }

    #[test]
    fn s11_check_item_refuses_virtual_disk_file_itself() {
        let fx = testzone::fixture();
        let disk = fx.path().join("ext4.vhdx");
        write_file(&disk, 1024);
        let snap = ItemSnapshot {
            is_dir: false,
            protection: None,
            below_stop_folder: false,
        };
        assert_eq!(
            refused(check(&ctx(), &disk, &snap)),
            Some(Self_(Reason::VirtualDisk))
        );
    }
}
