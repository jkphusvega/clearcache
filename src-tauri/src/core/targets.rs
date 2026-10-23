//! Scan targets: the user folder plus local fixed/removable drives.
//! The UI only ever sends a target id; `resolve` re-queries the list and maps id → path.

use serde::Serialize;
use std::path::PathBuf;

use super::paths;

const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    UserHome,
    Drive,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanTarget {
    pub id: String,
    pub kind: TargetKind,
    pub label: String,
    pub root_display: String,
    pub fs: Option<String>,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub removable: bool,
    /// Never serialized: the UI has no path to send back.
    #[serde(skip)]
    pub root: PathBuf,
}

impl ScanTarget {
    pub fn drive_letter(&self) -> Option<char> {
        paths::drive_letter(&self.root)
    }
}

/// What the Win32 probes returned for one drive letter. Filtering is a pure function of this.
#[derive(Debug, Clone)]
pub struct DriveProbe {
    pub letter: char,
    pub drive_type: u32,
    /// `None` when `GetVolumeInformationW` failed (no media, unreadable).
    pub fs: Option<String>,
    /// `QueryDosDeviceW` target, e.g. `\Device\HarddiskVolume3` or `\??\C:\dir` for `subst`.
    pub dos_device: Option<String>,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
}

pub fn drive_target(p: &DriveProbe) -> Option<ScanTarget> {
    if p.drive_type != DRIVE_FIXED && p.drive_type != DRIVE_REMOVABLE {
        return None;
    }
    let fs = p.fs.clone()?;
    if p.dos_device
        .as_deref()
        .is_some_and(|d| d.starts_with(r"\??\"))
    {
        return None; // subst virtual drive: already covered by its real drive
    }
    let root = format!("{}:\\", p.letter.to_ascii_uppercase());
    Some(ScanTarget {
        id: format!("drive:{}", p.letter.to_ascii_uppercase()),
        kind: TargetKind::Drive,
        label: format!("{}: 드라이브", p.letter.to_ascii_uppercase()),
        root_display: root.clone(),
        fs: Some(fs),
        total_bytes: p.total_bytes,
        free_bytes: p.free_bytes,
        removable: p.drive_type == DRIVE_REMOVABLE,
        root: PathBuf::from(root),
    })
}

pub fn user_home_target(home: PathBuf) -> ScanTarget {
    ScanTarget {
        id: "user_home".into(),
        kind: TargetKind::UserHome,
        label: "사용자 폴더".into(),
        root_display: home.to_string_lossy().into_owned(),
        fs: None,
        total_bytes: None,
        free_bytes: None,
        removable: false,
        root: home,
    }
}

pub fn build_targets(home: Option<PathBuf>, probes: &[DriveProbe]) -> Vec<ScanTarget> {
    home.map(user_home_target)
        .into_iter()
        .chain(probes.iter().filter_map(drive_target))
        .collect()
}

/// Maps an id from the UI to a target from a freshly built list. Unknown ids are refused.
pub fn resolve(targets: &[ScanTarget], id: &str) -> Result<ScanTarget, String> {
    targets
        .iter()
        .find(|t| t.id == id)
        .cloned()
        .ok_or_else(|| format!("알 수 없는 스캔 대상: {id}"))
}

pub fn list_scan_targets() -> Vec<ScanTarget> {
    build_targets(paths::env_path("USERPROFILE"), &win::probe_drives())
}

pub fn resolve_current(id: &str) -> Result<ScanTarget, String> {
    resolve(&list_scan_targets(), id)
}

mod win {
    use super::DriveProbe;
    use windows::core::HSTRING;
    use windows::Win32::Storage::FileSystem::{
        GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW,
        QueryDosDeviceW,
    };

    fn from_wide(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    pub fn probe_drives() -> Vec<DriveProbe> {
        let mask = unsafe { GetLogicalDrives() };
        (0..26u8)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| probe((b'A' + i) as char))
            .collect()
    }

    fn probe(letter: char) -> DriveProbe {
        let root = HSTRING::from(format!("{letter}:\\"));
        let drive_type = unsafe { GetDriveTypeW(&root) };

        let mut fs_buf = [0u16; 64];
        let fs = unsafe { GetVolumeInformationW(&root, None, None, None, None, Some(&mut fs_buf)) }
            .ok()
            .map(|_| from_wide(&fs_buf));

        let mut dev_buf = [0u16; 1024];
        let n =
            unsafe { QueryDosDeviceW(&HSTRING::from(format!("{letter}:")), Some(&mut dev_buf)) };
        let dos_device = (n > 0).then(|| from_wide(&dev_buf));

        let (mut total, mut free) = (0u64, 0u64);
        let space =
            unsafe { GetDiskFreeSpaceExW(&root, None, Some(&mut total), Some(&mut free)) }.is_ok();

        DriveProbe {
            letter,
            drive_type,
            fs,
            dos_device,
            total_bytes: space.then_some(total),
            free_bytes: space.then_some(free),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(letter: char, drive_type: u32) -> DriveProbe {
        DriveProbe {
            letter,
            drive_type,
            fs: Some("NTFS".into()),
            dos_device: Some(r"\Device\HarddiskVolume3".into()),
            total_bytes: Some(100),
            free_bytes: Some(40),
        }
    }

    #[test]
    fn targets_keep_only_fixed_and_removable() {
        let probes = [
            probe('C', DRIVE_FIXED),
            probe('D', DRIVE_REMOVABLE),
            probe('E', 4), // remote
            probe('F', 5), // cdrom
            probe('G', 6), // ramdisk
        ];
        let ids: Vec<_> = build_targets(None, &probes)
            .into_iter()
            .map(|t| t.id)
            .collect();
        assert_eq!(ids, ["drive:C", "drive:D"]);
    }

    #[test]
    fn targets_drop_unreadable_volume_and_subst() {
        let mut no_media = probe('D', DRIVE_REMOVABLE);
        no_media.fs = None;
        let mut subst = probe('S', DRIVE_FIXED);
        subst.dos_device = Some(r"\??\C:\work".into());
        assert!(drive_target(&no_media).is_none());
        assert!(drive_target(&subst).is_none());
    }

    #[test]
    fn targets_user_home_first_and_removable_flag() {
        let t = build_targets(
            Some(PathBuf::from(r"C:\Users\me")),
            &[probe('d', DRIVE_REMOVABLE)],
        );
        assert_eq!(t[0].id, "user_home");
        assert_eq!(t[1].id, "drive:D");
        assert_eq!(t[1].root, PathBuf::from(r"D:\"));
        assert!(t[1].removable);
    }

    #[test]
    fn targets_resolve_rejects_unknown_id() {
        let t = build_targets(
            Some(PathBuf::from(r"C:\Users\me")),
            &[probe('C', DRIVE_FIXED)],
        );
        assert_eq!(resolve(&t, "drive:C").unwrap().root, PathBuf::from(r"C:\"));
        assert!(resolve(&t, "drive:Z").is_err());
        assert!(resolve(&t, r"C:\Windows").is_err());
    }

    #[test]
    fn targets_root_is_not_serialized() {
        let t = user_home_target(PathBuf::from(r"C:\Users\me"));
        let json = serde_json::to_value(&t).unwrap();
        assert!(json.get("root").is_none());
        assert_eq!(json["kind"], "user_home");
    }

    #[test]
    fn targets_live_list_contains_system_drive() {
        let t = list_scan_targets();
        assert!(t.iter().any(|t| t.id == "user_home"));
        assert!(t.iter().any(|t| t.id == "drive:C"), "{t:?}");
    }
}
