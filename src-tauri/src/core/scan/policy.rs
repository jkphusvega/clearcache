//! `DirPolicy`: what the walker does with a directory. M2 maps system items for drive scans;
//! M3 rule matching plugs in here.

use std::path::{Path, PathBuf};

use crate::core::paths;

pub const QUARANTINE_DIR: &str = "ClearCache_Quarantine";

/// Tags carried by system items and everything below them.
pub const TAG_SYSTEM: &str = "system";
pub const TAG_SYSTEM_APPS: &str = "system_apps";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirPolicy {
    Descend,
    /// Shown as a node with no size ("측정하지 않음").
    Unmeasured {
        tag: &'static str,
    },
    /// Not traversed and not shown (quarantine).
    Skip,
    /// Only the listed relative sub-paths are measured; everything else folds into "기타 Windows".
    MeasureChildrenOnly {
        allow: Vec<&'static str>,
    },
}

/// Windows sub-folders measured in M2 (relative to `%SystemRoot%`).
pub const WINDOWS_MEASURED: &[&str] = &[
    "WinSxS",
    r"SoftwareDistribution\Download",
    "Installer",
    "Temp",
    "Minidump",
    "LiveKernelReports",
];

const ROOT_UNMEASURED: &[&str] = &[
    "ProgramData",
    "System Volume Information",
    "$Recycle.Bin",
    "Recovery",
    "$WinREAgent",
    "PerfLogs",
];

const ROOT_SYSTEM_FILES: &[&str] = &["hiberfil.sys", "pagefile.sys", "swapfile.sys"];

#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// Root of the scan when it is a whole drive; system mapping applies only then.
    pub drive_root: Option<PathBuf>,
    pub system_root: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirDecision {
    pub policy: DirPolicy,
    /// Tag for this node (inherited by descendants unless they get their own).
    pub tag: Option<&'static str>,
    /// Mapped system items are kept in the tree regardless of the size threshold.
    pub pinned: bool,
}

impl DirDecision {
    fn descend() -> Self {
        Self {
            policy: DirPolicy::Descend,
            tag: None,
            pinned: false,
        }
    }
}

impl PolicyContext {
    /// Decision for directory `path`, whose parent was decided with `parent_allow`
    /// (`Some` if the parent was `MeasureChildrenOnly`).
    pub fn decide(
        &self,
        path: &Path,
        name: &str,
        parent_allow: Option<&[&'static str]>,
    ) -> DirDecision {
        let lname = name.to_lowercase();

        if let Some(allow) = parent_allow {
            // Inside a MeasureChildrenOnly parent: only allowed children are measured.
            if allow.iter().any(|a| a.to_lowercase() == lname) {
                return DirDecision {
                    policy: DirPolicy::Descend,
                    tag: Some(TAG_SYSTEM),
                    pinned: true,
                };
            }
            // `SoftwareDistribution\Download`: the head is itself measured-children-only.
            let nested: Vec<&'static str> = allow
                .iter()
                .filter_map(|a| {
                    a.split_once('\\')
                        .filter(|(h, _)| h.to_lowercase() == lname)
                        .map(|(_, r)| r)
                })
                .collect();
            if !nested.is_empty() {
                return DirDecision {
                    policy: DirPolicy::MeasureChildrenOnly { allow: nested },
                    tag: Some(TAG_SYSTEM),
                    pinned: true,
                };
            }
            return DirDecision {
                policy: DirPolicy::Unmeasured { tag: TAG_SYSTEM },
                tag: Some(TAG_SYSTEM),
                pinned: false,
            };
        }

        if self
            .system_root
            .as_deref()
            .is_some_and(|sr| paths::same_path(path, sr))
        {
            return DirDecision {
                policy: DirPolicy::MeasureChildrenOnly {
                    allow: WINDOWS_MEASURED.to_vec(),
                },
                tag: Some(TAG_SYSTEM),
                pinned: true,
            };
        }

        let Some(drive_root) = &self.drive_root else {
            return DirDecision::descend();
        };
        let at_root = path
            .parent()
            .is_some_and(|p| paths::same_path(p, drive_root));
        if !at_root {
            return DirDecision::descend();
        }
        if lname == QUARANTINE_DIR.to_lowercase() {
            return DirDecision {
                policy: DirPolicy::Skip,
                tag: None,
                pinned: false,
            };
        }
        if lname == "program files" || lname == "program files (x86)" {
            return DirDecision {
                policy: DirPolicy::Descend,
                tag: Some(TAG_SYSTEM_APPS),
                pinned: true,
            };
        }
        if lname == "windows.old" {
            return DirDecision {
                policy: DirPolicy::Descend,
                tag: Some(TAG_SYSTEM),
                pinned: true,
            };
        }
        if ROOT_UNMEASURED.iter().any(|n| n.to_lowercase() == lname) {
            return DirDecision {
                policy: DirPolicy::Unmeasured { tag: TAG_SYSTEM },
                tag: Some(TAG_SYSTEM),
                pinned: true,
            };
        }
        DirDecision::descend()
    }

    /// Files shown as their own pinned node: root `*.sys` files and `%SystemRoot%\MEMORY.DMP`.
    pub fn is_system_file(&self, dir: &Path, name: &str) -> bool {
        let lname = name.to_lowercase();
        if let Some(dr) = &self.drive_root {
            if paths::same_path(dir, dr) && ROOT_SYSTEM_FILES.contains(&lname.as_str()) {
                return true;
            }
        }
        lname == "memory.dmp"
            && self
                .system_root
                .as_deref()
                .is_some_and(|sr| paths::same_path(dir, sr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive_ctx() -> PolicyContext {
        PolicyContext {
            drive_root: Some(PathBuf::from(r"C:\")),
            system_root: Some(PathBuf::from(r"C:\Windows")),
        }
    }

    fn decide(ctx: &PolicyContext, path: &str) -> DirDecision {
        let p = Path::new(path);
        ctx.decide(p, &p.file_name().unwrap().to_string_lossy(), None)
    }

    #[test]
    fn policy_maps_root_system_items() {
        let ctx = drive_ctx();
        let pf = decide(&ctx, r"C:\Program Files");
        assert_eq!(pf.policy, DirPolicy::Descend);
        assert_eq!(pf.tag, Some(TAG_SYSTEM_APPS));
        assert!(pf.pinned);
        assert_eq!(
            decide(&ctx, r"C:\Program Files (x86)").tag,
            Some(TAG_SYSTEM_APPS)
        );
        assert_eq!(decide(&ctx, r"C:\Windows.old").policy, DirPolicy::Descend);
        for n in ROOT_UNMEASURED {
            assert!(
                matches!(
                    decide(&ctx, &format!(r"C:\{n}")).policy,
                    DirPolicy::Unmeasured { .. }
                ),
                "{n}"
            );
        }
        assert_eq!(
            decide(&ctx, r"C:\ClearCache_Quarantine").policy,
            DirPolicy::Skip
        );
        assert_eq!(decide(&ctx, r"C:\Users").policy, DirPolicy::Descend);
        // Only at the drive root.
        assert_eq!(
            decide(&ctx, r"C:\Users\ProgramData").policy,
            DirPolicy::Descend
        );
    }

    #[test]
    fn policy_is_case_insensitive() {
        let ctx = drive_ctx();
        assert_eq!(decide(&ctx, r"c:\PROGRAM FILES").tag, Some(TAG_SYSTEM_APPS));
        assert_eq!(
            decide(&ctx, r"C:\programdata").policy,
            DirPolicy::Unmeasured { tag: TAG_SYSTEM }
        );
        assert!(matches!(
            decide(&ctx, r"c:\WINDOWS").policy,
            DirPolicy::MeasureChildrenOnly { .. }
        ));
        assert!(ctx.is_system_file(Path::new(r"C:\"), "PageFile.SYS"));
        assert!(ctx.is_system_file(Path::new(r"c:\windows"), "memory.dmp"));
        assert!(!ctx.is_system_file(Path::new(r"C:\Users"), "pagefile.sys"));
    }

    #[test]
    fn policy_windows_measures_known_children_only() {
        let ctx = drive_ctx();
        let win = decide(&ctx, r"C:\Windows");
        let DirPolicy::MeasureChildrenOnly { allow } = &win.policy else {
            panic!()
        };
        let child =
            |name: &str| ctx.decide(&Path::new(r"C:\Windows").join(name), name, Some(allow));
        assert_eq!(child("WinSxS").policy, DirPolicy::Descend);
        assert!(child("winsxs").pinned);
        assert!(matches!(
            child("System32").policy,
            DirPolicy::Unmeasured { .. }
        ));
        let sd = child("SoftwareDistribution");
        let DirPolicy::MeasureChildrenOnly { allow: sd_allow } = &sd.policy else {
            panic!("{sd:?}")
        };
        assert_eq!(sd_allow, &vec!["Download"]);
        let dl = ctx.decide(
            Path::new(r"C:\Windows\SoftwareDistribution\Download"),
            "Download",
            Some(sd_allow),
        );
        assert_eq!(dl.policy, DirPolicy::Descend);
        let other = ctx.decide(
            Path::new(r"C:\Windows\SoftwareDistribution\DataStore"),
            "DataStore",
            Some(sd_allow),
        );
        assert!(matches!(other.policy, DirPolicy::Unmeasured { .. }));
    }

    #[test]
    fn policy_system_root_not_on_c() {
        let ctx = PolicyContext {
            drive_root: Some(PathBuf::from(r"C:\")),
            system_root: Some(PathBuf::from(r"D:\WINNT")),
        };
        assert_eq!(decide(&ctx, r"C:\Windows").policy, DirPolicy::Descend);
        let d = PolicyContext {
            drive_root: Some(PathBuf::from(r"D:\")),
            system_root: Some(PathBuf::from(r"D:\WINNT")),
        };
        assert!(matches!(
            decide(&d, r"D:\WINNT").policy,
            DirPolicy::MeasureChildrenOnly { .. }
        ));
        assert!(d.is_system_file(Path::new(r"D:\WINNT"), "MEMORY.DMP"));
    }

    #[test]
    fn policy_user_home_scan_has_no_system_mapping() {
        let ctx = PolicyContext {
            drive_root: None,
            system_root: Some(PathBuf::from(r"C:\Windows")),
        };
        assert_eq!(
            decide(&ctx, r"C:\Users\me\Program Files").policy,
            DirPolicy::Descend
        );
        assert!(!ctx.is_system_file(Path::new(r"C:\Users\me"), "pagefile.sys"));
    }
}
