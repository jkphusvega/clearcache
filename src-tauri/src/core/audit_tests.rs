//! Reproductions of the security audit (2026-11-12, 13 findings), one test per case, named
//! `audit_<finding>_…`. Threat model (SPEC 안전 규칙): user mistakes and app bugs, not an
//! attacker who can already write to the disk. Cases that need private items live next to
//! them: `paths` (10, 13), `scan::tests` (1·9, 3, 13), `protect` (13). Findings 4 and 12 are
//! M4 requirements (the plan's M4 list); nothing to reproduce yet.

use std::fs;
use std::path::{Path, PathBuf};

use crate::core::protect::{
    self, check_item, file_protection, CanonPath, ItemSnapshot, NoStopFolders, ProtectContext,
    Protection, Reason, Refusal, Stop, StopFolders,
};
use crate::core::rules::pattern::RuleMatcher;
use crate::core::rules::source::{BuiltinRules, RuleSource};
use crate::core::rules::testenv::{canon, env, rule, sib, ENV};
use crate::core::rules::{judge, Action, Category, Facts, Grade, RuleOrigin};
use crate::core::scan::syncroots::{SyncRootDetection, SyncRootSource};
use crate::core::testzone::{self, odd_dir, write_file, write_verbatim};
use Protection::{Contains, Self_};

fn ctx() -> ProtectContext {
    crate::core::rules::testenv::ctx()
}

fn builtin() -> RuleMatcher {
    RuleMatcher::new(&BuiltinRules::embedded().rules().unwrap().rules, &env)
}

fn dir() -> ItemSnapshot {
    ItemSnapshot {
        is_dir: true,
        protection: None,
        below_stop_folder: false,
    }
}

fn refusal(r: Result<(), Refusal>) -> Protection {
    match r {
        Err(Refusal::Protected { protection }) => protection,
        other => panic!("expected a protection refusal, got {other:?}"),
    }
}

fn best<'a>(m: &'a RuleMatcher, path: &str, files: &[&str]) -> Option<&'a str> {
    m.best(&canon(path), &sib(files)).map(|r| r.id.as_str())
}

// --- 1: every directory read goes through `\\?\` (PoC p1) ---

/// A folder named `evil.` is listed, but a plain read of it opens `evil`. What is inside must
/// be found, with a clean decoy `evil` next to it (p1a, p1c).
#[test]
fn audit_01_check_item_reads_odd_names() {
    for name in ["evil.", "evil ", "evil. ."] {
        for (file, want) in [
            ("db.kdbx", Reason::CredentialFile { name: ".kdbx" }),
            ("ext4.vhdx", Reason::VirtualDisk),
        ] {
            let fx = testzone::fixture();
            let item = fx.path().join("proj");
            odd_dir(&item.join(name));
            write_verbatim(&item.join(name).join(file), 1024);
            write_file(&item.join("evil").join("ok.txt"), 4);
            assert_eq!(
                refusal(check_item(&ctx(), &item, &dir(), &NoStopFolders)),
                Contains(want),
                "{name:?} {file}"
            );
        }
    }
}

/// p1b, p1d: the lone odd folder (no twin) is read too, not just refused as unreadable.
#[test]
fn audit_01_lone_odd_folder_is_read() {
    for name in ["evil.", "evil "] {
        let fx = testzone::fixture();
        let item = fx.path().join("proj");
        odd_dir(&item.join(name));
        write_verbatim(&item.join(name).join("db.kdbx"), 1);
        assert_eq!(
            refusal(check_item(&ctx(), &item, &dir(), &NoStopFolders)),
            Contains(Reason::CredentialFile { name: ".kdbx" }),
            "{name:?}"
        );
    }
}

/// p1f: the twin two levels down, hiding a `.ssh` folder.
#[test]
fn audit_01_deep_twin_hiding_ssh() {
    let fx = testzone::fixture();
    let item = fx.path().join("f");
    write_file(&item.join(r"x\evil\ok.txt"), 4);
    odd_dir(&item.join(r"x\evil.\.ssh"));
    write_verbatim(&item.join(r"x\evil.\.ssh\id_ed25519"), 1);
    assert_eq!(
        refusal(check_item(&ctx(), &item, &dir(), &NoStopFolders)),
        Contains(Reason::CredentialDir { name: ".ssh" })
    );
}

/// p1g: the item itself is the dotted twin; its own contents are checked, not the twin's.
#[test]
fn audit_01_item_that_is_the_odd_twin() {
    let fx = testzone::fixture();
    let g = fx.path().join("g");
    write_file(&g.join(r"cache\ok.txt"), 4);
    odd_dir(&g.join("cache."));
    write_verbatim(&g.join(r"cache.\db.kdbx"), 1);
    assert_eq!(
        refusal(check_item(
            &ctx(),
            &g.join("cache."),
            &dir(),
            &NoStopFolders
        )),
        Contains(Reason::CredentialFile { name: ".kdbx" })
    );
    assert_eq!(
        check_item(&ctx(), &g.join("cache"), &dir(), &NoStopFolders),
        Ok(())
    );
}

/// The same past MAX_PATH (Rust's std already prefixed long paths; kept as a regression).
#[test]
fn audit_01_check_item_reads_past_max_path() {
    let fx = testzone::fixture();
    let item = fx.path().join("proj");
    let mut deep = item.clone();
    while deep.to_string_lossy().len() < 320 {
        deep = deep.join("a-fairly-long-folder-name");
    }
    write_verbatim(&deep.join("wallet.dat"), 10);
    assert_eq!(
        refusal(check_item(&ctx(), &item, &dir(), &NoStopFolders)),
        Contains(Reason::CredentialFile { name: "wallet.dat" })
    );
}

// --- 2: credential boundary only for built-in rules; `when` needs a file ---

/// A user rule stops the walk but must not hide a credential below it.
#[test]
fn audit_02_user_rule_does_not_bound_credentials() {
    let mut cache = rule("my-cache", r"**\.cache", Grade::Safe);
    cache.source = RuleOrigin::User;
    let user = RuleMatcher::new(&[cache], &env);
    assert_eq!(
        user.stop(Path::new(r"C:\work\proj\.cache"), &[]),
        Some(Stop::Walk)
    );
    let fx = testzone::fixture();
    let proj = fx.path().join("proj");
    write_file(&proj.join(r".cache\tokens\db.kdbx"), 1024);
    assert_eq!(
        refusal(check_item(&ctx(), &proj, &dir(), &user)),
        Contains(Reason::CredentialFile { name: ".kdbx" })
    );
    // The built-in `node_modules` rule still bounds (D12).
    let fx = testzone::fixture();
    let proj = fx.path().join("proj");
    write_file(&proj.join("package.json"), 10);
    write_file(&proj.join(r"node_modules\pkg\test\db.kdbx"), 1024);
    assert_eq!(check_item(&ctx(), &proj, &dir(), &builtin()), Ok(()));
    assert_eq!(
        builtin().stop(&proj.join("node_modules"), &sib(&["package.json"])),
        Some(Stop::Bounded)
    );
}

/// A folder named `package.json` must not turn its sibling into a rule folder.
#[test]
fn audit_02_sibling_condition_needs_a_file() {
    let fx = testzone::fixture();
    let proj = fx.path().join("proj");
    fs::create_dir_all(proj.join("package.json")).unwrap();
    write_file(&proj.join(r"node_modules\x\db.kdbx"), 1024);
    assert_eq!(
        refusal(check_item(&ctx(), &proj, &dir(), &builtin())),
        Contains(Reason::CredentialFile { name: ".kdbx" })
    );
    // With a real file the rule applies and bounds the finding.
    fs::remove_dir(proj.join("package.json")).unwrap();
    write_file(&proj.join("package.json"), 10);
    assert_eq!(check_item(&ctx(), &proj, &dir(), &builtin()), Ok(()));
}

/// p2a / 2B as reported: `Cargo.toml` is a folder, `target` holds an `.aws` folder, a `.kdbx`
/// and a `.ppk`. The project is refused, and so is `target` itself.
#[test]
fn audit_02_cargo_toml_folder_does_not_make_target_a_rule_folder() {
    let fx = testzone::fixture();
    let proj = fx.path().join("proj");
    fs::create_dir_all(proj.join("Cargo.toml")).unwrap();
    write_file(&proj.join(r"target\.aws\credentials"), 10);
    write_file(&proj.join(r"target\keys.kdbx"), 10);
    write_file(&proj.join(r"target\a\id.ppk"), 10);
    let m = builtin();
    assert!(refusal(check_item(&ctx(), &proj, &dir(), &m))
        .reason()
        .is_credential());
    assert!(
        refusal(check_item(&ctx(), &proj.join("target"), &dir(), &m))
            .reason()
            .is_credential()
    );
}

/// p2b / 2A as reported: user rule `**\backup` graded "안전" over a `.kdbx` and a `.ssh`.
#[test]
fn audit_02_user_backup_rule_as_reported() {
    let mut u = rule("u", r"**\backup", Grade::Safe);
    u.source = RuleOrigin::User;
    let um = RuleMatcher::new(&[u], &env);
    let fx = testzone::fixture();
    let work = fx.path().join("work");
    write_file(&work.join(r"backup\passwords.kdbx"), 10);
    fs::create_dir_all(work.join(r"backup\.ssh")).unwrap();
    for stops in [&um as &dyn StopFolders, &NoStopFolders] {
        assert!(refusal(check_item(&ctx(), &work, &dir(), stops))
            .reason()
            .is_credential());
    }
}

// --- 3: sync-root detection fails closed ---

struct Src {
    name: &'static str,
    result: Result<Vec<PathBuf>, String>,
    authoritative: bool,
}

impl SyncRootSource for Src {
    fn name(&self) -> &'static str {
        self.name
    }
    fn read(&self) -> Result<Vec<PathBuf>, String> {
        self.result.clone()
    }
    fn authoritative(&self) -> bool {
        self.authoritative
    }
}

fn src(
    name: &'static str,
    result: Result<Vec<&str>, &str>,
    authoritative: bool,
) -> Box<dyn SyncRootSource> {
    Box::new(Src {
        name,
        result: result
            .map(|v| v.into_iter().map(PathBuf::from).collect())
            .map_err(String::from),
        authoritative,
    })
}

/// Registry sources failing and environment variables that are merely unset is not a
/// working detection.
#[test]
fn audit_03_unset_env_vars_are_not_a_success() {
    let det = SyncRootDetection::detect(&[
        src("sync_root_manager", Err("denied"), true),
        src("onedrive_accounts", Err("denied"), true),
        src("env", Ok(vec![]), false),
    ]);
    assert!(det.all_failed);
    assert!(!det.sources[2].succeeded);
    // Env variables that do name a root count.
    let det = SyncRootDetection::detect(&[
        src("sync_root_manager", Err("denied"), true),
        src("env", Ok(vec![r"C:\Users\me\OneDrive"]), false),
    ]);
    assert!(!det.all_failed && det.partial_failure);
    // An authoritative "none" is fine.
    let det = SyncRootDetection::detect(&[
        src("sync_root_manager", Ok(vec![]), true),
        src("env", Ok(vec![]), false),
    ]);
    assert!(!det.all_failed && !det.partial_failure);
}

/// p5 / 3C: a root Windows can resolve (`.`, `..`, a volume GUID path) is resolved and
/// protects what is inside it, instead of being dropped.
#[test]
fn audit_03_resolvable_roots_still_protect() {
    let guid = crate::core::paths::volume_guid(r"C:\").expect("volume GUID of C:");
    for (root, inside) in [
        (r"C:\od\.\root".to_string(), r"C:\od\root\x"),
        (r"C:\od\sub\..\root".to_string(), r"C:\od\root\x"),
        (format!(r"{guid}od"), r"C:\od\x"),
    ] {
        let det = SyncRootDetection::detect(&[src("sync_root_manager", Ok(vec![&root]), true)]);
        assert!(det.sources[0].error.is_none(), "{root}");
        assert!(!det.all_failed, "{root}");
        let ctx = ProtectContext::new(env, &det);
        assert_eq!(
            ctx.path_protection(Path::new(inside)),
            Some(Self_(Reason::SyncRoot)),
            "{root}"
        );
    }
}

/// A root that cannot be resolved fails its source instead of disappearing.
#[test]
fn audit_03_unparsable_root_fails_its_source() {
    for bad in [
        r"OneDrive",
        r"%USERPROFILE%\OneDrive",
        r"C:\NOSUCH~1\od",
        r"\\?\Volume{11111111-2222-3333-4444-555555555555}\od",
        "",
    ] {
        let det = SyncRootDetection::detect(&[src(
            "sync_root_manager",
            Ok(vec![r"C:\Users\me\OneDrive", bad]),
            true,
        )]);
        assert!(det.sources[0].error.is_some(), "{bad:?}");
        assert!(det.partial_failure && det.all_failed, "{bad:?}");
        // The good root is still honoured.
        assert!(
            det.contains(Path::new(r"C:\Users\me\OneDrive\x")),
            "{bad:?}"
        );
    }
}

/// Without `USERPROFILE` nothing can be cleared by sync detection.
#[test]
fn audit_03_missing_user_profile_refuses() {
    let det = SyncRootDetection::with_roots(Vec::new());
    let no_home = ProtectContext::new(
        |k| {
            ENV.iter()
                .filter(|(n, _)| *n != "USERPROFILE")
                .find(|(n, _)| n.eq_ignore_ascii_case(k))
                .map(|(_, v)| PathBuf::from(v))
        },
        &det,
    );
    let fx = testzone::fixture();
    let item = fx.path().join("cache");
    fs::create_dir_all(&item).unwrap();
    assert!(no_home.sync_unverified(&CanonPath::new(&item).unwrap()));
    assert_eq!(
        check_item(&no_home, &item, &dir(), &NoStopFolders),
        Err(Refusal::SyncDetectionFailed)
    );
    assert_eq!(check_item(&ctx(), &item, &dir(), &NoStopFolders), Ok(()));
}

/// p5 / 3B: every source failed and `USERPROFILE` holds `..`: no usable user folder, so the
/// block still fires (it used to pass).
#[test]
fn audit_03_user_profile_with_dotdot_refuses() {
    let det = SyncRootDetection::detect(&[src("failing", Err("access denied"), true)]);
    assert!(det.all_failed);
    let fx = testzone::fixture();
    let home = fx.path().join("home");
    let item = home.join("stuff");
    fs::create_dir_all(&item).unwrap();
    let odd_home = home.join("..").join("home");
    let ctx = ProtectContext::new(
        move |k| (k == "USERPROFILE").then(|| odd_home.clone()),
        &det,
    );
    assert_eq!(
        check_item(&ctx, &item, &dir(), &NoStopFolders),
        Err(Refusal::SyncDetectionFailed)
    );
}

// --- 5: dev-output rules are "안전" only inside a repository; app locations excluded ---

#[test]
fn audit_05_dev_output_outside_a_repo_is_likely_safe() {
    let m = builtin();
    let ctx = ctx();
    for (path, file) in [
        (r"C:\work\proj\node_modules", "package.json"),
        (r"C:\work\proj\.next", "package.json"),
        (r"C:\work\proj\target", "Cargo.toml"),
    ] {
        let c = canon(path);
        let r = m
            .best(&c, &sib(&[file]))
            .unwrap_or_else(|| panic!("{path}"));
        for (in_repo, grade) in [(true, Grade::Safe), (false, Grade::LikelySafe)] {
            let v = judge(
                &ctx,
                &Facts {
                    path: Some(&c),
                    rule: Some(r),
                    in_repo,
                    ..Facts::default()
                },
            );
            assert_eq!(v.grade, grade, "{path} in_repo={in_repo}");
            assert_eq!(v.category(), Category::CleanNow, "{path}");
        }
        // Either way the walk stops there.
        assert!(r.stop().is_some(), "{path}");
    }
}

#[test]
fn audit_05_app_locations_are_excluded() {
    let m = builtin();
    let pj = &["package.json"];
    for path in [
        r"C:\Users\me\.vscode\extensions\ms-python.python-2026.1\node_modules",
        r"C:\Users\me\.vscode-insiders\extensions\x\node_modules",
        r"C:\Users\me\.cursor\extensions\x\node_modules",
        r"C:\Users\me\.windsurf\extensions\x\node_modules",
        r"D:\Apps\Foo\resources\app\node_modules",
        r"C:\Users\me\AppData\Local\Discord\app-1.0\resources\app.asar.unpacked\node_modules",
        // p3, as reported: a Squirrel app's per-version folder.
        r"C:\Users\me\AppData\Local\Discord\app-1.0.9\modules\discord_desktop_core-1\discord_desktop_core\node_modules",
        r"C:\Users\me\AppData\Local\slack\app-4.41.105\resources\x\node_modules",
        r"C:\Users\me\AppData\Local\pnpm\global\5\node_modules",
        r"C:\Users\me\AppData\Local\Yarn\Data\global\node_modules",
        r"C:\Users\me\.bun\install\global\node_modules",
        r"C:\Users\me\scoop\apps\nodejs\current\node_modules",
        r"C:\Users\me\scoop\apps\app\1.0\resources\app\node_modules",
        r"D:\Tools\PortableApp\resources\app\node_modules",
    ] {
        assert_eq!(best(&m, path, pj), None, "{path}");
    }
    // A project that happens to sit in a folder named like a Squirrel version, but not
    // directly under an app folder in `%LOCALAPPDATA%`, still matches.
    for path in [
        r"C:\work\app-2\node_modules",
        r"C:\Users\me\AppData\Local\Discord\application\node_modules",
        r"C:\Users\me\AppData\Local\app-1.0\node_modules",
    ] {
        assert_eq!(best(&m, path, pj), Some("node-modules"), "{path}");
    }
    // Not too wide: a project folder called `app` or `resources` alone still matches.
    for path in [
        r"C:\work\app\node_modules",
        r"C:\work\resources\node_modules",
        r"C:\Users\me\code\vscode-ext\node_modules",
    ] {
        assert_eq!(best(&m, path, pj), Some("node-modules"), "{path}");
    }
}

// --- 6·7·8: more credential stores, virtual disks and root folders ---

#[test]
fn audit_06_more_browser_and_app_profiles() {
    let ctx = ctx();
    for path in [
        r"C:\Users\me\AppData\Local\Naver\Naver Whale\User Data",
        r"C:\Users\me\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default",
        r"C:\Users\me\AppData\Local\Microsoft\Edge Beta\User Data",
        r"C:\Users\me\AppData\Local\Microsoft\Edge Dev\User Data",
        r"C:\Users\me\AppData\Local\Microsoft\Edge SxS\User Data",
        r"C:\Users\me\AppData\Local\Google\Chrome Beta\User Data",
        r"C:\Users\me\AppData\Local\Google\Chrome SxS\User Data",
        r"C:\Users\me\AppData\Local\Vivaldi\User Data",
        r"C:\Users\me\AppData\Roaming\Opera Software\Opera Stable",
        r"C:\Users\me\AppData\Roaming\Opera Software\Opera GX Stable",
        r"C:\Users\me\AppData\Roaming\Thunderbird\Profiles\x.default",
        r"C:\Users\me\AppData\Roaming\Thunderbird\Profiles",
        r"C:\Users\me\AppData\Roaming\gnupg",
        r"C:\Users\me\AppData\Roaming\gnupg\private-keys-v1.d",
        r"C:\Users\me\AppData\Local\Microsoft\Vault",
        r"C:\Users\me\AppData\Roaming\Microsoft\Vault\x",
        r"C:\Users\me\AppData\Roaming\gcloud",
        r"C:\Users\me\AppData\Roaming\Bitwarden",
        r"C:\Users\me\AppData\Local\1Password\data",
    ] {
        assert_eq!(
            ctx.path_protection(Path::new(path)),
            Some(Self_(Reason::CredentialPath)),
            "{path}"
        );
    }
    for (path, name) in [
        (r"C:\Users\me\.docker", ".docker"),
        (r"C:\Users\me\.config\gcloud", r".config\gcloud"),
        (
            r"D:\backup\.config\gcloud\legacy_credentials",
            r".config\gcloud",
        ),
    ] {
        assert_eq!(
            ctx.path_protection(Path::new(path)),
            Some(Self_(Reason::CredentialDir { name })),
            "{path}"
        );
    }
    assert_eq!(ctx.path_protection(Path::new(r"C:\Users\me\.config")), None);
}

#[test]
fn audit_07_more_virtual_disks() {
    for name in [
        "ext4.vhdx",
        "snap.avhdx",
        "shared.vhds",
        "vm.vdi",
        "disk.QCOW2",
        "old.vhd",
        "x.vmdk",
    ] {
        assert_eq!(file_protection(name), Some(Reason::VirtualDisk), "{name}");
    }
    assert_eq!(file_protection("notes.vhdx.txt"), None);
}

// --- 9: credential and disk file names with Win32-stripped endings or backup suffixes ---

#[test]
fn audit_09_file_name_variants() {
    for (name, want) in [
        ("db.kdbx.", Reason::CredentialFile { name: ".kdbx" }),
        ("wallet.dat ", Reason::CredentialFile { name: "wallet.dat" }),
        ("ext4.vhdx.", Reason::VirtualDisk),
        ("db.kdbx. .", Reason::CredentialFile { name: ".kdbx" }),
        (
            "passwords.kdbx.bak",
            Reason::CredentialFile { name: ".kdbx" },
        ),
        (
            "passwords.kdbx.OLD",
            Reason::CredentialFile { name: ".kdbx" },
        ),
        ("cert.pfx.orig", Reason::CredentialFile { name: ".pfx" }),
        ("db.kdbx.tmp", Reason::CredentialFile { name: ".kdbx" }),
        (
            "wallet.dat.backup",
            Reason::CredentialFile { name: "wallet.dat" },
        ),
        ("disk.vhdx.bak", Reason::VirtualDisk),
    ] {
        assert_eq!(file_protection(name), Some(want), "{name:?}");
    }
    for name in [
        "kdbx.bak",
        "notes.bak",
        "db.kdbx.bak.txt",
        "my-wallet.dat.bak",
    ] {
        assert_eq!(file_protection(name), None, "{name:?}");
    }
}

/// p1e: a folder holding only such names is refused by `check_item`.
#[test]
fn audit_09_check_item_finds_odd_file_names() {
    for name in [
        "db.kdbx.",
        "wallet.dat ",
        "ext4.vhdx.",
        "passwords.kdbx.bak",
    ] {
        let fx = testzone::fixture();
        let e = fx.path().join("e");
        write_verbatim(&e.join(name), 1);
        assert!(
            check_item(&ctx(), &e, &dir(), &NoStopFolders).is_err(),
            "{name:?}"
        );
    }
}

#[test]
fn audit_08_more_root_folders() {
    let ctx = ctx();
    let m = builtin();
    for (path, action) in [
        (r"C:\Boot", Action::ExplainOnly),
        (r"C:\EFI\Microsoft", Action::ExplainOnly),
        (r"C:\Config.Msi", Action::ExplainOnly),
        (r"C:\$WINDOWS.~BT", Action::ExplainOnly),
        (r"C:\$Windows.~WS\Sources", Action::ExplainOnly),
        (r"C:\Windows.old", Action::OfficialTool),
        (r"C:\Windows.old.000", Action::OfficialTool),
        (r"C:\WINDOWS.OLD.001\Users", Action::OfficialTool),
    ] {
        assert_eq!(
            ctx.path_protection(Path::new(path)),
            Some(Self_(Reason::System)),
            "{path}"
        );
        let c = canon(path);
        let v = judge(
            &ctx,
            &Facts {
                path: Some(&c),
                protection: ctx.path_protection(Path::new(path)),
                rule: m.best(&c, &[]),
                ..Facts::default()
            },
        );
        assert_eq!(v.action, action, "{path}");
    }
    // `~` in a real name is not an 8.3 alias, so it is not looked up (the path need not exist).
    assert!(CanonPath::new(Path::new(r"C:\$WINDOWS.~BT\x")).is_some());
    assert!(CanonPath::new(Path::new(r"C:\a~b\c")).is_some());
    assert_eq!(
        ctx.path_protection(Path::new(r"C:\NOSUCH~1")),
        Some(Self_(Reason::Unresolved))
    );
    assert!(!protect::is_windows_old_n("Windows.old"));
    assert_eq!(ctx.path_protection(Path::new(r"C:\Windows.older")), None);
}

// --- 10: names compare like NTFS ---

/// A sync root and a folder whose names differ only in a letter `to_lowercase` would merge.
#[test]
fn audit_10_protection_does_not_merge_distinct_names() {
    let det = SyncRootDetection::with_roots(vec![PathBuf::from(r"C:\Users\me\Straße")]);
    let ctx = ProtectContext::new(env, &det);
    assert_eq!(
        ctx.path_protection(Path::new(r"C:\Users\me\STRASSE\x")),
        None
    );
    assert_eq!(
        ctx.path_protection(Path::new(r"C:\Users\me\STRAẞE\x")),
        None
    );
    assert_eq!(
        ctx.path_protection(Path::new(r"c:\users\ME\straße\x")),
        Some(Self_(Reason::SyncRoot))
    );
    // A folder named with the Kelvin sign is not `.kube`.
    assert_eq!(
        ctx.path_protection(Path::new("C:\\Users\\me\\.\u{212A}ube")),
        None
    );
}

/// p6 / 10 as reported: NTFS opens `ΝΙΚΟΣ` as `νικοσ`, but `to_lowercase` turns the capital
/// final sigma into `ς`, so a sync root or profile written in the other case was missed.
#[test]
fn audit_10_greek_final_sigma_matches_like_ntfs() {
    let fx = testzone::fixture();
    let on_disk = fx.path().join("ΝΙΚΟΣ");
    fs::create_dir(&on_disk).unwrap();
    // NTFS really treats them as one name.
    assert!(fx.path().join("νικοσ").exists());
    assert_ne!("ΝΙΚΟΣ".to_lowercase(), "νικοσ".to_lowercase());
    assert!(crate::core::paths::eq_ci("ΝΙΚΟΣ", "νικοσ"));

    let det = SyncRootDetection::with_roots(vec![fx.path().join("νικοσ")]);
    let ctx = ProtectContext::new(env, &det);
    assert_eq!(
        ctx.path_protection(&on_disk.join("x")),
        Some(Self_(Reason::SyncRoot))
    );
    // The same for the user folder the sync block is scoped to.
    let failed = SyncRootDetection::detect(&[src("failing", Err("denied"), true)]);
    let home = fx.path().join("νικοσ");
    let ctx = ProtectContext::new(move |k| (k == "USERPROFILE").then(|| home.clone()), &failed);
    assert!(ctx.sync_unverified(&CanonPath::new(&on_disk.join("x")).unwrap()));
}

/// "막혀 있음을 확인한 것": names NTFS keeps apart stay apart, on disk and in the verdicts.
#[test]
fn audit_10_lookalike_names_stay_distinct() {
    let fx = testzone::fixture();
    for (disk, lookalike) in [
        (".ſsh", ".SSH"),
        ("uſers", "USERS"),
        ("wındows", "WINDOWS"),
        (".\u{212A}ube", ".kube"),
    ] {
        fs::create_dir(fx.path().join(disk)).unwrap();
        assert!(!fx.path().join(lookalike).exists(), "{disk}");
        assert!(!crate::core::paths::eq_ci(disk, lookalike), "{disk}");
    }
    let ctx = ctx();
    for p in [
        r"C:\Users\me\.ſsh",
        "C:\\Users\\me\\.\u{212A}ube",
        r"C:\wındows",
    ] {
        assert_eq!(ctx.path_protection(Path::new(p)), None, "{p}");
    }
    assert_eq!(
        ctx.path_protection(Path::new(r"C:\uſers")),
        None,
        "not the Users root"
    );
}

/// "막혀 있음을 확인한 것": a `~` in a path that no longer exists used to make it always
/// `Unresolved`; only 8.3-shaped names are looked up now (S12 restore, M4).
#[test]
fn audit_tilde_in_missing_path_is_compared_as_written() {
    let ctx = ctx();
    for p in [
        r"C:\ClearCache_TestZone\scan-tests\gone\~cache",
        r"C:\ClearCache_TestZone\scan-tests\gone\file~",
        r"C:\ClearCache_TestZone\scan-tests\gone\a~b.txt",
    ] {
        assert!(CanonPath::new(Path::new(p)).is_some(), "{p}");
        assert_eq!(ctx.path_protection(Path::new(p)), None, "{p}");
    }
    assert_eq!(
        ctx.path_protection(Path::new(r"C:\ClearCache_TestZone\scan-tests\gone\CACHE~1")),
        Some(Self_(Reason::Unresolved))
    );
}

// --- 11: the Hugging Face rule covers the model hub only ---

#[test]
fn audit_11_hugging_face_token_is_not_in_the_rule() {
    let m = builtin();
    assert_eq!(best(&m, r"C:\Users\me\.cache\huggingface", &[]), None);
    assert_eq!(
        best(&m, r"C:\Users\me\.cache\huggingface\hub", &[]),
        Some("huggingface-cache")
    );
    assert_eq!(best(&m, r"C:\Users\me\.cache\huggingface\token", &[]), None);
}
