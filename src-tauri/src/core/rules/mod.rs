//! Verdicts: grade, action, reason and source for a folder (SPEC 판정 우선순위).
//! 1. hard-coded safety rules (`protect.rs`, user-data pinning) 2. the most specific rule
//! 3. (M5) AI 4. unknown. Nothing in 2 can override 1, user rules included.

pub mod pattern;
pub mod source;

use serde::{Deserialize, Serialize};

use crate::core::paths;
use crate::core::protect::{
    self, CanonPath, ProtectContext, Protection, Protections, Reason, Stop,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Grade {
    Safe,
    LikelySafe,
    UserData,
    Unknown,
}

impl Grade {
    /// The walk stops at folders whose rule has one of these grades (D9): nothing below
    /// becomes a node. Other grades only label the folder and the walk goes on.
    pub fn stops(self) -> bool {
        matches!(self, Grade::Safe | Grade::LikelySafe)
    }

    /// Higher is more cautious; breaks ties between equally specific rules (D8).
    pub fn caution(self) -> u8 {
        match self {
            Grade::Safe => 0,
            Grade::LikelySafe => 1,
            Grade::Unknown => 2,
            Grade::UserData => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Quarantine,
    OfficialTool,
    UninstallApp,
    ExplainOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictSource {
    Safety,
    Rule,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleOrigin {
    #[default]
    Builtin,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bundle {
    Windows,
    DevAi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetMode {
    #[default]
    Folder,
    /// Only items directly inside that are older than `older_than_days` (D10).
    ContentsOlderThan,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct When {
    /// Every one of these names must be listed next to the folder.
    #[serde(default)]
    pub sibling_exists: Vec<String>,
    /// `%VAR%\path` locations below which the rule does not apply.
    #[serde(default)]
    pub not_inside: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub bundle: Bundle,
    pub pattern: String,
    pub name: String,
    pub grade: Grade,
    pub action: Action,
    pub description: String,
    #[serde(default)]
    pub restore_hint: Option<String>,
    #[serde(default)]
    pub target_mode: TargetMode,
    #[serde(default)]
    pub older_than_days: Option<u32>,
    #[serde(default)]
    pub when: When,
    /// Grade used when the folder is not inside a git repository (audit 5): a `node_modules`
    /// in a project is rebuilt from its package file, one elsewhere may belong to a tool.
    #[serde(default)]
    pub outside_repo_grade: Option<Grade>,
    /// Set by the loader, never read from the file.
    #[serde(skip)]
    pub source: RuleOrigin,
}

impl Rule {
    /// Whether this rule stops the walk (D9) and, for built-in rules only, bounds credential
    /// findings below it (D12). The outside-repo grade must stop too (checked at load), so the
    /// answer does not depend on where the repository is.
    pub fn stop(&self) -> Option<Stop> {
        self.grade.stops().then_some(match self.source {
            RuleOrigin::Builtin => Stop::Bounded,
            RuleOrigin::User => Stop::Walk,
        })
    }
}

/// The five summary columns (디자인 리뷰 7D).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// (1) 바로 정리
    CleanNow,
    /// (1b) 확인 필요
    NeedsReview,
    /// (2) 공식 도구
    OfficialTool,
    /// (3) 앱 제거
    UninstallApp,
    /// (4) 건드리면 안 됨
    DoNotTouch,
}

/// The one place that decides the column (D15). Order matters: action first, so WinSxS stays
/// (2) and Program Files (3) although both are system-protected; then `Self_` protection;
/// `Contains` leaves the folder in the column of its own grade (D13).
pub fn category(action: Action, grade: Grade, protection: Option<&Protection>) -> Category {
    match action {
        Action::OfficialTool => Category::OfficialTool,
        Action::UninstallApp => Category::UninstallApp,
        Action::ExplainOnly => Category::DoNotTouch,
        Action::Quarantine if protection.is_some_and(Protection::is_self) => Category::DoNotTouch,
        Action::Quarantine if grade.stops() => Category::CleanNow,
        Action::Quarantine => Category::NeedsReview,
    }
}

/// Why a folder is pinned to "사용자 데이터" by the safety rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fixed {
    /// Documents, Desktop, Pictures, Videos, Music.
    PersonalFolder,
    /// Holds `.git`.
    Repo,
    /// A repository lies somewhere below.
    ContainsRepo,
    /// `.pst`/`.ost`/virtual disk files adding up to 1 GB or more.
    LargeFiles,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    Itself,
    Inside,
}

/// Whether `path` is one of the personal folders (wherever the shell says they are) or lies
/// inside one.
pub fn personal_folder(ctx: &ProtectContext, path: &CanonPath) -> Option<Depth> {
    let folder = ctx
        .personal_folders()
        .iter()
        .filter(|f| path.starts_with(f))
        .max_by_key(|f| f.comps.len())?;
    Some(if folder == path {
        Depth::Itself
    } else {
        Depth::Inside
    })
}

/// SPEC 1-1 시스템 항목 매핑: what the app offers for a system-protected path.
const SYSTEM_REASON: &str = "Windows나 설치된 프로그램이 쓰는 시스템 영역입니다.";
const WINDOWS_OLD_REASON: &str =
    "이전 Windows 설치 파일입니다. 설정 > 시스템 > 저장소 > 임시 파일 > 이전 Windows 설치에서 정리하세요.";

/// SPEC 1-1 시스템 항목 매핑: what the app offers for a system-protected path, and the line
/// shown with it.
pub fn system_item(ctx: &ProtectContext, path: Option<&CanonPath>) -> (Action, &'static str) {
    let Some(c) = path else {
        return (Action::ExplainOnly, SYSTEM_REASON);
    };
    let first = c.comps.first().map(String::as_str).unwrap_or("");
    if paths::eq_ci(first, "Windows.old") || protect::is_windows_old_n(first) {
        return (Action::OfficialTool, WINDOWS_OLD_REASON);
    }
    (system_action(ctx, c), SYSTEM_REASON)
}

fn system_action(ctx: &ProtectContext, c: &CanonPath) -> Action {
    if let Some(sr) = ctx.system_root().filter(|sr| c.starts_with(sr)) {
        let rel: Vec<String> = c.comps[sr.comps.len()..]
            .iter()
            .map(|s| paths::fold(s))
            .collect();
        let rel: Vec<&str> = rel.iter().map(String::as_str).collect();
        return match rel.as_slice() {
            ["WINSXS", ..]
            | ["TEMP", ..]
            | ["MINIDUMP", ..]
            | ["LIVEKERNELREPORTS", ..]
            | ["MEMORY.DMP"]
            | ["SOFTWAREDISTRIBUTION", "DOWNLOAD", ..] => Action::OfficialTool,
            _ => Action::ExplainOnly,
        };
    }
    if c.comps.len() == 1 && c.comp_is(0, "hiberfil.sys") {
        Action::OfficialTool
    } else if c.comp_is(0, "Program Files") || c.comp_is(0, "Program Files (x86)") {
        Action::UninstallApp
    } else {
        Action::ExplainOnly
    }
}

/// Everything the verdict of one folder depends on. The scan fills it in; tests build it.
#[derive(Debug, Clone, Default)]
pub struct Facts<'a> {
    pub path: Option<&'a CanonPath>,
    /// Every reason, from the path and from what the scan lifted out of the subtree.
    pub protection: Protections,
    /// The most specific rule matching this folder.
    pub rule: Option<&'a Rule>,
    /// The nearest ancestor's rule that did not stop the walk (Downloads, `Programs\*`).
    pub inherited: Option<&'a Rule>,
    /// This folder itself is pinned.
    pub fixed: Option<Fixed>,
    /// An ancestor is pinned.
    pub inside_fixed: Option<Fixed>,
    /// An ancestor holds `.git` (the scan does not count one found below a rule folder).
    pub in_repo: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    pub grade: Grade,
    pub action: Action,
    /// One line shown under the badge.
    pub reason: String,
    pub source: VerdictSource,
    pub rule_id: Option<String>,
    /// The strongest reason, shown and used for the column.
    pub protection: Option<Protection>,
    /// Every reason; any one blocks selection.
    pub protections: Protections,
}

impl Verdict {
    pub fn category(&self) -> Category {
        category(self.action, self.grade, self.protection.as_ref())
    }
}

fn fixed_reason(f: Fixed) -> &'static str {
    match f {
        Fixed::PersonalFolder => "문서·사진 같은 개인 파일 폴더입니다.",
        Fixed::Repo => "git 저장소입니다. 작업 중인 코드가 들어 있습니다.",
        Fixed::ContainsRepo => "안에 git 저장소가 있습니다.",
        Fixed::LargeFiles => "메일 저장소나 가상 디스크 같은 큰 개인 파일이 들어 있습니다.",
    }
}

pub fn judge(ctx: &ProtectContext, f: &Facts) -> Verdict {
    let verdict = |grade, action, reason: &str, source, rule: Option<&Rule>| Verdict {
        grade,
        action,
        reason: reason.to_string(),
        source,
        rule_id: rule.map(|r| r.id.clone()),
        protection: f.protection.primary(),
        protections: f.protection.clone(),
    };
    let safety =
        |grade, action, reason| verdict(grade, action, reason, VerdictSource::Safety, None);

    // 1. Safety rules. `Contains` blocks selection but leaves grade and action alone (D13).
    if let Some(Protection::Self_(r)) = f.protection.primary() {
        return match r {
            Reason::System => {
                let (action, reason) = system_item(ctx, f.path);
                safety(Grade::Unknown, action, reason)
            }
            r if r.is_credential() => safety(
                Grade::UserData,
                Action::ExplainOnly,
                "로그인 정보나 키가 들어 있어 옮기면 앱이나 계정이 깨질 수 있습니다.",
            ),
            Reason::SyncRoot | Reason::CloudFile => safety(
                Grade::UserData,
                Action::ExplainOnly,
                "클라우드와 동기화되는 폴더입니다. 옮기면 클라우드에서도 지워질 수 있습니다.",
            ),
            Reason::VirtualDisk => safety(
                Grade::UserData,
                Action::ExplainOnly,
                "WSL·Docker 같은 가상 디스크가 들어 있습니다. 해당 도구로 정리하세요.",
            ),
            Reason::Reparse => safety(
                Grade::Unknown,
                Action::ExplainOnly,
                "다른 위치를 가리키는 링크입니다.",
            ),
            Reason::Quarantine => safety(
                Grade::Unknown,
                Action::ExplainOnly,
                "ClearCache 격리함입니다.",
            ),
            _ => safety(
                Grade::Unknown,
                Action::ExplainOnly,
                "경로를 확인할 수 없어 보호합니다.",
            ),
        };
    }
    if let Some(fixed) = f.fixed {
        return safety(Grade::UserData, Action::Quarantine, fixed_reason(fixed));
    }
    // 2. Rules: the folder's own, then what it inherits. Pinning covers descendants that no
    // rule of their own matched, so it comes before an inherited rule.
    if let Some(r) = f.rule {
        return match r.outside_repo_grade.filter(|_| !f.in_repo) {
            Some(grade) => verdict(
                grade,
                r.action,
                &format!(
                    "{} git 저장소 밖이라 직접 확인한 뒤 고르세요.",
                    r.description
                ),
                VerdictSource::Rule,
                Some(r),
            ),
            None => verdict(
                r.grade,
                r.action,
                &r.description,
                VerdictSource::Rule,
                Some(r),
            ),
        };
    }
    if let Some(fixed) = f.inside_fixed {
        return safety(Grade::UserData, Action::Quarantine, fixed_reason(fixed));
    }
    if let Some(r) = f.inherited {
        return verdict(
            r.grade,
            r.action,
            &r.description,
            VerdictSource::Rule,
            Some(r),
        );
    }
    // 4. Unknown (Q2): selectable behind a warning.
    verdict(
        Grade::Unknown,
        Action::Quarantine,
        "규칙에 없는 폴더입니다. 직접 확인한 뒤 고르세요.",
        VerdictSource::None,
        None,
    )
}

#[cfg(test)]
pub(crate) mod testenv {
    use super::*;
    use crate::core::scan::syncroots::SyncRootDetection;
    use std::path::{Path, PathBuf};

    /// Fixed environment for rule tests; nothing reads the real one.
    pub const ENV: &[(&str, &str)] = &[
        ("SystemRoot", r"C:\Windows"),
        ("USERPROFILE", r"C:\Users\me"),
        ("LOCALAPPDATA", r"C:\Users\me\AppData\Local"),
        ("APPDATA", r"C:\Users\me\AppData\Roaming"),
        ("ProgramFiles", r"C:\Program Files"),
        ("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ];

    pub fn env(name: &str) -> Option<PathBuf> {
        ENV.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| PathBuf::from(v))
    }

    pub fn ctx() -> ProtectContext {
        ProtectContext::new(env, &SyncRootDetection::with_roots(Vec::new()))
    }

    pub fn canon(path: &str) -> CanonPath {
        CanonPath::new(Path::new(path)).expect("test path")
    }

    pub fn sib(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    pub fn rule(id: &str, pattern: &str, grade: Grade) -> Rule {
        Rule {
            id: id.into(),
            bundle: Bundle::DevAi,
            pattern: pattern.into(),
            name: id.into(),
            grade,
            action: Action::Quarantine,
            description: format!("rule {id}"),
            restore_hint: None,
            target_mode: TargetMode::Folder,
            older_than_days: None,
            when: When::default(),
            outside_repo_grade: None,
            source: RuleOrigin::Builtin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::pattern::RuleMatcher;
    use super::source::{BuiltinRules, RuleSource};
    use super::testenv::{canon, ctx, env, rule, sib};
    use super::*;
    use std::path::{Path, PathBuf};
    use Protection::{Contains, Self_};

    /// Verdict from the path alone, the way the scan composes it: path protection, the best
    /// rule and personal-folder pinning. Subtree facts are added by the caller.
    fn judge_at(m: &RuleMatcher, path: &str, siblings: &[&str]) -> Verdict {
        judge_with(m, path, siblings, |_| {})
    }

    fn judge_with<'a>(
        m: &'a RuleMatcher,
        path: &str,
        siblings: &[&str],
        extra: impl FnOnce(&mut Facts<'a>),
    ) -> Verdict {
        let ctx = ctx();
        let c = canon(path);
        let depth = personal_folder(&ctx, &c);
        let mut facts = Facts {
            protection: ctx.path_protections(Path::new(path)),
            rule: m.best(&c, &sib(siblings)),
            fixed: (depth == Some(Depth::Itself)).then_some(Fixed::PersonalFolder),
            inside_fixed: (depth == Some(Depth::Inside)).then_some(Fixed::PersonalFolder),
            ..Facts::default()
        };
        extra(&mut facts);
        let facts = Facts {
            path: Some(&c),
            ..facts
        };
        judge(&ctx, &facts)
    }

    fn builtin() -> RuleMatcher {
        RuleMatcher::new(&BuiltinRules::embedded().rules().unwrap().rules, &env)
    }

    #[test]
    fn rules_category_table() {
        use Action::{ExplainOnly, Quarantine};
        use Category::{CleanNow, DoNotTouch, NeedsReview};
        use Grade::*;
        let sys = Self_(Reason::System);
        let cred = Self_(Reason::CredentialPath);
        let holds = Contains(Reason::CredentialPath);
        let root = Contains(Reason::UserFolderRoot);
        let table: &[(Action, Grade, Option<&Protection>, Category)] = &[
            (Quarantine, Safe, None, CleanNow),
            (Quarantine, LikelySafe, None, CleanNow),
            (Quarantine, Unknown, None, NeedsReview),
            (Quarantine, UserData, None, NeedsReview),
            // Action first: system-protected items keep their SPEC 1-1 column.
            (
                Action::OfficialTool,
                Unknown,
                Some(&sys),
                Category::OfficialTool,
            ),
            (
                Action::UninstallApp,
                Unknown,
                Some(&sys),
                Category::UninstallApp,
            ),
            (Action::UninstallApp, Unknown, None, Category::UninstallApp),
            (ExplainOnly, Unknown, Some(&sys), DoNotTouch),
            (ExplainOnly, UserData, Some(&cred), DoNotTouch),
            (ExplainOnly, Safe, None, DoNotTouch),
            // Self_ protection on a quarantine verdict.
            (Quarantine, Safe, Some(&cred), DoNotTouch),
            // Contains keeps the folder's own column (D13, D24).
            (Quarantine, Safe, Some(&holds), CleanNow),
            (Quarantine, Unknown, Some(&holds), NeedsReview),
            (Quarantine, UserData, Some(&root), NeedsReview),
        ];
        for (action, grade, protection, want) in table {
            assert_eq!(
                category(*action, *grade, *protection),
                *want,
                "{action:?} {grade:?} {protection:?}"
            );
        }
    }

    #[test]
    fn rules_spec_m3_criteria() {
        let m = builtin();
        let npm = judge_at(&m, r"C:\Users\me\AppData\Local\npm-cache", &[]);
        assert_eq!(
            (npm.grade, npm.source, npm.rule_id.as_deref()),
            (Grade::Safe, VerdictSource::Rule, Some("npm-cache"))
        );
        assert_eq!(npm.category(), Category::CleanNow);

        // node_modules inside a repository follows its rule; the repository root is pinned.
        let nm = judge_with(&m, r"C:\work\proj\node_modules", &["package.json"], |f| {
            f.inside_fixed = Some(Fixed::Repo);
            f.in_repo = true;
        });
        assert_eq!((nm.grade, nm.source), (Grade::Safe, VerdictSource::Rule));
        let root = judge_with(&m, r"C:\work\proj", &[], |f| f.fixed = Some(Fixed::Repo));
        assert_eq!(
            (root.grade, root.action, root.source),
            (Grade::UserData, Action::Quarantine, VerdictSource::Safety)
        );
        assert_eq!(root.category(), Category::NeedsReview);
        let above = judge_with(&m, r"C:\work", &[], |f| f.fixed = Some(Fixed::ContainsRepo));
        assert_eq!(above.grade, Grade::UserData);
        // Folders in the repository with no rule of their own.
        let src = judge_with(&m, r"C:\work\proj\src", &[], |f| {
            f.inside_fixed = Some(Fixed::Repo)
        });
        assert_eq!(
            (src.grade, src.source),
            (Grade::UserData, VerdictSource::Safety)
        );

        let unknown = judge_at(&m, r"C:\work\stuff", &[]);
        assert_eq!(
            (unknown.grade, unknown.action, unknown.source),
            (Grade::Unknown, Action::Quarantine, VerdictSource::None)
        );
        assert_eq!(unknown.category(), Category::NeedsReview);
    }

    #[test]
    fn d9_non_stopping_rule_labels_what_is_below() {
        let m = builtin();
        let downloads = judge_at(&m, r"C:\Users\me\Downloads", &[]);
        assert_eq!(
            (downloads.grade, downloads.source),
            (Grade::UserData, VerdictSource::Rule)
        );
        let rules = BuiltinRules::embedded().rules().unwrap().rules;
        let dl = rules.iter().find(|r| r.id == "downloads").unwrap();
        let app = rules.iter().find(|r| r.id == "local-programs-app").unwrap();
        // No rule of its own: the inherited one.
        let sub = judge_with(&m, r"C:\Users\me\Downloads\stuff", &[], |f| {
            f.inherited = Some(dl)
        });
        assert_eq!(
            (sub.grade, sub.rule_id.as_deref()),
            (Grade::UserData, Some("downloads"))
        );
        // Its own rule wins over the inherited one.
        let nm = judge_with(
            &m,
            r"C:\Users\me\Downloads\proj\node_modules",
            &["package.json"],
            |f| {
                f.inherited = Some(dl);
                f.in_repo = true;
            },
        );
        assert_eq!(
            (nm.grade, nm.rule_id.as_deref()),
            (Grade::Safe, Some("node-modules"))
        );
        // Inside an installed app everything stays uninstall-only.
        let bin = judge_with(
            &m,
            r"C:\Users\me\AppData\Local\Programs\App\bin",
            &[],
            |f| f.inherited = Some(app),
        );
        assert_eq!(bin.action, Action::UninstallApp);
        assert_eq!(bin.category(), Category::UninstallApp);
    }

    #[test]
    fn rules_system_items_map_to_spec_columns() {
        let m = builtin();
        let table = [
            (r"C:\Windows\WinSxS", Category::OfficialTool),
            (r"C:\Windows\WinSxS\amd64_x", Category::OfficialTool),
            (
                r"C:\Windows\SoftwareDistribution\Download",
                Category::OfficialTool,
            ),
            (r"C:\Windows\Temp", Category::OfficialTool),
            (r"C:\Windows\Minidump", Category::OfficialTool),
            (r"C:\Windows\LiveKernelReports", Category::OfficialTool),
            (r"C:\Windows\MEMORY.DMP", Category::OfficialTool),
            (r"C:\Windows.old", Category::OfficialTool),
            (r"C:\Windows.old\Users", Category::OfficialTool),
            (r"C:\hiberfil.sys", Category::OfficialTool),
            (r"C:\Windows\Installer", Category::DoNotTouch),
            (r"C:\Windows\System32", Category::DoNotTouch),
            (r"C:\Windows\SoftwareDistribution", Category::DoNotTouch),
            (r"C:\Windows", Category::DoNotTouch),
            (r"C:\pagefile.sys", Category::DoNotTouch),
            (r"C:\swapfile.sys", Category::DoNotTouch),
            (r"C:\ProgramData", Category::DoNotTouch),
            (r"C:\$Recycle.Bin", Category::DoNotTouch),
            (r"C:\Program Files", Category::UninstallApp),
            (r"C:\Program Files\App", Category::UninstallApp),
            (r"C:\Program Files (x86)\App\bin", Category::UninstallApp),
        ];
        for (path, want) in table {
            let v = judge_at(&m, path, &[]);
            assert_eq!(v.category(), want, "{path}");
            assert_eq!(v.source, VerdictSource::Safety, "{path}");
            assert_eq!(v.protection, Some(Self_(Reason::System)), "{path}");
        }
    }

    #[test]
    fn rules_pinned_folder_itself_cannot_be_regraded() {
        let m = RuleMatcher::new(
            &[rule("docs", r"%USERPROFILE%\Documents", Grade::Safe)],
            &env,
        );
        let docs = judge_at(&m, r"C:\Users\me\Documents", &[]);
        assert_eq!(
            (docs.grade, docs.source),
            (Grade::UserData, VerdictSource::Safety)
        );
        // Below it, a folder with its own rule follows the rule; one without stays pinned.
        let m = builtin();
        let nm = judge_with(
            &m,
            r"C:\Users\me\Documents\proj\node_modules",
            &["package.json"],
            |f| f.in_repo = true,
        );
        assert_eq!(nm.grade, Grade::Safe);
        let plain = judge_at(&m, r"C:\Users\me\Documents\letters", &[]);
        assert_eq!(
            (plain.grade, plain.source),
            (Grade::UserData, VerdictSource::Safety)
        );
        for name in ["Desktop", "Pictures", "Videos", "Music", "DOCUMENTS"] {
            let v = judge_at(&m, &format!(r"C:\Users\me\{name}"), &[]);
            assert_eq!(v.grade, Grade::UserData, "{name}");
        }
        assert_eq!(
            judge_at(&m, r"C:\work\Documents", &[]).grade,
            Grade::Unknown
        );
    }

    #[test]
    fn rules_moved_personal_folders_are_pinned_where_they_are() {
        let ctx = ctx().with_personal_folders(vec![
            PathBuf::from(r"D:\Data\내 문서"),
            PathBuf::from(r"E:\Photos"),
            PathBuf::from(r"C:\Users\me\Desktop"),
        ]);
        let depth = |p: &str| personal_folder(&ctx, &canon(p));
        assert_eq!(depth(r"D:\Data\내 문서"), Some(Depth::Itself));
        assert_eq!(depth(r"d:\data\내 문서\letters"), Some(Depth::Inside));
        assert_eq!(depth(r"\\?\E:\PHOTOS\"), Some(Depth::Itself));
        assert_eq!(depth(r"C:\Users\me\Desktop"), Some(Depth::Itself));
        // The old name under the profile is no longer the folder once it has moved.
        assert_eq!(depth(r"C:\Users\me\Documents"), None);
        assert_eq!(depth(r"C:\Users\me\Pictures"), None);
        assert_eq!(depth(r"D:\Data"), None);

        let c = canon(r"D:\Data\내 문서");
        let v = judge(
            &ctx,
            &Facts {
                path: Some(&c),
                fixed: Some(Fixed::PersonalFolder),
                ..Facts::default()
            },
        );
        assert_eq!(
            (v.grade, v.source),
            (Grade::UserData, VerdictSource::Safety)
        );
    }

    #[test]
    fn rules_personal_folders_come_from_the_shell() {
        use crate::core::scan::syncroots::SyncRootDetection;
        let ctx = ProtectContext::from_system(&SyncRootDetection::with_roots(Vec::new()));
        assert_eq!(ctx.personal_folders().len(), 5);
        let docs = crate::core::protect::known_folder_for_test(
            crate::core::protect::KnownFolder::Documents,
        )
        .expect("Documents resolves on this machine");
        let docs = CanonPath::new(&docs).unwrap();
        assert!(ctx.personal_folders().contains(&docs), "{docs:?}");
        assert_eq!(personal_folder(&ctx, &docs), Some(Depth::Itself));
    }

    #[test]
    fn rules_windows_old_points_to_the_settings_page() {
        let v = judge_at(&builtin(), r"C:\Windows.old", &[]);
        assert_eq!(
            (v.action, v.category(), v.protection),
            (
                Action::OfficialTool,
                Category::OfficialTool,
                Some(Self_(Reason::System))
            )
        );
        assert!(
            v.reason
                .contains("설정 > 시스템 > 저장소 > 임시 파일 > 이전 Windows 설치"),
            "{}",
            v.reason
        );
    }

    /// D8: no rule reaches past the safety rules, user rules included, located or named.
    #[test]
    fn d8_user_rules_cannot_override_safety_rules() {
        let cases = [
            (
                r"C:\Windows\Temp\x",
                r"%SystemRoot%\Temp\x",
                r"**\x",
                Grade::Unknown,
                Action::OfficialTool,
            ),
            (
                r"C:\Users\me\.ssh",
                r"%USERPROFILE%\.ssh",
                r"**\.ssh",
                Grade::UserData,
                Action::ExplainOnly,
            ),
            (
                r"C:\Users\me\AppData\Local\Google\Chrome\User Data",
                r"%LOCALAPPDATA%\Google\Chrome\User Data",
                r"**\User Data",
                Grade::UserData,
                Action::ExplainOnly,
            ),
            (
                r"C:\Users\me\AppData\Local\Packages\App\LocalCache",
                r"%LOCALAPPDATA%\Packages\App\LocalCache",
                r"**\LocalCache",
                Grade::UserData,
                Action::ExplainOnly,
            ),
            (
                r"C:\Users\me\Documents",
                r"%USERPROFILE%\Documents",
                r"**\Documents",
                Grade::UserData,
                Action::Quarantine,
            ),
        ];
        for (path, located, named, grade, action) in cases {
            for pattern in [located, named] {
                let mut r = rule("user", pattern, Grade::Safe);
                r.source = RuleOrigin::User;
                let m = RuleMatcher::new(&[r], &env);
                let v = judge_at(&m, path, &[]);
                assert_eq!(
                    (v.grade, v.action, v.source, v.rule_id.as_deref()),
                    (grade, action, VerdictSource::Safety, None),
                    "{path} {pattern}"
                );
                assert_ne!(v.category(), Category::CleanNow, "{path} {pattern}");
            }
        }
        // Facts from the subtree: a repository root, a folder holding a virtual disk (S11), a
        // folder with a credential file, and a container blocked by S2.
        for pattern in [r"%USERPROFILE%\code\proj", r"**\proj"] {
            let mut r = rule("user", pattern, Grade::Safe);
            r.source = RuleOrigin::User;
            let m = RuleMatcher::new(&[r], &env);
            let path = r"C:\Users\me\code\proj";
            let repo = judge_with(&m, path, &[], |f| f.fixed = Some(Fixed::Repo));
            assert_eq!(
                (repo.grade, repo.source),
                (Grade::UserData, VerdictSource::Safety)
            );
            let disk = judge_with(&m, path, &[], |f| {
                f.protection = Self_(Reason::VirtualDisk).into()
            });
            assert_eq!(
                (disk.action, disk.source, disk.category()),
                (
                    Action::ExplainOnly,
                    VerdictSource::Safety,
                    Category::DoNotTouch
                )
            );
            let cred = judge_with(&m, path, &[], |f| {
                f.protection = Self_(Reason::CredentialFile { name: ".kdbx" }).into()
            });
            assert_eq!(cred.action, Action::ExplainOnly);
            // S2: the rule's grade stands, but the verdict carries the block.
            let holds = judge_with(&m, path, &[], |f| {
                f.protection = Contains(Reason::VirtualDisk).into()
            });
            assert_eq!(holds.grade, Grade::Safe);
            assert_eq!(holds.protection, Some(Contains(Reason::VirtualDisk)));
        }
    }

    #[test]
    fn rules_containers_keep_their_own_grade() {
        let m = builtin();
        for path in [
            r"C:\Users\me",
            r"C:\Users",
            r"C:\",
            r"C:\Users\me\AppData\Local",
        ] {
            let v = judge_with(&m, path, &[], |f| {
                if f.protection.is_empty() {
                    f.protection = Contains(Reason::CredentialPath).into();
                }
            });
            assert_eq!(
                (v.grade, v.action, v.category()),
                (Grade::Unknown, Action::Quarantine, Category::NeedsReview),
                "{path}"
            );
            assert!(v.protection.is_some_and(|p| !p.is_self()), "{path}");
        }
        // Inside a credential path everything is (4), rule or not.
        let v = judge_at(
            &m,
            r"C:\Users\me\AppData\Local\Packages\App\LocalCache",
            &[],
        );
        assert_eq!(v.category(), Category::DoNotTouch);
    }

    #[test]
    fn rules_verdict_json_shape() {
        let m = builtin();
        let v = judge_at(&m, r"C:\Users\me\AppData\Local\npm-cache", &[]);
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["grade"], "safe");
        assert_eq!(json["action"], "quarantine");
        assert_eq!(json["source"], "rule");
        assert_eq!(json["rule_id"], "npm-cache");
        assert!(json["protection"].is_null());
        assert_eq!(
            serde_json::to_value(Category::DoNotTouch).unwrap(),
            "do_not_touch"
        );
    }
}
