//! Rule patterns: `%VAR%\path` (one location, optionally `\*` for each folder directly inside)
//! and `**\name` (that name at any depth). No regex. Matching is on `CanonPath`, so it
//! compares names the NTFS way (`paths::eq_ci`) and respects component boundaries.

use std::path::{Path, PathBuf};

use super::Rule;
use crate::core::paths;
use crate::core::protect::{CanonPath, Stop, StopFolders};

/// Resolves an environment variable to a path.
pub type Env<'a> = &'a dyn Fn(&str) -> Option<PathBuf>;

/// `**\` rules never match below these: the same names there are parts of installed apps,
/// editor extensions or global package managers, and removing them breaks the program. Applies
/// to built-in and user rules alike and no rule can turn it off. M4's re-check (S3) uses the
/// same lists.
pub const APP_INSTALL_EXCLUDES: &[(&str, &str)] = &[
    ("LOCALAPPDATA", "Packages"),
    ("LOCALAPPDATA", "Programs"),
    ("APPDATA", "npm"),
    ("ProgramFiles", ""),
    ("ProgramFiles(x86)", ""),
    // Editor extensions (each one a Node project with its own `node_modules`).
    ("USERPROFILE", ".vscode"),
    ("USERPROFILE", ".vscode-insiders"),
    ("USERPROFILE", ".vscode-oss"),
    ("USERPROFILE", ".cursor"),
    ("USERPROFILE", ".windsurf"),
    // Global installs of pnpm, Yarn, Bun and Scoop apps.
    ("LOCALAPPDATA", "pnpm"),
    ("LOCALAPPDATA", "Yarn"),
    ("USERPROFILE", ".bun"),
    ("USERPROFILE", r"scoop\apps"),
    ("SCOOP", "apps"),
    // Node version managers: nvm-windows, fnm, Volta (2nd audit B3).
    ("APPDATA", "nvm"),
    ("NVM_HOME", ""),
    ("NVM_SYMLINK", ""),
    ("APPDATA", "fnm"),
    ("LOCALAPPDATA", "fnm_multishells"),
    ("FNM_DIR", ""),
    ("LOCALAPPDATA", "Volta"),
    ("VOLTA_HOME", ""),
];

/// Variables every Windows profile has. If one of these cannot be resolved the exclusions
/// above are incomplete, so `**\` rules match nothing rather than risk matching inside an app
/// (2nd audit B5). The others are set only when the tool is installed; unset means "not used".
pub const REQUIRED_VARS: &[&str] = &[
    "LOCALAPPDATA",
    "APPDATA",
    "USERPROFILE",
    "ProgramFiles",
    "ProgramFiles(x86)",
];

/// Files that mark a folder as an installed program: no `**\` rule matches at or below a
/// folder listing one (a Node install keeps `node.exe` next to its `node_modules`, B3).
pub const INSTALL_MARKERS: &[&str] = &["node.exe"];

/// The same, by name wherever they appear: an Electron app's bundled sources.
pub const APP_INSTALL_NAMED: &[&[&str]] =
    &[&["resources", "app"], &["resources", "app.asar.unpacked"]];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternSpec {
    /// `%VAR%\a\b`, or `%VAR%\a\*` with `any_child`. Components as written.
    Located {
        var: String,
        comps: Vec<String>,
        any_child: bool,
    },
    /// `**\a\b`.
    Named(Vec<String>),
}

fn valid_name(c: &str) -> bool {
    !c.is_empty()
        && c != "."
        && c != ".."
        && !c.contains(['*', '%', ':', '/', '?', '"', '<', '>', '|'])
}

pub fn parse(pattern: &str) -> Result<PatternSpec, String> {
    let bad = || format!("패턴 형식이 잘못됨: {pattern}");
    let mut parts = pattern.split('\\');
    let head = parts.next().unwrap_or("");
    let mut comps: Vec<String> = parts.map(str::to_string).collect();
    if head == "**" {
        return (!comps.is_empty() && comps.iter().all(|c| valid_name(c)))
            .then_some(PatternSpec::Named(comps))
            .ok_or_else(bad);
    }
    let var = head
        .strip_prefix('%')
        .and_then(|h| h.strip_suffix('%'))
        .filter(|v| valid_name(v))
        .ok_or_else(bad)?;
    let any_child = comps.last().is_some_and(|c| c == "*");
    if any_child {
        comps.pop();
    }
    if comps.is_empty() || !comps.iter().all(|c| valid_name(c)) {
        return Err(bad());
    }
    Ok(PatternSpec::Located {
        var: var.to_string(),
        comps,
        any_child,
    })
}

/// `%VAR%\comps` in comparison form; `None` when the variable is unset.
pub fn expand(env: Env, var: &str, comps: &[String]) -> Option<CanonPath> {
    let mut base = CanonPath::new(&env(var)?)?;
    base.comps.extend(comps.iter().cloned());
    Some(base)
}

#[derive(Debug, Clone)]
enum Compiled {
    Located {
        base: CanonPath,
        any_child: bool,
    },
    Named(Vec<String>),
    /// Unset variable, unparsable pattern, or a `not_inside` location that cannot be
    /// resolved: never matches.
    Unavailable,
}

#[derive(Debug, Clone)]
struct Entry {
    rule: Rule,
    pattern: Compiled,
    not_inside: Vec<CanonPath>,
}

/// Rules compiled against one environment. Built once per scan and per re-check.
#[derive(Debug, Clone, Default)]
pub struct RuleMatcher {
    entries: Vec<Entry>,
    excludes: Vec<CanonPath>,
    local_app_data: Option<CanonPath>,
    /// A required variable could not be resolved: `**\` rules are off (B5).
    named_off: bool,
}

/// `app-1.0.9`: the per-version folder of an app installed by Squirrel under
/// `%LOCALAPPDATA%\<app>` (Discord, Slack, Teams classic, …).
fn is_squirrel_version(name: &str) -> bool {
    name.get(..4).is_some_and(|p| paths::eq_ci(p, "app-"))
        && name.as_bytes().get(4).is_some_and(u8::is_ascii_digit)
}

impl RuleMatcher {
    pub fn new(rules: &[Rule], env: Env) -> Self {
        let located = |p: &str| match parse(p) {
            Ok(PatternSpec::Located { var, comps, .. }) => expand(env, &var, &comps),
            _ => None,
        };
        let entries = rules
            .iter()
            .map(|rule| {
                // A `not_inside` that cannot be resolved turns the rule off instead of being
                // dropped, which would widen the rule (B5).
                let not_inside: Option<Vec<CanonPath>> =
                    rule.when.not_inside.iter().map(|p| located(p)).collect();
                let pattern = match (parse(&rule.pattern), &not_inside) {
                    (_, None) | (Err(_), _) => Compiled::Unavailable,
                    (Ok(PatternSpec::Named(names)), _) => Compiled::Named(names),
                    (
                        Ok(PatternSpec::Located {
                            var,
                            comps,
                            any_child,
                        }),
                        _,
                    ) => match expand(env, &var, &comps) {
                        Some(base) => Compiled::Located { base, any_child },
                        None => Compiled::Unavailable,
                    },
                };
                Entry {
                    rule: rule.clone(),
                    pattern,
                    not_inside: not_inside.unwrap_or_default(),
                }
            })
            .collect();
        // Every exclusion is resolved or the `**\` rules go off: a required variable that is
        // missing, or any variable that is set but cannot be put in comparison form
        // (`"D:\tools\nvm"`, `…\.`, an unexpanded `%X%`), would otherwise leave a hole in the
        // list (2nd audit B5, focused review 1). Only an unset optional variable is skipped.
        let mut named_off = false;
        let mut excludes = Vec::new();
        for (var, rel) in APP_INSTALL_EXCLUDES {
            match env(var) {
                None => named_off |= REQUIRED_VARS.contains(var),
                Some(p) => match CanonPath::new(&p.join(rel)) {
                    Some(c) => excludes.push(c),
                    None => named_off = true,
                },
            }
        }
        Self {
            entries,
            excludes,
            local_app_data: env("LOCALAPPDATA").and_then(|p| CanonPath::new(&p)),
            named_off,
        }
    }

    /// Inside an app install location (the lists above, or `Program Files` on any drive).
    pub fn in_app_install(&self, path: &CanonPath) -> bool {
        self.excludes.iter().any(|e| path.starts_with(e))
            || path.comp_is(0, "Program Files")
            || path.comp_is(0, "Program Files (x86)")
            || APP_INSTALL_NAMED.iter().any(|run| path.contains_run(run))
            || self.local_app_data.as_ref().is_some_and(|l| {
                path.starts_with(l)
                    && path
                        .comps
                        .get(l.comps.len() + 1)
                        .is_some_and(|c| is_squirrel_version(c))
            })
    }

    fn matches(&self, e: &Entry, path: &CanonPath, siblings: &[String]) -> bool {
        let hit = match &e.pattern {
            Compiled::Located {
                base,
                any_child: false,
            } => path == base,
            Compiled::Located {
                base,
                any_child: true,
            } => path.comps.len() == base.comps.len() + 1 && path.starts_with(base),
            Compiled::Named(names) => {
                !self.named_off
                    && path.ends_with(names)
                    && !self.in_app_install(path)
                    && !is_install_root(siblings)
            }
            Compiled::Unavailable => false,
        };
        hit && e
            .rule
            .when
            .sibling_exists
            .iter()
            .all(|want| siblings.iter().any(|s| paths::eq_ci(s, want)))
            && !e.not_inside.iter().any(|d| path.starts_with(d))
    }

    /// Located beats named, then more pattern components, then the more cautious grade (D8).
    fn specificity(e: &Entry) -> (bool, usize, u8) {
        let (located, comps) = match &e.pattern {
            Compiled::Located { base, any_child } => {
                (true, base.comps.len() + usize::from(*any_child))
            }
            Compiled::Named(names) => (false, names.len()),
            Compiled::Unavailable => (false, 0),
        };
        (located, comps, e.rule.grade.caution())
    }

    /// The most specific rule matching folder `path`; `siblings` are the names of the files
    /// (not folders) listed next to it, for `when.sibling_exists`. Ties keep the earlier rule.
    pub fn best(&self, path: &CanonPath, siblings: &[String]) -> Option<&Rule> {
        let mut best: Option<&Entry> = None;
        for e in self
            .entries
            .iter()
            .filter(|e| self.matches(e, path, siblings))
        {
            if best.is_none_or(|b| Self::specificity(e) > Self::specificity(b)) {
                best = Some(e);
            }
        }
        best.map(|e| &e.rule)
    }
}

/// The files of a listing mark an installed program (`INSTALL_MARKERS`).
pub fn is_install_root(files: &[String]) -> bool {
    files
        .iter()
        .any(|f| INSTALL_MARKERS.iter().any(|m| paths::eq_ci(f, m)))
}

impl StopFolders for RuleMatcher {
    fn stop(&self, dir: &Path, files: &[String]) -> Option<Stop> {
        CanonPath::new(dir)
            .and_then(|c| self.best(&c, files))
            .and_then(Rule::stop)
    }

    fn install_root(&self, files: &[String]) -> bool {
        is_install_root(files)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testenv::{canon, env, rule, sib};
    use super::super::{Action, Grade, RuleOrigin};
    use super::*;
    use crate::core::rules::source::{BuiltinRules, RuleSource};

    fn builtin() -> RuleMatcher {
        RuleMatcher::new(&BuiltinRules::embedded().rules().unwrap().rules, &env)
    }

    fn best<'a>(m: &'a RuleMatcher, path: &str, siblings: &[&str]) -> Option<&'a str> {
        m.best(&canon(path), &sib(siblings)).map(|r| r.id.as_str())
    }

    #[test]
    fn pattern_parse_accepts_two_forms_only() {
        assert_eq!(
            parse(r"%LOCALAPPDATA%\npm-cache"),
            Ok(PatternSpec::Located {
                var: "LOCALAPPDATA".into(),
                comps: vec!["npm-cache".into()],
                any_child: false
            })
        );
        assert_eq!(
            parse(r"%LOCALAPPDATA%\Programs\*"),
            Ok(PatternSpec::Located {
                var: "LOCALAPPDATA".into(),
                comps: vec!["Programs".into()],
                any_child: true
            })
        );
        assert_eq!(
            parse(r"**\A\node_modules"),
            Ok(PatternSpec::Named(vec!["A".into(), "node_modules".into()]))
        );
        for p in [
            "",
            "**",
            r"**\",
            r"**\a\*",
            r"**\..\x",
            r"C:\Users\me\x",
            r"node_modules",
            r"%LOCALAPPDATA%",
            r"%LOCALAPPDATA%\*",
            r"%LOCALAPPDATA%\*\cache",
            r"%LOCAL%APPDATA%\x",
            r"%%\x",
            r"%LOCALAPPDATA%\a\\b",
            r"%LOCALAPPDATA%\a:b",
            r"**\a/b",
        ] {
            assert!(parse(p).is_err(), "{p:?}");
        }
    }

    #[test]
    fn pattern_located_matches_exact_folder_only() {
        let m = builtin();
        for p in [
            r"C:\Users\me\AppData\Local\npm-cache",
            r"c:\users\ME\appdata\local\NPM-CACHE\",
            r"\\?\C:\Users\me\AppData\Local\npm-cache",
        ] {
            assert_eq!(best(&m, p, &[]), Some("npm-cache"), "{p}");
        }
        for p in [
            r"C:\Users\me\AppData\Local\npm-cache2",
            r"C:\Users\me\AppData\Local\npm-cache\_cacache",
            r"C:\Users\other\AppData\Local\npm-cache",
            r"C:\Users\me\AppData\Local",
        ] {
            assert_eq!(best(&m, p, &[]), None, "{p}");
        }
    }

    #[test]
    fn pattern_any_child_matches_one_level() {
        let m = builtin();
        let programs = r"C:\Users\me\AppData\Local\Programs";
        assert_eq!(best(&m, programs, &[]), Some("local-programs"));
        assert_eq!(
            best(&m, &format!(r"{programs}\Some App"), &[]),
            Some("local-programs-app")
        );
        assert_eq!(best(&m, &format!(r"{programs}\Some App\bin"), &[]), None);
    }

    #[test]
    fn pattern_named_respects_boundary_case_and_when() {
        let m = builtin();
        let pj = &["package.json", "src"];
        assert_eq!(
            best(&m, r"C:\work\proj\node_modules", pj),
            Some("node-modules")
        );
        assert_eq!(
            best(&m, r"D:\a\b\c\NODE_MODULES", &["PACKAGE.JSON"]),
            Some("node-modules")
        );
        assert_eq!(best(&m, r"C:\node_modules", pj), Some("node-modules"));
        // Component boundary.
        assert_eq!(best(&m, r"C:\work\proj\node_modules2", pj), None);
        assert_eq!(best(&m, r"C:\work\proj\my_node_modules", pj), None);
        // `when`: the sibling must be there.
        assert_eq!(best(&m, r"C:\work\proj\node_modules", &["src"]), None);
        assert_eq!(best(&m, r"C:\work\proj\target", pj), None);
        assert_eq!(
            best(&m, r"C:\work\proj\target", &["Cargo.toml"]),
            Some("cargo-target")
        );
        assert_eq!(best(&m, r"C:\work\proj\.next", pj), Some("next-build"));
    }

    #[test]
    fn pattern_unset_variable_never_matches() {
        let rules = [rule("x", r"%NOSUCHVAR%\cache", Grade::Safe)];
        let m = RuleMatcher::new(&rules, &env);
        assert_eq!(best(&m, r"C:\cache", &[]), None);
    }

    #[test]
    fn pattern_not_inside_blocks_the_rule() {
        let mut r = rule("cache", r"**\.cache", Grade::Safe);
        r.when.not_inside = vec![r"%USERPROFILE%\keep".into()];
        let m = RuleMatcher::new(&[r], &env);
        assert_eq!(best(&m, r"C:\Users\me\work\.cache", &[]), Some("cache"));
        assert_eq!(best(&m, r"C:\Users\me\keep\a\.cache", &[]), None);
    }

    #[test]
    fn pattern_app_install_excludes_cover_every_named_rule() {
        let m = builtin();
        let locations = [
            r"C:\Users\me\AppData\Local\Packages\App_8wekyb3d8bbwe\LocalCache",
            r"C:\Users\me\AppData\Local\Programs\App\resources\app",
            r"C:\Users\me\AppData\Roaming\npm",
            r"C:\Program Files\App",
            r"C:\Program Files (x86)\App",
            r"D:\Program Files\App",
        ];
        for loc in locations {
            for (name, sibling) in [
                ("node_modules", "package.json"),
                (".next", "package.json"),
                ("target", "Cargo.toml"),
            ] {
                let p = format!(r"{loc}\{name}");
                assert_eq!(best(&m, &p, &[sibling]), None, "{p}");
                assert!(m.in_app_install(&canon(&p)), "{p}");
            }
        }
        // The same shape elsewhere still matches: the exclusion is not too wide.
        assert_eq!(
            best(&m, r"C:\work\proj\node_modules", &["package.json"]),
            Some("node-modules")
        );
        assert_eq!(
            best(
                &m,
                r"C:\Users\me\AppData\Local\proj\node_modules",
                &["package.json"]
            ),
            Some("node-modules")
        );
        // User rules get the same exclusion; located rules do not.
        let mut user = rule("u", r"**\cache", Grade::Safe);
        user.source = RuleOrigin::User;
        let located = rule("l", r"%LOCALAPPDATA%\Programs\App\cache", Grade::Safe);
        let m = RuleMatcher::new(&[user, located], &env);
        assert_eq!(best(&m, r"C:\Program Files\App\cache", &[]), None);
        assert_eq!(
            best(&m, r"C:\Users\me\AppData\Local\Programs\App\cache", &[]),
            Some("l")
        );
        assert_eq!(best(&m, r"C:\work\cache", &[]), Some("u"));
    }

    #[test]
    fn pattern_local_programs_apps_are_uninstall_only() {
        let m = builtin();
        let r = m
            .best(&canon(r"C:\Users\me\AppData\Local\Programs\App"), &[])
            .unwrap();
        assert_eq!((r.grade, r.action), (Grade::Unknown, Action::UninstallApp));
        assert!(!r.grade.stops());
    }

    #[test]
    fn d8_most_specific_rule_wins() {
        // Located beats named, whatever the grades say.
        let m = RuleMatcher::new(
            &[
                rule("named", r"**\npm-cache", Grade::UserData),
                rule("located", r"%LOCALAPPDATA%\npm-cache", Grade::Safe),
            ],
            &env,
        );
        assert_eq!(
            best(&m, r"C:\Users\me\AppData\Local\npm-cache", &[]),
            Some("located")
        );
        // More components beat fewer.
        let m = RuleMatcher::new(
            &[
                rule("b", r"**\b", Grade::UserData),
                rule("ab", r"**\a\b", Grade::Safe),
            ],
            &env,
        );
        assert_eq!(best(&m, r"C:\x\a\b", &[]), Some("ab"));
        assert_eq!(best(&m, r"C:\x\c\b", &[]), Some("b"));
        // Same kind and count: the more cautious grade, in either order.
        for order in [[0, 1, 2, 3], [3, 2, 1, 0]] {
            let all = [
                rule("safe", r"%LOCALAPPDATA%\x", Grade::Safe),
                rule(
                    "likely",
                    r"%USERPROFILE%\AppData\Local\x",
                    Grade::LikelySafe,
                ),
                rule("unknown", r"%LOCALAPPDATA%\x", Grade::Unknown),
                rule("user", r"%LOCALAPPDATA%\x", Grade::UserData),
            ];
            let rules: Vec<_> = order.iter().map(|i| all[*i].clone()).collect();
            let m = RuleMatcher::new(&rules, &env);
            assert_eq!(best(&m, r"C:\Users\me\AppData\Local\x", &[]), Some("user"));
        }
    }

    #[test]
    fn d9_only_safe_and_likely_safe_rules_stop() {
        let m = builtin();
        let stop = |p: &str, s: &[&str]| m.stop(Path::new(p), &sib(s)).is_some();
        assert!(stop(r"C:\work\proj\node_modules", &["package.json"]));
        assert!(stop(r"C:\Users\me\AppData\Local\pnpm\store", &[]));
        assert!(stop(r"C:\Users\me\AppData\Local\Temp", &[]));
        assert!(!stop(r"C:\Users\me\Downloads", &[]));
        assert!(!stop(r"C:\Users\me\AppData\Local\Programs\App", &[]));
        assert!(!stop(r"C:\work\proj", &[]));
        // The same for user rules.
        let mut projects = rule("p", r"%USERPROFILE%\Projects", Grade::UserData);
        let mut cache = rule("c", r"**\.cache", Grade::Safe);
        projects.source = RuleOrigin::User;
        cache.source = RuleOrigin::User;
        let m = RuleMatcher::new(&[projects, cache], &env);
        assert_eq!(m.stop(Path::new(r"C:\Users\me\Projects"), &[]), None);
        assert_eq!(
            m.stop(Path::new(r"C:\Users\me\Projects\a\.cache"), &[]),
            Some(Stop::Walk)
        );
    }
}
