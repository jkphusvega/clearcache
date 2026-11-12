//! Where rules come from. M3 has the built-in `rules.json` only; M5 adds the SQLite store and
//! M6 user rules as further `RuleSource`s. Verdict code takes `&[Rule]` and never sees a source.

use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;

use super::pattern::{self, PatternSpec};
use super::{Rule, RuleOrigin, TargetMode};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleSet {
    pub version: u32,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleLoadError {
    Parse(String),
    Schema(String),
}

impl fmt::Display for RuleLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleLoadError::Parse(e) => write!(f, "규칙 파일을 읽지 못함: {e}"),
            RuleLoadError::Schema(e) => write!(f, "규칙 형식 오류: {e}"),
        }
    }
}

pub trait RuleSource {
    fn rules(&self) -> Result<RuleSet, RuleLoadError>;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    schema: u32,
    version: u32,
    rules: Vec<Rule>,
}

/// Parses and validates a rules file; every rule gets `origin`.
pub fn parse_rules(json: &str, origin: RuleOrigin) -> Result<RuleSet, RuleLoadError> {
    let file: RuleFile =
        serde_json::from_str(json).map_err(|e| RuleLoadError::Parse(e.to_string()))?;
    let schema = |msg: String| Err(RuleLoadError::Schema(msg));
    if file.schema != SCHEMA_VERSION {
        return schema(format!("지원하지 않는 schema {}", file.schema));
    }
    let mut ids = HashSet::new();
    let mut rules = file.rules;
    for r in &mut rules {
        r.source = origin;
        if r.id.is_empty() || !ids.insert(r.id.clone()) {
            return schema(format!("id가 비었거나 겹침: {:?}", r.id));
        }
        if r.name.trim().is_empty() || r.description.trim().is_empty() {
            return schema(format!("{}: name과 description이 필요함", r.id));
        }
        pattern::parse(&r.pattern).map_err(|e| RuleLoadError::Schema(format!("{}: {e}", r.id)))?;
        for p in &r.when.not_inside {
            if !matches!(pattern::parse(p), Ok(PatternSpec::Located { .. })) {
                return schema(format!("{}: not_inside는 %VAR%\\경로 형식만 됨", r.id));
            }
        }
        if r.when.sibling_exists.iter().any(|s| s.trim().is_empty()) {
            return schema(format!("{}: sibling_exists에 빈 이름", r.id));
        }
        if let Some(g) = r.outside_repo_grade {
            // More cautious, and still stopping: the walk must not depend on the repository.
            if g.caution() <= r.grade.caution() || g.stops() != r.grade.stops() {
                return schema(format!(
                    "{}: outside_repo_grade는 grade보다 조심스럽고 멈춤 여부가 같아야 함",
                    r.id
                ));
            }
        }
        let needs_days = r.target_mode == TargetMode::ContentsOlderThan;
        if needs_days != r.older_than_days.is_some_and(|d| d > 0) {
            return schema(format!(
                "{}: older_than_days는 contents_older_than일 때만, 1 이상",
                r.id
            ));
        }
    }
    Ok(RuleSet {
        version: file.version,
        rules,
    })
}

/// The `rules.json` compiled into the app.
pub struct BuiltinRules(&'static str);

impl BuiltinRules {
    pub fn embedded() -> Self {
        Self(include_str!("../../../rules/rules.json"))
    }
}

impl RuleSource for BuiltinRules {
    fn rules(&self) -> Result<RuleSet, RuleLoadError> {
        parse_rules(self.0, RuleOrigin::Builtin)
    }
}

#[derive(Debug, Clone, Default)]
pub struct LoadedRules {
    pub set: RuleSet,
    /// The source failed, so there are no rules and every folder shows "모름". The table warns:
    /// "내장 규칙을 읽지 못해 모든 폴더를 '모름'으로 표시합니다. 다시 설치하면 고쳐집니다."
    pub failed: Option<String>,
}

/// A failing source never stops the app: it yields no rules and a warning.
pub fn load(source: &dyn RuleSource) -> LoadedRules {
    match source.rules() {
        Ok(set) => LoadedRules { set, failed: None },
        Err(e) => LoadedRules {
            set: RuleSet::default(),
            failed: Some(e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::super::testenv::env;
    use super::super::{Action, Grade};
    use super::*;
    use crate::core::rules::pattern::expand;

    #[test]
    fn rules_builtin_json_parses_and_passes_schema() {
        let set = BuiltinRules::embedded().rules().expect("built-in rules");
        assert!(set.version >= 1);
        assert!(!set.rules.is_empty());
        assert!(set.rules.iter().all(|r| r.source == RuleOrigin::Builtin));
        let by_id = |id: &str| set.rules.iter().find(|r| r.id == id).unwrap();
        assert_eq!(by_id("npm-cache").grade, Grade::Safe);
        assert_eq!(by_id("node-modules").when.sibling_exists, ["package.json"]);
        assert_eq!(by_id("downloads").grade, Grade::UserData);
        let temp = by_id("user-temp");
        assert_eq!(temp.target_mode, TargetMode::ContentsOlderThan);
        assert_eq!(temp.older_than_days, Some(7));
        assert_eq!(by_id("local-programs-app").action, Action::UninstallApp);
        // Rules that hand a folder to quarantine say how it comes back.
        for r in &set.rules {
            if r.grade.stops() {
                assert_eq!(r.action, Action::Quarantine, "{}", r.id);
                assert!(r.restore_hint.is_some(), "{}", r.id);
            }
        }
    }

    /// A located rule below another rule that stops the walk would never match (D8, D9).
    #[test]
    fn rules_builtin_located_rules_are_not_shadowed() {
        let set = BuiltinRules::embedded().rules().unwrap();
        let located: Vec<_> = set
            .rules
            .iter()
            .filter_map(|r| match pattern::parse(&r.pattern) {
                Ok(PatternSpec::Located { var, comps, .. }) => Some((
                    r,
                    expand(&env, &var, &comps).expect("test env covers the variable"),
                )),
                _ => None,
            })
            .collect();
        assert!(located.len() > 5);
        for (outer, outer_path) in located.iter().filter(|(r, _)| r.grade.stops()) {
            for (inner, inner_path) in &located {
                assert!(
                    inner.id == outer.id || !inner_path.starts_with(outer_path),
                    "{} is hidden below {}",
                    inner.id,
                    outer.id
                );
            }
        }
    }

    #[test]
    fn rules_broken_source_gives_no_rules_and_a_warning() {
        let loaded = load(&BuiltinRules("{ not json"));
        assert!(loaded.set.rules.is_empty());
        assert!(loaded.failed.is_some());
        let ok = load(&BuiltinRules::embedded());
        assert!(ok.failed.is_none());
        assert!(!ok.set.rules.is_empty());
    }

    #[test]
    fn rules_schema_rejects_bad_files() {
        let file = |rule: &str| format!(r#"{{"schema":1,"version":1,"rules":[{rule}]}}"#);
        let base = r#""bundle":"dev_ai","name":"n","grade":"safe","action":"quarantine","description":"d""#;
        let ok = file(&format!(r#"{{"id":"a","pattern":"**\\x",{base}}}"#));
        assert!(parse_rules(&ok, RuleOrigin::User).is_ok());
        assert_eq!(
            parse_rules(&ok, RuleOrigin::User).unwrap().rules[0].source,
            RuleOrigin::User
        );
        let schema_errors = [
            // duplicate id
            format!(
                r#"{{"schema":1,"version":1,"rules":[{{"id":"a","pattern":"**\\x",{base}}},{{"id":"a","pattern":"**\\y",{base}}}]}}"#
            ),
            file(&format!(r#"{{"id":"","pattern":"**\\x",{base}}}"#)),
            file(&format!(r#"{{"id":"a","pattern":"C:\\x",{base}}}"#)),
            file(&format!(
                r#"{{"id":"a","pattern":"**\\x","target_mode":"contents_older_than",{base}}}"#
            )),
            file(&format!(
                r#"{{"id":"a","pattern":"**\\x","older_than_days":7,{base}}}"#
            )),
            file(&format!(
                r#"{{"id":"a","pattern":"**\\x","when":{{"not_inside":["**\\y"]}},{base}}}"#
            )),
            r#"{"schema":2,"version":1,"rules":[]}"#.to_string(),
        ];
        for json in &schema_errors {
            assert!(
                matches!(
                    parse_rules(json, RuleOrigin::Builtin),
                    Err(RuleLoadError::Schema(_))
                ),
                "{json}"
            );
        }
        let parse_errors = [
            // unknown grade, unknown action, unknown field, a file claiming its own source
            file(
                r#"{"id":"a","pattern":"**\\x","bundle":"dev_ai","name":"n","grade":"fine","action":"quarantine","description":"d"}"#,
            ),
            file(
                r#"{"id":"a","pattern":"**\\x","bundle":"dev_ai","name":"n","grade":"safe","action":"delete","description":"d"}"#,
            ),
            file(&format!(
                r#"{{"id":"a","pattern":"**\\x","extra":1,{base}}}"#
            )),
            file(&format!(
                r#"{{"id":"a","pattern":"**\\x","source":"builtin",{base}}}"#
            )),
            file(r#"{"id":"a","pattern":"**\\x"}"#),
        ];
        for json in &parse_errors {
            assert!(
                matches!(
                    parse_rules(json, RuleOrigin::Builtin),
                    Err(RuleLoadError::Parse(_))
                ),
                "{json}"
            );
        }
    }
}
