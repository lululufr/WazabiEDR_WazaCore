//! Abstract syntax tree for `.waza` rules.
//!
//! The parser produces these types; the engine consumes them. Neither
//! the AST nor the parser ever knows concrete module field names — a
//! [`FieldPath`] is an opaque `module.event_type.field` triple.

use std::time::Duration;

use crate::event::{CmpOp, RuleValue};

/// Fully-qualified field reference: `"kernel_callback.process_create.pid"`.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldPath {
    pub module: String,
    pub event_type: String,
    pub field: String,
}

impl FieldPath {
    /// Parse a dotted path.
    ///
    /// Sémantique : le `field` est le **dernier segment** (après le
    /// dernier `.`), le `module` est le **premier segment** (avant le
    /// premier `.`), et le `event_type` est tout ce qui vit entre les
    /// deux — **il peut donc contenir des points**.
    ///
    /// Ce comportement autorise les events de plugins dont le `kind`
    /// est hiérarchique (ex: `plugin.hook.api_call.api` →
    /// module=`plugin`, event_type=`hook.api_call`, field=`api`).
    /// Pour les paths kernel classiques il reste équivalent au split
    /// naïf (`kernel_callback.process_create.pid` inchangé).
    pub fn parse(s: &str) -> Option<Self> {
        let last_dot = s.rfind('.')?;
        let (left, field_with_dot) = s.split_at(last_dot);
        let field = &field_with_dot[1..]; // strip le '.'
        let first_dot = left.find('.')?;
        let (module, event_with_dot) = left.split_at(first_dot);
        let event_type = &event_with_dot[1..]; // strip le '.'
        if module.is_empty() || event_type.is_empty() || field.is_empty() {
            return None;
        }
        Some(FieldPath {
            module: module.into(),
            event_type: event_type.into(),
            field: field.into(),
        })
    }
}

/// A boolean condition over event fields.
#[derive(Debug, Clone)]
pub enum Condition {
    Compare {
        path: FieldPath,
        op: CmpOp,
        value: RuleValue,
    },
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
    Not(Box<Condition>),
}

impl Condition {
    /// Collect the `(module, event_type)` pairs referenced by this
    /// condition. Drives the engine's inverted index so an event only
    /// hits the rules that actually mention its type.
    pub fn collect_event_refs(&self, refs: &mut Vec<(String, String)>) {
        match self {
            Condition::Compare { path, .. } => {
                let k = (path.module.clone(), path.event_type.clone());
                if !refs.contains(&k) {
                    refs.push(k);
                }
            }
            Condition::And(a, b) | Condition::Or(a, b) => {
                a.collect_event_refs(refs);
                b.collect_event_refs(refs);
            }
            Condition::Not(a) => a.collect_event_refs(refs),
        }
    }

    /// Visit every [`FieldPath`] in the tree. Used for schema validation
    /// at load time.
    pub fn collect_field_paths<'a>(&'a self, out: &mut Vec<&'a FieldPath>) {
        match self {
            Condition::Compare { path, .. } => out.push(path),
            Condition::And(a, b) | Condition::Or(a, b) => {
                a.collect_field_paths(out);
                b.collect_field_paths(out);
            }
            Condition::Not(a) => a.collect_field_paths(out),
        }
    }
}

/// Anti-storm rate-limit attached to a rule.
///
/// Semantics : the engine triggers the rule at most `max` times within any
/// rolling `per` window. A match that hits the cap is *silently dropped*
/// (still counted internally for window bookkeeping, but no actions run).
///
/// Independent from the correlation `window`: correlation decides whether
/// the rule matches; throttle decides whether we *act* on the match.
#[derive(Debug, Clone, PartialEq)]
pub struct Throttle {
    pub max: u32,
    pub per: Duration,
}

/// One detection rule: a named group of OR-ed condition lines, a
/// correlation window, optional throttle, and the actions to run on match.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    /// Multiple lines in a Detection group = implicit OR between them.
    pub conditions: Vec<Condition>,
    /// Temporal correlation window (default 5s, overridable via `window:`).
    pub window: Duration,
    /// Optional anti-storm rate-limit (`throttle: N/duration`).
    pub throttle: Option<Throttle>,
    pub actions: Vec<Action>,
}

/// Action triggered when a rule matches. Extensible: add a variant here
/// and a match arm in the agent's `actions.rs`.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Log,
    Alert(String),
    KillProcess,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_path_parses_three_segments() {
        let fp = FieldPath::parse("kernel_callback.process_create.pid").unwrap();
        assert_eq!(fp.module, "kernel_callback");
        assert_eq!(fp.event_type, "process_create");
        assert_eq!(fp.field, "pid");
    }

    #[test]
    fn field_path_rejects_malformed() {
        assert!(FieldPath::parse("a.b").is_none());
        assert!(FieldPath::parse("a..c").is_none());
        assert!(FieldPath::parse("").is_none());
    }

    #[test]
    fn field_path_supports_dotted_event_type() {
        // Un event_type hiérarchique (kind d'un plugin) est préservé.
        let fp = FieldPath::parse("plugin.hook.api_call.api").unwrap();
        assert_eq!(fp.module, "plugin");
        assert_eq!(fp.event_type, "hook.api_call");
        assert_eq!(fp.field, "api");
    }

    #[test]
    fn field_path_field_is_always_last_segment() {
        // Cas dégénéré : plusieurs points dans event_type.
        let fp = FieldPath::parse("plugin.a.b.c.d.field").unwrap();
        assert_eq!(fp.module, "plugin");
        assert_eq!(fp.event_type, "a.b.c.d");
        assert_eq!(fp.field, "field");
    }

    #[test]
    fn collect_event_refs_dedup() {
        let p = FieldPath::parse("m.e.f").unwrap();
        let p2 = FieldPath::parse("m.e.g").unwrap();
        let cond = Condition::And(
            Box::new(Condition::Compare {
                path: p,
                op: CmpOp::Eq,
                value: RuleValue::Int(1),
            }),
            Box::new(Condition::Compare {
                path: p2,
                op: CmpOp::Eq,
                value: RuleValue::Int(2),
            }),
        );
        let mut refs = Vec::new();
        cond.collect_event_refs(&mut refs);
        assert_eq!(refs, vec![("m".to_string(), "e".to_string())]);
    }
}
