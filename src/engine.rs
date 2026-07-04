//! Rule engine: inverted index + sliding correlation window + throttle.
//!
//! Performance-critical: the inverted index maps `(module, event_type)`
//! to the rule indices that reference it, so the hot path
//! (`process_event`) only ever evaluates the rules that can possibly
//! match the incoming event — never an O(n_rules) scan.
//!
//! Each rule owns its own sliding correlation window. A leaf `Compare`
//! matches if *any* event currently in the window satisfies it, which is
//! what makes multi-event / multi-module correlation possible.
//!
//! If a rule declares `throttle: N/per`, the engine keeps a separate
//! ring of last firing timestamps; matches above the cap drop their
//! actions silently (counted, but no firing).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::ast::*;
use crate::event::LogEvent;

type EventKey = (String, String);
type RuleIndex = HashMap<EventKey, Vec<usize>>;

/// One rule firing returned by [`RuleEngine::process_event`].
///
/// Carries the matched rule's name + actions **and** a snapshot of its
/// correlation window at match time. The window lets the caller build
/// richer alert evidence — e.g. surface the *other* events a correlation
/// rule matched on, not only the triggering one. The triggering event is
/// the last element of `window`.
pub struct Firing {
    pub rule_name: String,
    pub actions: Vec<Action>,
    pub window: Vec<LogEvent>,
}

/// FIFO sliding window of recent events for one rule.
struct CorrelationWindow {
    events: VecDeque<LogEvent>,
    max_age: Duration,
}

impl CorrelationWindow {
    fn new(max_age: Duration) -> Self {
        Self {
            events: VecDeque::new(),
            max_age,
        }
    }

    fn push(&mut self, e: LogEvent) {
        self.events.push_back(e);
        self.evict();
    }

    fn evict(&mut self) {
        let now = Instant::now();
        while let Some(front) = self.events.front() {
            if now.duration_since(front.timestamp) > self.max_age {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Per-rule throttle bookkeeping: a sliding window of recent *firings*.
/// Kept in a separate `Mutex` from the correlation window so the engine
/// can record a firing without re-touching the event ring.
struct ThrottleState {
    fires: VecDeque<Instant>,
    cap: u32,
    per: Duration,
}

impl ThrottleState {
    fn from(t: &Throttle) -> Self {
        Self {
            fires: VecDeque::with_capacity(t.max as usize + 1),
            cap: t.max,
            per: t.per,
        }
    }

    /// Returns `true` if a firing is allowed *now* — and records the
    /// firing if so. Returns `false` when the cap is reached (no record).
    fn allow_and_record(&mut self) -> bool {
        let now = Instant::now();
        while let Some(front) = self.fires.front() {
            if now.duration_since(*front) > self.per {
                self.fires.pop_front();
            } else {
                break;
            }
        }
        if (self.fires.len() as u32) < self.cap {
            self.fires.push_back(now);
            true
        } else {
            false
        }
    }
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    index: RuleIndex,
    windows: Vec<Mutex<CorrelationWindow>>,
    /// `None` for rules without a throttle.
    throttles: Vec<Option<Mutex<ThrottleState>>>,
}

impl RuleEngine {
    /// Build the inverted index once, at load time.
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut index: RuleIndex = HashMap::new();
        for (idx, rule) in rules.iter().enumerate() {
            for cond in &rule.conditions {
                let mut refs = Vec::new();
                cond.collect_event_refs(&mut refs);
                for key in refs {
                    // Dedup : une règle qui répète la même (module, event_type)
                    // sur plusieurs lignes OR doit ne déclencher qu'UNE fois
                    // pour un event donné, pas une fois par occurrence.
                    let bucket = index.entry(key).or_default();
                    if !bucket.contains(&idx) {
                        bucket.push(idx);
                    }
                }
            }
        }
        let windows = rules
            .iter()
            .map(|r| Mutex::new(CorrelationWindow::new(r.window)))
            .collect();
        let throttles = rules
            .iter()
            .map(|r| {
                r.throttle
                    .as_ref()
                    .map(|t| Mutex::new(ThrottleState::from(t)))
            })
            .collect();
        Self {
            rules,
            index,
            windows,
            throttles,
        }
    }

    #[allow(dead_code)]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// HOT PATH: called for every received event. Returns the
    /// `(rule_name, actions)` of every rule that fired and passed
    /// throttle gating.
    pub fn process_event(&self, event: &LogEvent) -> Vec<Firing> {
        let key = (event.module.clone(), event.event_type.clone());
        let mut triggered = Vec::new();

        let Some(rule_indices) = self.index.get(&key) else {
            return triggered;
        };

        for &idx in rule_indices {
            let rule = &self.rules[idx];
            let snapshot = {
                let mut w = match self.windows[idx].lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                w.push(event.clone());
                w.events.clone()
            };
            if rule.conditions.iter().any(|c| eval(c, &snapshot)) {
                // Gate on throttle if declared. A capped firing is
                // dropped silently — the goal is anti-storm, not silent
                // failure: operators see the cap in the rule itself.
                if let Some(th_mu) = &self.throttles[idx] {
                    let mut th = match th_mu.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    if !th.allow_and_record() {
                        continue;
                    }
                }
                triggered.push(Firing {
                    rule_name: rule.name.clone(),
                    actions: rule.actions.clone(),
                    // Snapshot of the correlation window — the caller uses
                    // it to attach the correlated events to the alert.
                    window: snapshot.into_iter().collect(),
                });
            }
        }
        triggered
    }
}

/// Recursively evaluate a condition against the window snapshot. A leaf
/// `Compare` is true if THERE EXISTS an event in the window satisfying it
/// — this is what enables cross-event, cross-module correlation.
fn eval(cond: &Condition, window: &VecDeque<LogEvent>) -> bool {
    match cond {
        Condition::Compare { path, op, value } => window.iter().any(|e| {
            e.module == path.module
                && e.event_type == path.event_type
                && e.get_field(&path.field)
                    .map(|v| v.compare(op, value))
                    .unwrap_or(false)
        }),
        Condition::And(a, b) => eval(a, window) && eval(b, window),
        Condition::Or(a, b) => eval(a, window) || eval(b, window),
        Condition::Not(a) => !eval(a, window),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{CmpOp, FieldValue, RuleValue};
    use std::collections::HashMap;

    fn ev(module: &str, et: &str, fields: &[(&str, FieldValue)]) -> LogEvent {
        let mut map = HashMap::new();
        for (k, v) in fields {
            map.insert((*k).to_string(), v.clone());
        }
        LogEvent {
            module: module.into(),
            event_type: et.into(),
            fields: map,
            timestamp: Instant::now(),
        }
    }

    fn cmp(path: &str, op: CmpOp, v: RuleValue) -> Condition {
        Condition::Compare {
            path: FieldPath::parse(path).unwrap(),
            op,
            value: v,
        }
    }

    #[test]
    fn single_event_matches_compare() {
        let rule = Rule {
            name: "r1".into(),
            conditions: vec![cmp(
                "kernel_callback.process_create.pid",
                CmpOp::Eq,
                RuleValue::Int(4688),
            )],
            window: Duration::from_secs(5),
            throttle: None,
            actions: vec![Action::Log],
        };
        let engine = RuleEngine::new(vec![rule]);
        let fired = engine.process_event(&ev(
            "kernel_callback",
            "process_create",
            &[("pid", FieldValue::Int(4688))],
        ));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule_name, "r1");
    }

    #[test]
    fn unindexed_event_evaluates_no_rule() {
        let rule = Rule {
            name: "r1".into(),
            conditions: vec![cmp(
                "kernel_callback.process_create.pid",
                CmpOp::Eq,
                RuleValue::Int(4688),
            )],
            window: Duration::from_secs(5),
            throttle: None,
            actions: vec![Action::Log],
        };
        let engine = RuleEngine::new(vec![rule]);
        let fired = engine.process_event(&ev(
            "kernel_callback",
            "thread_exit",
            &[("tid", FieldValue::Int(1))],
        ));
        assert!(fired.is_empty());
    }

    #[test]
    fn correlation_and_across_modules_in_window() {
        let cond = Condition::And(
            Box::new(cmp(
                "kernel_callback.process_create.pid",
                CmpOp::Eq,
                RuleValue::Int(4688),
            )),
            Box::new(cmp(
                "minifilter.file_create.name",
                CmpOp::Eq,
                RuleValue::Str("malware.exe".into()),
            )),
        );
        let rule = Rule {
            name: "corr".into(),
            conditions: vec![cond],
            window: Duration::from_secs(5),
            throttle: None,
            actions: vec![Action::Alert("suspicious".into())],
        };
        let engine = RuleEngine::new(vec![rule]);

        let fired = engine.process_event(&ev(
            "kernel_callback",
            "process_create",
            &[("pid", FieldValue::Int(4688))],
        ));
        assert!(fired.is_empty());

        let fired = engine.process_event(&ev(
            "minifilter",
            "file_create",
            &[("name", FieldValue::Str("malware.exe".into()))],
        ));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule_name, "corr");
        // La fenêtre porte les DEUX events corrélés (process_create +
        // file_create), le déclencheur étant le dernier — c'est ce qui
        // permet à l'agent d'enrichir l'alerte avec l'autre côté du motif.
        assert_eq!(fired[0].window.len(), 2);
        assert!(
            fired[0]
                .window
                .iter()
                .any(|e| e.module == "kernel_callback" && e.event_type == "process_create")
        );
    }

    #[test]
    fn correlation_misses_when_event_aged_out() {
        let cond = Condition::And(
            Box::new(cmp(
                "kernel_callback.process_create.pid",
                CmpOp::Eq,
                RuleValue::Int(4688),
            )),
            Box::new(cmp(
                "minifilter.file_create.name",
                CmpOp::Eq,
                RuleValue::Str("malware.exe".into()),
            )),
        );
        let rule = Rule {
            name: "corr".into(),
            conditions: vec![cond],
            window: Duration::from_millis(50),
            throttle: None,
            actions: vec![Action::Log],
        };
        let engine = RuleEngine::new(vec![rule]);

        let mut stale = ev(
            "kernel_callback",
            "process_create",
            &[("pid", FieldValue::Int(4688))],
        );
        stale.timestamp = Instant::now() - Duration::from_millis(200);
        let _ = engine.process_event(&stale);

        let fired = engine.process_event(&ev(
            "minifilter",
            "file_create",
            &[("name", FieldValue::Str("malware.exe".into()))],
        ));
        assert!(fired.is_empty());
    }

    #[test]
    fn duplicate_event_refs_dont_double_fire() {
        // Une règle avec 3 lignes OR référençant toutes la même
        // (module, event_type) ne doit déclencher qu'UNE fois par event.
        let rule = Rule {
            name: "or3".into(),
            conditions: vec![
                cmp(
                    "kernel_callback.process_create.image_path",
                    CmpOp::Contains,
                    RuleValue::Str("a.exe".into()),
                ),
                cmp(
                    "kernel_callback.process_create.image_path",
                    CmpOp::Contains,
                    RuleValue::Str("b.exe".into()),
                ),
                cmp(
                    "kernel_callback.process_create.image_path",
                    CmpOp::Contains,
                    RuleValue::Str("c.exe".into()),
                ),
            ],
            window: Duration::from_secs(5),
            throttle: None,
            actions: vec![Action::Log],
        };
        let engine = RuleEngine::new(vec![rule]);
        let e = ev(
            "kernel_callback",
            "process_create",
            &[("image_path", FieldValue::Str("a.exe".into()))],
        );
        let fired = engine.process_event(&e);
        assert_eq!(fired.len(), 1, "1 event = 1 fire, pas N");
    }

    #[test]
    fn throttle_caps_firings_in_window() {
        // 2 alertes max par seconde. La 3e dans la même seconde doit être
        // muselée.
        let rule = Rule {
            name: "noisy".into(),
            conditions: vec![cmp(
                "kernel_callback.process_create.pid",
                CmpOp::Gt,
                RuleValue::Int(0),
            )],
            window: Duration::from_secs(5),
            throttle: Some(Throttle {
                max: 2,
                per: Duration::from_secs(1),
            }),
            actions: vec![Action::Log],
        };
        let engine = RuleEngine::new(vec![rule]);
        let one = ev(
            "kernel_callback",
            "process_create",
            &[("pid", FieldValue::Int(1))],
        );
        assert_eq!(engine.process_event(&one).len(), 1);
        assert_eq!(engine.process_event(&one).len(), 1);
        assert_eq!(
            engine.process_event(&one).len(),
            0,
            "3e match dans la fenêtre throttle doit être étouffé"
        );
    }
}
