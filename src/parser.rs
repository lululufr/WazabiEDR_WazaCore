//! `.waza` parser: turns a rule file into `Vec<Rule>`.
//!
//! # File format
//!
//! Indentation-tolerant, YAML-like. Two top-level sections, `Detection`
//! and `Action`, each holding named groups. A Detection group is a list
//! of condition lines (implicit OR between them) plus optional `window:`
//! and `throttle:` directives; the matching Action group (same name)
//! lists the actions to run.
//!
//! ```text
//! - Detection:
//!   - Group1:
//!       window: 10s
//!       throttle: 1/min
//!       - kernel_callback.process_create.pid == 4688 && minifilter.file_create.name == "malware.exe"
//!       - kernel_callback.process_create.pid == 4689
//!       - include "./network.waza"
//! - Action:
//!   - Group1:
//!     - log
//!     - alert "Suspicious process"
//! ```
//!
//! # Two-layer design
//!
//! 1. A **line classifier** recognises sections / group headers /
//!    directives / content lines. It is indentation-tolerant (it keys off
//!    the leading `-` marker and trailing `:`, not absolute column).
//! 2. An **expression parser** (tokenizer + recursive descent) turns one
//!    condition line into a [`Condition`].

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::ast::*;
use crate::event::{CmpOp, RuleValue};

/// Default correlation window when a group declares no `window:`.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(5);

/// One parse error with line/column context. The CLI surfaces these as
/// JSON so the web editor can render gutter markers.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub line: u32,
    pub col: u32,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parse a `.waza` file with the default 5s window. Convenience wrapper
/// used by tests; the agent calls [`parse_file_with_window`] with the
/// window resolved from `agent.json`.
#[allow(dead_code)]
pub fn parse_file(path: &Path) -> Result<Vec<Rule>, String> {
    parse_file_with_window(path, DEFAULT_WINDOW)
}

/// Parse a `.waza` file, using `default_window` for groups that don't
/// declare one.
pub fn parse_file_with_window(path: &Path, default_window: Duration) -> Result<Vec<Rule>, String> {
    let mut stack = HashSet::new();
    let mut done = HashSet::new();
    parse_file_inner(path, default_window, &mut stack, &mut done)
}

/// Parse a `.waza` source string (no `include` resolution — relative
/// includes would have no base directory). Used by the validation /
/// simulation CLI which gets source from stdin.
pub fn parse_source(content: &str, default_window: Duration) -> Result<Vec<Rule>, String> {
    let base = PathBuf::from(".");
    let mut stack = HashSet::new();
    let mut done = HashSet::new();
    parse_str(content, &base, default_window, &mut stack, &mut done)
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn parse_file_inner(
    path: &Path,
    default_window: Duration,
    stack: &mut HashSet<PathBuf>,
    done: &mut HashSet<PathBuf>,
) -> Result<Vec<Rule>, String> {
    let canon = canonical(path);
    if stack.contains(&canon) {
        return Err(format!("circular include: {}", canon.display()));
    }
    if done.contains(&canon) {
        return Ok(Vec::new());
    }
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let base_dir = path.parent().map(Path::to_path_buf).unwrap_or_default();

    stack.insert(canon.clone());
    let result = parse_str(&content, &base_dir, default_window, stack, done);
    stack.remove(&canon);
    done.insert(canon);
    result
}

/// Parse rule text. `base_dir` anchors relative `include` paths.
fn parse_str(
    content: &str,
    base_dir: &Path,
    default_window: Duration,
    stack: &mut HashSet<PathBuf>,
    done: &mut HashSet<PathBuf>,
) -> Result<Vec<Rule>, String> {
    #[derive(Clone, Copy, PartialEq)]
    enum Section {
        None,
        Detection,
        Action,
    }

    struct DetGroup {
        window: Option<Duration>,
        throttle: Option<Throttle>,
        conditions: Vec<Condition>,
    }

    let mut det_order: Vec<String> = Vec::new();
    let mut det_groups: Vec<DetGroup> = Vec::new();
    let mut act_names: Vec<String> = Vec::new();
    let mut act_lists: Vec<Vec<Action>> = Vec::new();
    let mut included: Vec<Rule> = Vec::new();

    let mut section = Section::None;
    let mut cur_group: Option<usize> = None;

    let det_index = |order: &Vec<String>, name: &str| order.iter().position(|n| n == name);

    for (lineno, raw) in content.lines().enumerate() {
        // Strip d'un éventuel commentaire `#` inline avant tout autre
        // traitement. Un `#` *à l'intérieur* d'une string littérale ne
        // doit pas être interprété — d'où le parcours qui suit l'état
        // "in_string", au lieu d'un simple `split_once('#')`.
        let line_no_comment = strip_inline_comment(raw);
        let line = line_no_comment.trim();
        if line.is_empty() {
            continue;
        }

        let core = if let Some(rest) = line.strip_prefix('-') {
            rest.trim()
        } else {
            line
        };
        if core.is_empty() {
            continue;
        }

        let header_word = core.trim_end_matches(':').trim().to_ascii_lowercase();
        if header_word == "detection" && core.ends_with(':') {
            section = Section::Detection;
            cur_group = None;
            continue;
        }
        if header_word == "action" && core.ends_with(':') {
            section = Section::Action;
            cur_group = None;
            continue;
        }

        if core.ends_with(':') {
            let name = core.trim_end_matches(':').trim();
            if is_ident(name) {
                match section {
                    Section::Detection => {
                        if det_index(&det_order, name).is_some() {
                            return Err(format!(
                                "line {}: duplicate Detection group '{}'",
                                lineno + 1,
                                name
                            ));
                        }
                        det_order.push(name.to_string());
                        det_groups.push(DetGroup {
                            window: None,
                            throttle: None,
                            conditions: Vec::new(),
                        });
                        cur_group = Some(det_groups.len() - 1);
                    }
                    Section::Action => {
                        if act_names.iter().any(|n| n == name) {
                            return Err(format!(
                                "line {}: duplicate Action group '{}'",
                                lineno + 1,
                                name
                            ));
                        }
                        act_names.push(name.to_string());
                        act_lists.push(Vec::new());
                        cur_group = Some(act_lists.len() - 1);
                    }
                    Section::None => {
                        return Err(format!(
                            "line {}: group '{}' outside any section",
                            lineno + 1,
                            name
                        ));
                    }
                }
                continue;
            }
        }

        if let Some(rest) = strip_kw(core, "window") {
            let rest = rest.trim_start_matches(':').trim();
            let dur = parse_duration(rest)
                .ok_or_else(|| format!("line {}: bad window '{}'", lineno + 1, rest))?;
            match (section, cur_group) {
                (Section::Detection, Some(i)) => det_groups[i].window = Some(dur),
                _ => {
                    return Err(format!(
                        "line {}: 'window:' only valid inside a Detection group",
                        lineno + 1
                    ));
                }
            }
            continue;
        }

        if let Some(rest) = strip_kw(core, "throttle") {
            let rest = rest.trim_start_matches(':').trim();
            let th = parse_throttle(rest)
                .ok_or_else(|| format!("line {}: bad throttle '{}'", lineno + 1, rest))?;
            match (section, cur_group) {
                (Section::Detection, Some(i)) => det_groups[i].throttle = Some(th),
                _ => {
                    return Err(format!(
                        "line {}: 'throttle:' only valid inside a Detection group",
                        lineno + 1
                    ));
                }
            }
            continue;
        }

        if let Some(rest) = strip_kw(core, "include") {
            let rel = parse_string_literal(rest.trim())
                .ok_or_else(|| format!("line {}: include needs a \"path\"", lineno + 1))?;
            let inc_path = base_dir.join(&rel);
            let mut inc_rules = parse_file_inner(&inc_path, default_window, stack, done)?;
            included.append(&mut inc_rules);
            continue;
        }

        match section {
            Section::Detection => {
                let Some(i) = cur_group else {
                    return Err(format!(
                        "line {}: condition outside any Detection group",
                        lineno + 1
                    ));
                };
                let cond =
                    parse_expression(core).map_err(|e| format!("line {}: {}", lineno + 1, e))?;
                det_groups[i].conditions.push(cond);
            }
            Section::Action => {
                let Some(i) = cur_group else {
                    return Err(format!(
                        "line {}: action outside any Action group",
                        lineno + 1
                    ));
                };
                let act = parse_action(core).map_err(|e| format!("line {}: {}", lineno + 1, e))?;
                act_lists[i].push(act);
            }
            Section::None => {
                return Err(format!("line {}: content outside any section", lineno + 1));
            }
        }
    }

    let mut rules = Vec::with_capacity(det_order.len() + included.len());
    for (i, name) in det_order.into_iter().enumerate() {
        let group = &det_groups[i];
        let actions = act_names
            .iter()
            .position(|n| *n == name)
            .map(|j| act_lists[j].clone())
            .unwrap_or_default();
        // Une règle qui matche mais ne fait rien est presque toujours un
        // oubli (`Action` manquant). Erreur de parse pour éviter le piège.
        if actions.is_empty() {
            return Err(format!(
                "rule '{}' has a Detection group but no matching Action group (a rule with no actions never produces output)",
                name
            ));
        }
        rules.push(Rule {
            name,
            conditions: group.conditions.clone(),
            window: group.window.unwrap_or(default_window),
            throttle: group.throttle.clone(),
            actions,
        });
    }
    rules.append(&mut included);
    Ok(rules)
}

fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Tronque la ligne au premier `#` qui n'est pas dans une string. Le
/// caractère d'échappe `\` consomme le suivant. Cohérent avec le
/// tokenizer de l'éditeur web (StreamLanguage côté frontend).
fn strip_inline_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_string => i += 2,
            b'"' => {
                in_string = !in_string;
                i += 1;
            }
            b'#' if !in_string => return &line[..i],
            _ => i += 1,
        }
    }
    line
}

fn strip_kw<'a>(core: &'a str, kw: &str) -> Option<&'a str> {
    let rest = core.strip_prefix(kw)?;
    match rest.chars().next() {
        None => Some(rest),
        Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == '.' => None,
        Some(_) => Some(rest),
    }
}

/// Parse `10s` / `500ms` / `5m` / `1h` into a [`Duration`].
/// A bare number is interpreted as seconds.
///
/// `n * 60` / `n * 3600` utilisent `checked_mul` pour rejeter un overflow
/// plutôt que paniquer en debug (ou wrap silencieusement en release).
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if let Some(num) = s.strip_suffix("ms") {
        num.trim().parse::<u64>().ok().map(Duration::from_millis)
    } else if let Some(num) = s.strip_suffix('s') {
        num.trim().parse::<u64>().ok().map(Duration::from_secs)
    } else if let Some(num) = s.strip_suffix('m') {
        num.trim()
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(60))
            .map(Duration::from_secs)
    } else if let Some(num) = s.strip_suffix('h') {
        num.trim()
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(3600))
            .map(Duration::from_secs)
    } else {
        s.parse::<u64>().ok().map(Duration::from_secs)
    }
}

/// Parse `N/duration` or shorthand `N/min`, `N/sec`, `N/hour`.
/// Examples : `1/min`, `5/30s`, `10/hour`, `1/sec`.
fn parse_throttle(s: &str) -> Option<Throttle> {
    let (num_str, dur_str) = s.split_once('/')?;
    let max: u32 = num_str.trim().parse().ok()?;
    if max == 0 {
        return None;
    }
    let dur_str = dur_str.trim();
    let per = match dur_str {
        "sec" | "s" => Duration::from_secs(1),
        "min" | "m" => Duration::from_secs(60),
        "hour" | "h" => Duration::from_secs(3600),
        other => parse_duration(other)?,
    };
    if per.is_zero() {
        return None;
    }
    Some(Throttle { max, per })
}

fn parse_string_literal(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut out = String::new();
    let mut chars = s[1..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => return None,
            },
            other => out.push(other),
        }
    }
    None
}

// =====================================================================
// Action lines
// =====================================================================

fn parse_action(s: &str) -> Result<Action, String> {
    let s = s.trim();
    let (kw, rest) = match s.split_once(char::is_whitespace) {
        Some((k, r)) => (k, r.trim()),
        None => (s, ""),
    };
    match kw {
        "log" => Ok(Action::Log),
        "alert" => {
            let msg =
                parse_string_literal(rest).unwrap_or_else(|| rest.trim_matches('"').to_string());
            Ok(Action::Alert(msg))
        }
        "kill" | "killProcess" | "kill_process" => Ok(Action::KillProcess),
        other => Err(format!("unknown action '{}'", other)),
    }
}

// =====================================================================
// Expression tokenizer + recursive-descent parser
// =====================================================================

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Path(String),
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Op(CmpOp),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

fn tokenize(s: &str) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        let c = bytes[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                out.push(Token::LParen);
                i += 1;
            }
            ')' => {
                out.push(Token::RParen);
                i += 1;
            }
            '&' => {
                if i + 1 < n && bytes[i + 1] == b'&' {
                    out.push(Token::And);
                    i += 2;
                } else {
                    return Err("expected '&&'".into());
                }
            }
            '|' => {
                if i + 1 < n && bytes[i + 1] == b'|' {
                    i += 2;
                } else {
                    i += 1;
                }
                out.push(Token::Or);
            }
            '=' => {
                if i + 1 < n && bytes[i + 1] == b'=' {
                    out.push(Token::Op(CmpOp::Eq));
                    i += 2;
                } else {
                    return Err("expected '=='".into());
                }
            }
            '!' => {
                if i + 1 < n && bytes[i + 1] == b'=' {
                    out.push(Token::Op(CmpOp::Ne));
                    i += 2;
                } else {
                    out.push(Token::Not);
                    i += 1;
                }
            }
            '<' => {
                if i + 1 < n && bytes[i + 1] == b'=' {
                    out.push(Token::Op(CmpOp::Le));
                    i += 2;
                } else {
                    out.push(Token::Op(CmpOp::Lt));
                    i += 1;
                }
            }
            '>' => {
                if i + 1 < n && bytes[i + 1] == b'=' {
                    out.push(Token::Op(CmpOp::Ge));
                    i += 2;
                } else {
                    out.push(Token::Op(CmpOp::Gt));
                    i += 1;
                }
            }
            '"' => {
                let lit = parse_string_literal(&s[i..])
                    .ok_or_else(|| "unterminated string literal".to_string())?;
                let consumed = string_literal_len(&s[i..])
                    .ok_or_else(|| "unterminated string literal".to_string())?;
                i += consumed;
                out.push(Token::Str(lit));
            }
            '-' | '0'..='9' => {
                let start = i;
                if c == '-' {
                    i += 1;
                }
                let mut is_float = false;
                while i < n {
                    let d = bytes[i] as char;
                    if d.is_ascii_digit() {
                        i += 1;
                    } else if d == '.' {
                        is_float = true;
                        i += 1;
                    } else {
                        break;
                    }
                }
                let num = &s[start..i];
                if is_float {
                    out.push(Token::Float(
                        num.parse::<f64>()
                            .map_err(|_| format!("bad float '{}'", num))?,
                    ));
                } else {
                    out.push(Token::Int(
                        num.parse::<i64>()
                            .map_err(|_| format!("bad int '{}'", num))?,
                    ));
                }
            }
            _ if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < n {
                    let d = bytes[i] as char;
                    if d.is_ascii_alphanumeric() || d == '_' || d == '.' {
                        i += 1;
                    } else {
                        break;
                    }
                }
                let word = &s[start..i];
                match word {
                    "contains" => out.push(Token::Op(CmpOp::Contains)),
                    "startsWith" => out.push(Token::Op(CmpOp::StartsWith)),
                    "true" => out.push(Token::Bool(true)),
                    "false" => out.push(Token::Bool(false)),
                    _ => out.push(Token::Path(word.to_string())),
                }
            }
            other => return Err(format!("unexpected character '{}'", other)),
        }
    }
    Ok(out)
}

fn string_literal_len(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn or_expr(&mut self) -> Result<Condition, String> {
        let mut left = self.and_expr()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.next();
            let right = self.and_expr()?;
            left = Condition::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and_expr(&mut self) -> Result<Condition, String> {
        let mut left = self.not_expr()?;
        while matches!(self.peek(), Some(Token::And)) {
            self.next();
            let right = self.not_expr()?;
            left = Condition::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn not_expr(&mut self) -> Result<Condition, String> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.next();
            let inner = self.not_expr()?;
            Ok(Condition::Not(Box::new(inner)))
        } else {
            self.atom()
        }
    }

    fn atom(&mut self) -> Result<Condition, String> {
        if matches!(self.peek(), Some(Token::LParen)) {
            self.next();
            let inner = self.or_expr()?;
            match self.next() {
                Some(Token::RParen) => Ok(inner),
                _ => Err("expected ')'".into()),
            }
        } else {
            self.comparison()
        }
    }

    fn comparison(&mut self) -> Result<Condition, String> {
        let path_str = match self.next() {
            Some(Token::Path(p)) => p,
            other => return Err(format!("expected field path, got {:?}", other)),
        };
        let path = FieldPath::parse(&path_str)
            .ok_or_else(|| format!("invalid field path '{}'", path_str))?;
        let op = match self.next() {
            Some(Token::Op(op)) => op,
            other => return Err(format!("expected comparison operator, got {:?}", other)),
        };
        let value = match self.next() {
            Some(Token::Int(v)) => RuleValue::Int(v),
            Some(Token::Float(v)) => RuleValue::Float(v),
            Some(Token::Str(v)) => RuleValue::Str(v),
            Some(Token::Bool(v)) => RuleValue::Bool(v),
            other => return Err(format!("expected value literal, got {:?}", other)),
        };
        Ok(Condition::Compare { path, op, value })
    }
}

fn parse_expression(s: &str) -> Result<Condition, String> {
    let tokens = tokenize(s)?;
    if tokens.is_empty() {
        return Err("empty expression".into());
    }
    let mut p = Parser { tokens, pos: 0 };
    let cond = p.or_expr()?;
    if p.pos != p.tokens.len() {
        return Err(format!("trailing tokens after expression in '{}'", s));
    }
    Ok(cond)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_of_two_compares() {
        let c = parse_expression(
            r#"kernel_callback.process_create.pid == 4688 && minifilter.file_create.name == "malware.exe""#,
        )
        .unwrap();
        match c {
            Condition::And(a, b) => {
                assert!(matches!(*a, Condition::Compare { .. }));
                assert!(matches!(*b, Condition::Compare { .. }));
            }
            _ => panic!("expected And(Compare, Compare), got {:?}", c),
        }
    }

    #[test]
    fn precedence_or_over_and() {
        let c = parse_expression("m.e.a == 1 || m.e.b == 2 && m.e.c == 3").unwrap();
        match c {
            Condition::Or(a, rest) => {
                assert!(matches!(*a, Condition::Compare { .. }));
                assert!(matches!(*rest, Condition::And(_, _)));
            }
            _ => panic!("expected Or(_, And(_,_)), got {:?}", c),
        }
    }

    #[test]
    fn parens_override_precedence() {
        let c = parse_expression("(m.e.a == 1 || m.e.b == 2) && m.e.c == 3").unwrap();
        assert!(matches!(c, Condition::And(_, _)));
        if let Condition::And(left, _) = c {
            assert!(matches!(*left, Condition::Or(_, _)));
        }
    }

    #[test]
    fn not_and_string_ops() {
        let c = parse_expression(r#"!m.e.path startsWith "C:\\Windows""#);
        assert!(c.is_ok(), "got {:?}", c);
        let c = parse_expression(r#"m.e.path contains "evil""#).unwrap();
        assert!(matches!(
            c,
            Condition::Compare {
                op: CmpOp::Contains,
                ..
            }
        ));
    }

    #[test]
    fn bool_and_float_and_neg_int() {
        assert!(parse_expression("m.e.flag == true").is_ok());
        assert!(parse_expression("m.e.ratio >= 0.5").is_ok());
        assert!(parse_expression("m.e.delta < -3").is_ok());
    }

    #[test]
    fn inline_comment_is_stripped() {
        // Bug #1 : `#` en milieu de ligne d'expression doit être ignoré
        // (pas vu comme un caractère inattendu par le tokenizer).
        let doc = r#"
- Detection:
  - R:
      - kernel_callback.process_create.pid == 4688  # commentaire fin de ligne
- Action:
  - R:
    - log
"#;
        let rules = parse_source(doc, DEFAULT_WINDOW).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].conditions.len(), 1);
    }

    #[test]
    fn hash_inside_string_is_not_a_comment() {
        // `#` dans une string littérale doit rester littéral.
        let doc = r#"
- Detection:
  - R:
      - kernel_callback.process_create.image_path contains "C:\\foo#bar.exe"
- Action:
  - R:
    - log
"#;
        let rules = parse_source(doc, DEFAULT_WINDOW).unwrap();
        assert_eq!(rules.len(), 1);
        match &rules[0].conditions[0] {
            Condition::Compare {
                value: RuleValue::Str(s),
                ..
            } => {
                assert_eq!(s, "C:\\foo#bar.exe");
            }
            other => panic!("expected Str literal preserving '#', got {:?}", other),
        }
    }

    #[test]
    fn duplicate_detection_group_is_rejected() {
        // Bug #2 : deux groupes Detection de même nom = erreur, pas merge.
        let doc = r#"
- Detection:
  - Same:
      - kernel_callback.process_create.pid == 1
  - Same:
      - kernel_callback.process_create.pid == 2
- Action:
  - Same:
    - log
"#;
        let err = parse_source(doc, DEFAULT_WINDOW).unwrap_err();
        assert!(
            err.contains("duplicate Detection group 'Same'"),
            "got: {err}"
        );
    }

    #[test]
    fn duplicate_action_group_is_rejected() {
        let doc = r#"
- Detection:
  - R:
      - kernel_callback.process_create.pid == 1
- Action:
  - R:
    - log
  - R:
    - alert "duplicated"
"#;
        let err = parse_source(doc, DEFAULT_WINDOW).unwrap_err();
        assert!(err.contains("duplicate Action group 'R'"), "got: {err}");
    }

    #[test]
    fn detection_without_action_is_rejected() {
        // Bug #3 : une rule sans actions ne sortirait rien — refuser au parse.
        let doc = r#"
- Detection:
  - Mute:
      - kernel_callback.process_create.pid == 1
- Action:
  - SomethingElse:
    - log
"#;
        let err = parse_source(doc, DEFAULT_WINDOW).unwrap_err();
        assert!(
            err.contains("Detection group but no matching Action group"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_duration_overflow_is_rejected() {
        // Bug #4 : `n * 60` doit retourner None plutôt que panic / wrap.
        // 2^63 minutes ≫ u64 / 60 → checked_mul retourne None.
        assert_eq!(parse_duration("9223372036854775807m"), None);
        assert_eq!(parse_duration("9223372036854775807h"), None);
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration("10s"), Some(Duration::from_secs(10)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("7"), Some(Duration::from_secs(7)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("abc"), None);
    }

    #[test]
    fn throttle_parsing() {
        assert_eq!(
            parse_throttle("1/min"),
            Some(Throttle {
                max: 1,
                per: Duration::from_secs(60)
            })
        );
        assert_eq!(
            parse_throttle("5/30s"),
            Some(Throttle {
                max: 5,
                per: Duration::from_secs(30)
            })
        );
        assert_eq!(
            parse_throttle("10/hour"),
            Some(Throttle {
                max: 10,
                per: Duration::from_secs(3600)
            })
        );
        assert_eq!(parse_throttle("0/min"), None); // zero max -> reject
        assert_eq!(parse_throttle("foo"), None);
    }

    #[test]
    fn full_inline_document() {
        let doc = r#"
- Detection:
  - Group1:
      window: 10s
      throttle: 1/min
      - kernel_callback.process_create.pid == 4688
      - kernel_callback.process_create.pid == 4689
- Action:
  - Group1:
    - log
    - alert "boom"
"#;
        let rules = parse_source(doc, DEFAULT_WINDOW).unwrap();
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.name, "Group1");
        assert_eq!(r.conditions.len(), 2);
        assert_eq!(r.window, Duration::from_secs(10));
        assert_eq!(
            r.throttle,
            Some(Throttle {
                max: 1,
                per: Duration::from_secs(60)
            })
        );
        assert_eq!(r.actions, vec![Action::Log, Action::Alert("boom".into())]);
    }

    #[test]
    fn include_merges_and_detects_cycles() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("waza_core_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let main = dir.join("main.waza");
        let net = dir.join("net.waza");

        let mut f = std::fs::File::create(&main).unwrap();
        writeln!(
            f,
            "- Detection:\n  - G1:\n      - m.e.a == 1\n      - include \"./net.waza\"\n- Action:\n  - G1:\n    - log"
        )
        .unwrap();
        let mut f = std::fs::File::create(&net).unwrap();
        writeln!(
            f,
            "- Detection:\n  - NetG:\n      - net.flow.port == 4444\n- Action:\n  - NetG:\n    - alert \"net\""
        )
        .unwrap();

        let rules = parse_file(&main).unwrap();
        let names: Vec<_> = rules.iter().map(|r| r.name.clone()).collect();
        assert!(names.contains(&"G1".to_string()));
        assert!(names.contains(&"NetG".to_string()));

        let mut f = std::fs::File::create(&net).unwrap();
        writeln!(
            f,
            "- Detection:\n  - NetG:\n      - include \"./main.waza\"\n- Action:\n  - NetG:\n    - log"
        )
        .unwrap();
        let err = parse_file(&main);
        assert!(
            err.is_err(),
            "expected circular include error, got {:?}",
            err
        );
        assert!(err.unwrap_err().contains("circular"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
