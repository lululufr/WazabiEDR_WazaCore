//! Schema registry — optional, validation-only.
//!
//! The rule engine matches fields purely dynamically and does **not**
//! need a schema to function. This registry exists only so the agent
//! (or the CLI / server) can *validate* the `FieldPath`s referenced by
//! loaded `.waza` rules and emit a warning on a likely typo — fail-fast
//! but soft (a missing schema never blocks startup or matching).

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDeclaration {
    pub module: String,
    pub events: Vec<EventSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSchema {
    pub name: String,
    pub fields: Vec<FieldSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSchema {
    pub name: String,
    pub field_type: FieldType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Int,
    Float,
    String,
    Bool,
}

pub struct SchemaRegistry {
    inner: RwLock<HashMap<String, HashMap<String, HashMap<String, FieldType>>>>,
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, decl: SchemaDeclaration) {
        let mut event_map = HashMap::new();
        for event in decl.events {
            let field_map: HashMap<String, FieldType> = event
                .fields
                .into_iter()
                .map(|f| (f.name, f.field_type))
                .collect();
            event_map.insert(event.name, field_map);
        }
        match self.inner.write() {
            Ok(mut g) => {
                g.insert(decl.module.clone(), event_map);
            }
            Err(p) => {
                p.into_inner().insert(decl.module.clone(), event_map);
            }
        }
    }

    pub fn register_all(&self, decls: Vec<SchemaDeclaration>) {
        for d in decls {
            self.register(d);
        }
    }

    pub fn is_empty(&self) -> bool {
        match self.inner.read() {
            Ok(g) => g.is_empty(),
            Err(p) => p.into_inner().is_empty(),
        }
    }

    pub fn validate_field(&self, module: &str, event_type: &str, field: &str) -> Option<FieldType> {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.get(module)?.get(event_type)?.get(field).cloned()
    }
}

/// Built-in schema for the kernel driver's events, mirroring what the
/// agent's `ipc::json` encoder produces. Kept here (rather than only in
/// a JSON file) so the CLI's `schema` command works without any external
/// resources. Plugins extend this dynamically at runtime via their own
/// schema declarations.
pub fn builtin_kernel_schema() -> SchemaDeclaration {
    use FieldType::*;
    let f = |name: &str, t: FieldType| FieldSchema {
        name: name.into(),
        field_type: t,
    };
    let e = |name: &str, fields: Vec<FieldSchema>| EventSchema {
        name: name.into(),
        fields,
    };
    SchemaDeclaration {
        module: "kernel_callback".into(),
        events: vec![
            e(
                "process_create",
                vec![
                    f("pid", Int),
                    f("parent_pid", Int),
                    f("creating_pid", Int),
                    f("image_path", String),
                ],
            ),
            e("process_terminate", vec![f("pid", Int)]),
            e(
                "module_load",
                vec![
                    f("pid", Int),
                    f("scope", String),
                    f("image_base", Int),
                    f("image_size", Int),
                    f("image_path", String),
                ],
            ),
            e(
                "registry_write",
                vec![
                    f("pid", Int),
                    f("op", String),
                    f("op_code", Int),
                    f("key_path", String),
                    f("value_name", String),
                    f("value_type", String),
                    f("data_size", Int),
                    f("data_preview_hex", String),
                    f("data_truncated", Bool),
                ],
            ),
            e(
                "thread_create",
                vec![
                    f("pid", Int),
                    f("tid", Int),
                    f("creating_pid", Int),
                    f("remote_injection", Bool),
                ],
            ),
            e("thread_exit", vec![f("pid", Int), f("tid", Int)]),
            e(
                "process_handle_access",
                vec![
                    f("source_pid", Int),
                    f("target_pid", Int),
                    f("desired_access", Int),
                    f("original_desired_access", Int),
                    f("op", String),
                ],
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SchemaDeclaration {
        SchemaDeclaration {
            module: "kernel_callback".into(),
            events: vec![EventSchema {
                name: "process_create".into(),
                fields: vec![
                    FieldSchema {
                        name: "pid".into(),
                        field_type: FieldType::Int,
                    },
                    FieldSchema {
                        name: "image_path".into(),
                        field_type: FieldType::String,
                    },
                ],
            }],
        }
    }

    #[test]
    fn register_and_validate() {
        let reg = SchemaRegistry::new();
        assert!(reg.is_empty());
        reg.register(sample());
        assert!(!reg.is_empty());
        assert_eq!(
            reg.validate_field("kernel_callback", "process_create", "pid"),
            Some(FieldType::Int)
        );
        assert_eq!(
            reg.validate_field("kernel_callback", "process_create", "image_path"),
            Some(FieldType::String)
        );
        assert_eq!(
            reg.validate_field("kernel_callback", "process_create", "nope"),
            None
        );
        assert_eq!(reg.validate_field("other", "x", "y"), None);
    }

    #[test]
    fn parse_from_json() {
        let json = r#"
        [
          { "module": "kernel_callback",
            "events": [
              { "name": "process_create",
                "fields": [ {"name":"pid","field_type":"int"} ] }
            ] }
        ]"#;
        let decls: Vec<SchemaDeclaration> = serde_json::from_str(json).unwrap();
        let reg = SchemaRegistry::new();
        reg.register_all(decls);
        assert_eq!(
            reg.validate_field("kernel_callback", "process_create", "pid"),
            Some(FieldType::Int)
        );
    }

    #[test]
    fn builtin_includes_process_create_pid() {
        let s = builtin_kernel_schema();
        assert_eq!(s.module, "kernel_callback");
        let pc = s.events.iter().find(|e| e.name == "process_create").unwrap();
        assert!(pc.fields.iter().any(|f| f.name == "pid"));
    }
}
