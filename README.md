# wedr-waza-core

Moteur de règles WazabiEDR — parser du DSL `.waza`, AST, évaluateur.

Ce crate est **indépendant de l'agent** : pas d'I/O kernel, pas de
réseau, pas de thread d'arrière-plan. Consommé par
[`WazabiEDR_Agent`](https://github.com/lululufr/WazabiEDR_Agent) (moteur
hot-reload sur les fichiers `.waza`) et
[`WazabiEDR_Utils`](https://github.com/lululufr/WazabiEDR_Utils) (binaire
`wedr-waza-check` : `validate` / `simulate` / `schema` sortie JSON).

Grammaire complète, exemples, limites connues :
[`WazabiEDR_Agent/doc/reference/waza-rules.md`](https://github.com/lululufr/WazabiEDR_Agent/blob/main/doc/reference/waza-rules.md).

## Modules

- `event` — représentation dynamique d'un évènement (`LogEvent`, `FieldValue`, opérateurs de comparaison).
- `ast` — types du DSL (`Rule`, `Condition`, `Action`, `Throttle`, `FieldPath`).
- `parser` — parser texte → `Vec<Rule>`, gère `include`, commentaires, corrélation par `window:` et anti-storm par `throttle:`.
- `engine` — index inversé + fenêtre glissante par règle + throttle gating.
- `schema` — registre de champs optionnel (validation soft des chemins).

## Usage

```rust
use wedr_waza_core::{parser, engine::RuleEngine, event::LogEvent};

let rules = parser::parse_source(r#"
- Detection:
  - HelloRule:
      - kernel_callback.process_create.pid > 0
- Action:
  - HelloRule:
    - log
"#, std::time::Duration::from_secs(5)).unwrap();

let engine = RuleEngine::new(rules);
// engine.process_event(&event) → Vec<(rule_name, actions)>
```

## Licence

MIT.
