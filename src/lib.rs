//! `wedr-waza-core` — moteur de règles WazabiEDR, indépendant de l'agent.
//!
//! Ce crate ne contient *que* ce qui est purement logique : le DSL `.waza`
//! (parser → AST), le moteur d'évaluation (index inversé + fenêtres
//! glissantes + throttle) et le registre de schéma optionnel. Aucune I/O
//! kernel ou réseau, aucun thread d'arrière-plan : tout ça reste côté
//! agent (`WazabiEDR_Agent::detection`).
//!
//! Pourquoi ce découpage : le serveur (Python) doit pouvoir valider et
//! simuler des règles sans dupliquer le parser. Il appelle le binaire
//! `wedr-waza-check` (dans `WazabiEDR_Utils`) qui linke ce crate.

pub mod ast;
pub mod engine;
pub mod event;
pub mod parser;
pub mod schema;
