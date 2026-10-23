//! Shared helpers for the per-object discovery/description metadata that the
//! `vgi-lint` strict profile expects on **every** function and table:
//! - `vgi.title` (VGI124) — human-friendly display name
//! - `vgi.doc_llm` (VGI112) — concise prose aimed at LLMs
//! - `vgi.doc_md` (VGI113) — short Markdown description
//! - `vgi.keywords` (VGI126/VGI138) — a JSON array of search terms/synonyms
//!
//! Per-object `vgi.source_url` is intentionally NOT emitted here: it belongs on
//! the catalog object only (VGI139).

/// Encode comma-separated keywords as the JSON array `vgi.keywords` requires.
pub fn keywords_json(keywords: &str) -> String {
    let items: Vec<String> = keywords
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(|k| {
            let escaped = k.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// One analyst task for the `vgi.agent_test_tasks` suite: the analyst-visible `name` + `prompt`.
/// Only this public half is published in the catalog tag; each task's grader
/// (`reference_sql` plus the `unordered` / `ignore_column_names` result-compare
/// policy) lives in `vgi-agent-tests.yaml` at the repo root, keyed by task name,
/// so the agent being graded never sees it (VGI416).
pub struct AgentTask {
    pub name: &'static str,
    pub prompt: &'static str,
}

/// Build the `vgi.agent_test_tasks` JSON value: the fixed suite of analyst tasks
/// that `vgi-lint simulate` runs. Only `name` + `prompt` are emitted; the grader
/// for each task is in `vgi-agent-tests.yaml`.
pub fn agent_test_tasks_json(tasks: &[AgentTask]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = tasks
        .iter()
        .map(|t| {
            format!(
                "{{\"name\":\"{}\",\"prompt\":\"{}\"}}",
                esc(t.name),
                esc(t.prompt),
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build a `vgi.example_queries` described-example list — the JSON array of
/// `{"description": ..., "sql": ...}` objects the linter (VGI515) requires so
/// every example carries a human-readable description. The native
/// `duckdb_functions().examples` carrier drops descriptions, so a function that
/// wants described examples must publish them through this tag; when the same
/// SQL also appears as a native `FunctionExample`, the linter dedups the two
/// (whitespace/case-insensitive) into the described one.
pub fn example_queries_json(examples: &[(&str, &str)]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = examples
        .iter()
        .map(|(desc, sql)| {
            format!(
                "{{\"description\":\"{}\",\"sql\":\"{}\"}}",
                esc(desc),
                esc(sql)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build the standard per-object discovery/description tags, including the
/// `vgi.category` (VGI413) that names one of the schema's `vgi.categories`.
/// Per-object `vgi.source_url` is intentionally NOT emitted (VGI139).
pub fn object_tags(
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
    category: &str,
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), description_llm.to_string()),
        ("vgi.doc_md".to_string(), description_md.to_string()),
        ("vgi.keywords".to_string(), keywords_json(keywords)),
        ("vgi.category".to_string(), category.to_string()),
    ]
}
