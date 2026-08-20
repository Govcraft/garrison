//! The four LSP capabilities as tools the model can call.
//!
//! `lsp_diagnostics`, `lsp_hover`, `lsp_definition`, and `lsp_references` —
//! all read-only, all installed per prompt the way [`crate::patch`] installs
//! `apply_patch`, and all routed to a language server by the file's
//! extension. Every executor follows the same shape: validate the path
//! against the session root, read the file from disk (disk is truth — the
//! agent's own edits land there), push the content to the server, ask, and
//! format the answer as compact text a model can act on.
//!
//! # Positions
//!
//! The model speaks 1-based lines and columns, because that is what every
//! compiler error it has ever read speaks. LSP speaks 0-based lines and
//! columns counted in a negotiated encoding. The conversion happens here,
//! using the file content the executor already read — which is what makes
//! UTF-16 column arithmetic possible at all.

use super::actor::{
    AwaitDiagnostics, LspOutcome, ReadyState, SendRequest, SyncDocument, WaitReady,
};
use super::LspRegistry;
use acton_ai::prompt::PromptBuilder;
use acton_ai::tools::{ToolDefinition, ToolError};
use acton_reactive::prelude::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// How many locations a definition or references answer will list.
const MAX_LOCATIONS: usize = 50;

/// How many diagnostics a diagnostics answer will list.
const MAX_DIAGNOSTICS: usize = 100;

/// Adds the LSP tools to a prompt, when any server is configured.
#[must_use]
pub fn install(
    builder: PromptBuilder,
    registry: Arc<LspRegistry>,
    root: Arc<PathBuf>,
) -> PromptBuilder {
    if registry.is_empty() {
        return builder;
    }
    let builder = install_one(builder, &registry, &root, Query::Diagnostics);
    let builder = install_one(builder, &registry, &root, Query::Hover);
    let builder = install_one(builder, &registry, &root, Query::Definition);
    install_one(builder, &registry, &root, Query::References)
}

/// The four tools, as data rather than four near-identical functions.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Query {
    Diagnostics,
    Hover,
    Definition,
    References,
}

impl Query {
    fn name(self) -> &'static str {
        match self {
            Self::Diagnostics => "lsp_diagnostics",
            Self::Hover => "lsp_hover",
            Self::Definition => "lsp_definition",
            Self::References => "lsp_references",
        }
    }

    fn takes_position(self) -> bool {
        !matches!(self, Self::Diagnostics)
    }

    fn description(self) -> &'static str {
        match self {
            Self::Diagnostics => {
                "Get compiler/linter diagnostics for a source file from the language server. \
                 Fast — no build is run. Use after editing a file to check it still compiles."
            }
            Self::Hover => {
                "Get type and documentation info for the symbol at a position in a source file, \
                 from the language server."
            }
            Self::Definition => {
                "Find where the symbol at a position in a source file is defined. Returns \
                 file:line:column locations."
            }
            Self::References => {
                "Find every reference to the symbol at a position in a source file. Returns \
                 file:line:column locations, capped at 50."
            }
        }
    }

    fn schema(self) -> Value {
        let mut properties = json!({
            "path": {
                "type": "string",
                "description": "The source file, relative to the project root.",
            },
        });
        let mut required = vec!["path"];
        if self.takes_position() {
            properties["line"] = json!({
                "type": "integer",
                "description": "1-based line number of the symbol.",
            });
            properties["column"] = json!({
                "type": "integer",
                "description": "1-based column number of the symbol.",
            });
            required.push("line");
            required.push("column");
        }
        json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false,
        })
    }

    fn definition(self) -> ToolDefinition {
        ToolDefinition {
            // Read-only queries: re-running one after a crash changes nothing.
            idempotent: true,
            name: self.name().to_string(),
            description: self.description().to_string(),
            input_schema: self.schema(),
        }
    }
}

fn install_one(
    builder: PromptBuilder,
    registry: &Arc<LspRegistry>,
    root: &Arc<PathBuf>,
    query: Query,
) -> PromptBuilder {
    let registry = Arc::clone(registry);
    let root = Arc::clone(root);
    builder.with_tool(query.definition(), move |arguments| {
        let registry = Arc::clone(&registry);
        let root = Arc::clone(&root);
        async move { run(query, &arguments, &registry, &root).await }
    })
}

/// One tool call, end to end.
async fn run(
    query: Query,
    arguments: &Value,
    registry: &LspRegistry,
    root: &Path,
) -> Result<Value, ToolError> {
    let name = query.name();
    let path = arguments
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| ToolError::validation_failed(name, "the 'path' argument is required"))?;

    let absolute =
        resolve_inside(root, path).map_err(|reason| ToolError::validation_failed(name, reason))?;
    let server = registry.for_path(&absolute).ok_or_else(|| {
        ToolError::execution_failed(
            name,
            format!(
                "no language server is configured for '{path}'; configured extensions: {}",
                registry.known_extensions().join(", ")
            ),
        )
    })?;

    let content = tokio::fs::read_to_string(&absolute)
        .await
        .map_err(|error| {
            ToolError::execution_failed(name, format!("cannot read '{path}': {error}"))
        })?;

    let ready: ReadyState = server
        .handle
        .ask_with_timeout(WaitReady, server.timeout)
        .await
        .map_err(|error| ToolError::execution_failed(name, format!("language server: {error}")))?;
    if !ready.ready {
        return Err(ToolError::execution_failed(
            name,
            ready
                .failed
                .unwrap_or_else(|| "language server is not ready".to_string()),
        ));
    }

    let uri = file_uri(&absolute).map_err(|reason| ToolError::execution_failed(name, reason))?;
    let synced: LspOutcome = server
        .handle
        .ask_with_timeout(
            SyncDocument {
                uri: uri.clone(),
                language_id: server.language_id.clone(),
                content: content.clone(),
            },
            server.timeout,
        )
        .await
        .map_err(|error| ToolError::execution_failed(name, format!("language server: {error}")))?;
    synced
        .result
        .map_err(|reason| ToolError::execution_failed(name, reason))?;

    let answer = match query {
        Query::Diagnostics => ask(server, AwaitDiagnostics { uri }, name).await?,
        _ => {
            let position = position_arguments(arguments, &content, ready.utf8_positions)
                .map_err(|reason| ToolError::validation_failed(name, reason))?;
            let method = match query {
                Query::Hover => "textDocument/hover",
                Query::Definition => "textDocument/definition",
                Query::References => "textDocument/references",
                Query::Diagnostics => unreachable!("handled above"),
            };
            let mut params = json!({
                "textDocument": { "uri": uri },
                "position": position,
            });
            if query == Query::References {
                params["context"] = json!({ "includeDeclaration": true });
            }
            ask(
                server,
                SendRequest {
                    method: method.to_string(),
                    params,
                },
                name,
            )
            .await?
        }
    };

    Ok(match query {
        Query::Diagnostics => format_diagnostics(&answer),
        Query::Hover => format_hover(&answer),
        Query::Definition | Query::References => format_locations(&answer, root),
    })
}

/// Asks the server actor and unwraps both layers of failure.
async fn ask<M>(server: &super::LspServerEntry, message: M, name: &str) -> Result<Value, ToolError>
where
    M: acton_reactive::prelude::Request<Response = LspOutcome> + Send + Sync + 'static,
{
    let outcome: LspOutcome = server
        .handle
        .ask_with_timeout(message, server.timeout)
        .await
        .map_err(|error| ToolError::execution_failed(name, format!("language server: {error}")))?;
    outcome
        .result
        .map_err(|reason| ToolError::execution_failed(name, reason))
}

/// Resolves a model-supplied path against the session root, refusing escapes.
///
/// Pure on its inputs; the filesystem is consulted only through the lexical
/// components, so a path that does not exist yet still resolves — and still
/// cannot escape.
fn resolve_inside(root: &Path, path: &str) -> Result<PathBuf, String> {
    let joined = root.join(path);
    let mut resolved = PathBuf::new();
    for component in joined.components() {
        match component {
            std::path::Component::ParentDir => {
                if !resolved.pop() {
                    return Err(format!("'{path}' escapes the project root"));
                }
            }
            std::path::Component::CurDir => {}
            other => resolved.push(other),
        }
    }
    if resolved.starts_with(root) {
        Ok(resolved)
    } else {
        Err(format!("'{path}' escapes the project root"))
    }
}

/// A `file://` URI for an absolute path.
fn file_uri(path: &Path) -> Result<String, String> {
    url::Url::from_file_path(path)
        .map(|url| url.to_string())
        .map_err(|()| format!("'{}' cannot be a file URI", path.display()))
}

/// Reads and converts the `line`/`column` arguments. Pure.
fn position_arguments(
    arguments: &Value,
    content: &str,
    utf8_positions: bool,
) -> Result<Value, String> {
    let line = arguments
        .get("line")
        .and_then(Value::as_u64)
        .ok_or("the 'line' argument is required and must be a positive integer")?;
    let column = arguments
        .get("column")
        .and_then(Value::as_u64)
        .ok_or("the 'column' argument is required and must be a positive integer")?;
    if line == 0 || column == 0 {
        return Err("'line' and 'column' are 1-based".to_string());
    }
    let character = lsp_character(content, line, column, utf8_positions)
        .ok_or_else(|| format!("line {line} is past the end of the file"))?;
    Ok(json!({ "line": line - 1, "character": character }))
}

/// Converts a 1-based character column to the server's encoding. Pure.
///
/// Columns count characters as a person sees them; the wire counts bytes
/// (UTF-8 servers) or UTF-16 code units. A column past the end of the line
/// clamps to the line's end, which servers treat as "the end of the line" —
/// more useful than an error for a model that miscounted by one.
fn lsp_character(content: &str, line: u64, column: u64, utf8: bool) -> Option<u64> {
    let line_index = usize::try_from(line).ok()? - 1;
    let text = content.lines().nth(line_index)?;
    let mut units: u64 = 0;
    for (seen, character) in text.chars().enumerate() {
        if seen as u64 == column - 1 {
            return Some(units);
        }
        units += if utf8 {
            character.len_utf8() as u64
        } else {
            character.len_utf16() as u64
        };
    }
    Some(units)
}

/// Renders a diagnostics answer — pull report or published params. Pure.
fn format_diagnostics(answer: &Value) -> Value {
    // Pull answers carry { kind, items }; published params carry
    // { uri, diagnostics }. Either way it is a list of diagnostics.
    let items = answer
        .get("items")
        .or_else(|| answer.get("diagnostics"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let listed: Vec<String> = items
        .iter()
        .take(MAX_DIAGNOSTICS)
        .filter_map(|item| {
            let diagnostic: lsp_types::Diagnostic = serde_json::from_value(item.clone()).ok()?;
            let severity = match diagnostic.severity {
                Some(lsp_types::DiagnosticSeverity::ERROR) => "error",
                Some(lsp_types::DiagnosticSeverity::WARNING) => "warning",
                Some(lsp_types::DiagnosticSeverity::INFORMATION) => "info",
                Some(lsp_types::DiagnosticSeverity::HINT) => "hint",
                _ => "note",
            };
            Some(format!(
                "{severity} at {}:{}: {}",
                diagnostic.range.start.line + 1,
                diagnostic.range.start.character + 1,
                diagnostic.message.trim().replace('\n', " "),
            ))
        })
        .collect();

    let omitted = items.len().saturating_sub(MAX_DIAGNOSTICS);
    json!({
        "count": items.len(),
        "diagnostics": listed,
        "omitted": omitted,
    })
}

/// Renders a hover answer. Pure.
fn format_hover(answer: &Value) -> Value {
    if answer.is_null() {
        return json!({ "found": false });
    }
    let Ok(hover) = serde_json::from_value::<lsp_types::Hover>(answer.clone()) else {
        return json!({ "found": false });
    };
    let text = match hover.contents {
        lsp_types::HoverContents::Markup(markup) => markup.value,
        lsp_types::HoverContents::Scalar(marked) => marked_string(marked),
        lsp_types::HoverContents::Array(list) => list
            .into_iter()
            .map(marked_string)
            .collect::<Vec<_>>()
            .join("\n\n"),
    };
    json!({ "found": true, "contents": text })
}

fn marked_string(marked: lsp_types::MarkedString) -> String {
    match marked {
        lsp_types::MarkedString::String(text) => text,
        lsp_types::MarkedString::LanguageString(code) => code.value,
    }
}

/// Renders a definition or references answer. Pure.
///
/// The wire allows a single `Location`, a list of them, or a list of
/// `LocationLink`s; all three flatten to `file:line:column`, with paths
/// relative to the root when they are under it.
fn format_locations(answer: &Value, root: &Path) -> Value {
    let mut locations: Vec<(String, u64, u64)> = Vec::new();
    collect_locations(answer, &mut locations);

    let listed: Vec<String> = locations
        .iter()
        .take(MAX_LOCATIONS)
        .map(|(uri, line, character)| {
            format!("{}:{}:{}", display_path(uri, root), line + 1, character + 1)
        })
        .collect();
    let omitted = locations.len().saturating_sub(MAX_LOCATIONS);
    json!({
        "count": locations.len(),
        "locations": listed,
        "omitted": omitted,
    })
}

fn collect_locations(answer: &Value, into: &mut Vec<(String, u64, u64)>) {
    match answer {
        Value::Array(items) => {
            for item in items {
                collect_locations(item, into);
            }
        }
        Value::Object(_) => {
            // A LocationLink names its target differently from a Location.
            let (uri, range) = if answer.get("targetUri").is_some() {
                (&answer["targetUri"], &answer["targetRange"])
            } else {
                (&answer["uri"], &answer["range"])
            };
            if let (Some(uri), Some(line), Some(character)) = (
                uri.as_str(),
                range["start"]["line"].as_u64(),
                range["start"]["character"].as_u64(),
            ) {
                into.push((uri.to_string(), line, character));
            }
        }
        _ => {}
    }
}

/// A URI as a path the model can hand back to other tools. Pure.
fn display_path(uri: &str, root: &Path) -> String {
    let Ok(url) = url::Url::parse(uri) else {
        return uri.to_string();
    };
    let Ok(path) = url.to_file_path() else {
        return uri.to_string();
    };
    match path.strip_prefix(root) {
        Ok(relative) => relative.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

/// A default ask timeout when the config names none.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_cannot_escape_the_root() {
        let root = Path::new("/work/project");
        assert!(resolve_inside(root, "src/main.rs").is_ok());
        assert!(resolve_inside(root, "../secrets").is_err());
        assert!(resolve_inside(root, "src/../../other").is_err());
        assert_eq!(
            resolve_inside(root, "src/./a/../main.rs").expect("must resolve"),
            PathBuf::from("/work/project/src/main.rs"),
        );
    }

    #[test]
    fn columns_convert_per_encoding() {
        // 'é' is 2 bytes in UTF-8, 1 unit in UTF-16.
        let content = "let é = 1;\n";
        assert_eq!(lsp_character(content, 1, 5, true), Some(4));
        assert_eq!(lsp_character(content, 1, 6, true), Some(6));
        assert_eq!(lsp_character(content, 1, 6, false), Some(5));
    }

    #[test]
    fn a_column_past_the_line_end_clamps() {
        assert_eq!(lsp_character("ab\n", 1, 99, true), Some(2));
    }

    #[test]
    fn a_line_past_the_file_end_is_refused() {
        assert_eq!(lsp_character("ab\n", 5, 1, true), None);
    }

    #[test]
    fn diagnostics_format_from_pull_and_publish_shapes() {
        let diagnostic = json!({
            "range": { "start": { "line": 4, "character": 2 },
                        "end": { "line": 4, "character": 9 } },
            "severity": 1,
            "message": "mismatched types\nexpected `u32`",
        });
        let pull = format_diagnostics(&json!({ "kind": "full", "items": [diagnostic] }));
        let publish =
            format_diagnostics(&json!({ "uri": "file:///x", "diagnostics": [diagnostic] }));
        assert_eq!(pull, publish);
        assert_eq!(pull["count"], 1);
        assert_eq!(
            pull["diagnostics"][0],
            "error at 5:3: mismatched types expected `u32`"
        );
    }

    #[test]
    fn hover_formats_markup_and_absence() {
        let markup = json!({
            "contents": { "kind": "markdown", "value": "```rust\nfn main()\n```" }
        });
        assert_eq!(format_hover(&markup)["contents"], "```rust\nfn main()\n```");
        assert_eq!(format_hover(&Value::Null)["found"], false);
    }

    #[test]
    fn locations_flatten_singles_lists_and_links() {
        let root = Path::new("/work");
        let single = json!({
            "uri": "file:///work/src/lib.rs",
            "range": { "start": { "line": 9, "character": 4 },
                        "end": { "line": 9, "character": 8 } },
        });
        let link = json!({
            "targetUri": "file:///elsewhere/dep.rs",
            "targetRange": { "start": { "line": 0, "character": 0 },
                              "end": { "line": 0, "character": 1 } },
        });
        let formatted = format_locations(&json!([single, link]), root);
        assert_eq!(formatted["locations"][0], "src/lib.rs:10:5");
        assert_eq!(formatted["locations"][1], "/elsewhere/dep.rs:1:1");
    }
}
