//! Turning a cursor into a suggestion.
//!
//! Everything here is pure. Building the model's prompt and cleaning up what
//! it says back are the two places inline completion actually goes wrong, and
//! both are decided entirely by their inputs — so they are functions with unit
//! tests rather than steps buried in an async handler where the only way to
//! exercise them is to stand up a runtime and a model.
//!
//! # Why the model is asked for a raw continuation
//!
//! A chat-tuned model asked to "complete this code" will happily answer with a
//! fenced block, a restatement of the line the cursor sits on, and a sentence
//! explaining itself. All three are wrong at a cursor: the fence and the prose
//! are not code, and the restatement duplicates what the developer already
//! typed. [`SYSTEM_PROMPT`] asks for none of it and [`clean`] assumes it will
//! arrive anyway, because prompt instructions are a request and not a
//! guarantee.

use crate::protocol::acp::CompletionRequest;
use acton_ai::messages::Message;

/// How much of the text before the cursor the model is shown, in bytes.
///
/// The lines immediately above a cursor carry nearly all of the signal, and a
/// completion that has to wait on a whole file being tokenized is a completion
/// that arrives after the developer has already typed the line. This is the
/// latency budget expressed as a length.
pub const PREFIX_BUDGET: usize = 4_000;

/// How much of the text after the cursor the model is shown, in bytes.
///
/// Smaller than [`PREFIX_BUDGET`] because the suffix only has to answer "what
/// is this code building toward" — the closing brace, the next function, the
/// return type — which the first few lines settle.
pub const SUFFIX_BUDGET: usize = 1_000;

/// The marker standing in for the cursor in the text the model is given.
///
/// Spelled to be something no real source file contains, because a document
/// that happened to contain it would otherwise get a second cursor.
const CURSOR: &str = "<|garrison_cursor|>";

/// What the model is told it is doing.
pub const SYSTEM_PROMPT: &str = "\
You complete code at a cursor inside an editor. You will be shown a file with \
the cursor marked as <|garrison_cursor|>.

Reply with the exact text to insert at that marker and nothing else.

Rules:
- Output raw code. No markdown, no code fences, no backticks, no commentary.
- Do not repeat any code that already appears before the cursor.
- Do not repeat any code that already appears after the cursor.
- Continue the surrounding style, indentation, and naming exactly.
- Complete only what the cursor plainly calls for, usually the rest of the \
current line or a short block. Do not write an entire file.
- If nothing sensible goes at the cursor, reply with nothing at all.";

/// Keeps the last `budget` bytes of `text`, cut at a character boundary.
///
/// Truncating a prefix from the front is deliberate: the text nearest the
/// cursor is the text that matters, so an over-long prefix loses its
/// beginning rather than its end.
#[must_use]
pub fn tail(text: &str, budget: usize) -> &str {
    if text.len() <= budget {
        return text;
    }

    let mut start = text.len() - budget;
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

/// Keeps the first `budget` bytes of `text`, cut at a character boundary.
#[must_use]
pub fn head(text: &str, budget: usize) -> &str {
    if text.len() <= budget {
        return text;
    }

    let mut end = budget;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Builds the messages for one completion.
///
/// One user message, no history: a completion is a question about a cursor and
/// nothing else, and carrying conversation into it would make the same cursor
/// in the same file answer differently depending on what was discussed
/// earlier.
#[must_use]
pub fn messages(request: &CompletionRequest) -> Vec<Message> {
    let language = request
        .language_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .unwrap_or("plain text");

    let path = request
        .uri
        .as_deref()
        .filter(|uri| !uri.is_empty())
        .unwrap_or("untitled");

    let content = format!(
        "Language: {language}\nFile: {path}\n\n{}{CURSOR}{}",
        tail(&request.prefix, PREFIX_BUDGET),
        head(&request.suffix, SUFFIX_BUDGET),
    );

    vec![Message::user(content)]
}

/// Strips the wrappers a chat model puts around code it was asked not to wrap.
///
/// Handles the fenced block whether or not it carries a language tag, and
/// leaves anything that is not fenced alone. A fence that opens and never
/// closes is still unwrapped, because a truncated response is exactly when the
/// opening fence would otherwise survive into the buffer.
#[must_use]
fn unfence(text: &str) -> &str {
    let trimmed = text.trim();
    let Some(rest) = trimmed.strip_prefix("```") else {
        return text;
    };

    // The remainder of the opening fence's line is its language tag.
    let body = rest.find('\n').map_or("", |newline| &rest[newline + 1..]);

    match body.rfind("```") {
        Some(close) => &body[..close],
        None => body,
    }
}

/// Drops a leading repeat of what the developer already typed.
///
/// Models restate the current line surprisingly often. The overlap is measured
/// against the tail of the prefix, so `let x = ` followed by a suggestion of
/// `let x = compute();` inserts only `compute();`.
#[must_use]
fn strip_prefix_echo<'a>(completion: &'a str, prefix: &str) -> &'a str {
    // Longest first: a short overlap is far more likely to be a coincidence
    // than a real echo, and stripping a coincidence deletes real code.
    let mut overlap = completion.len().min(prefix.len());
    while overlap > 0 {
        if completion.is_char_boundary(overlap)
            && prefix.is_char_boundary(prefix.len() - overlap)
            && prefix.ends_with(&completion[..overlap])
        {
            return &completion[overlap..];
        }
        overlap -= 1;
    }
    completion
}

/// Drops a trailing repeat of what already follows the cursor.
///
/// The mirror of [`strip_prefix_echo`], and the reason a completion does not
/// leave a duplicated closing brace behind it.
#[must_use]
fn strip_suffix_echo<'a>(completion: &'a str, suffix: &str) -> &'a str {
    let trimmed_suffix = suffix.trim_start();
    if trimmed_suffix.is_empty() {
        return completion;
    }

    let mut overlap = completion.len().min(trimmed_suffix.len());
    while overlap > 0 {
        if completion.is_char_boundary(completion.len() - overlap)
            && trimmed_suffix.is_char_boundary(overlap)
            && completion[completion.len() - overlap..] == trimmed_suffix[..overlap]
        {
            return &completion[..completion.len() - overlap];
        }
        overlap -= 1;
    }
    completion
}

/// Turns what the model said into what the editor should insert.
///
/// Returns an empty string when nothing is left worth inserting, which the
/// caller reports as "no suggestion" rather than as a failure.
#[must_use]
pub fn clean(raw: &str, request: &CompletionRequest) -> String {
    let unfenced = unfence(raw);

    // Leading newlines are the model formatting its answer, not indentation:
    // real indentation is spaces or tabs and survives this.
    let body = unfenced.trim_start_matches(['\n', '\r']);

    // Both echoes are measured before any trailing whitespace is removed.
    // Trimming first would change the very bytes being compared against the
    // document, so a suggestion that exactly restated the prefix would no
    // longer match it and would survive as a duplicate.
    let body = strip_prefix_echo(body, &request.prefix);
    let body = strip_suffix_echo(body, &request.suffix);
    let body = body.trim_end();

    if body.trim().is_empty() {
        return String::new();
    }

    body.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(prefix: &str, suffix: &str) -> CompletionRequest {
        CompletionRequest::new(
            crate::protocol::acp::SessionId::new("thread_test"),
            prefix,
            suffix,
        )
        .uri("file:///src/main.rs")
        .language_id("rust")
    }

    #[test]
    fn a_short_prefix_is_kept_whole() {
        assert_eq!(tail("fn main() {", PREFIX_BUDGET), "fn main() {");
    }

    #[test]
    fn an_over_long_prefix_loses_its_beginning_not_its_end() {
        let text = "a".repeat(10) + "cursor";
        assert_eq!(tail(&text, 6), "cursor");
    }

    #[test]
    fn an_over_long_suffix_loses_its_end_not_its_beginning() {
        let text = "cursor".to_string() + &"a".repeat(10);
        assert_eq!(head(&text, 6), "cursor");
    }

    #[test]
    fn trimming_never_splits_a_character() {
        // Four bytes each, so every budget below lands mid-character.
        let text = "🚀🚀🚀";

        for budget in 1..text.len() {
            assert!(tail(text, budget).is_char_boundary(0));
            assert!(std::str::from_utf8(head(text, budget).as_bytes()).is_ok());
        }
    }

    #[test]
    fn the_cursor_is_marked_between_the_prefix_and_the_suffix() {
        let messages = messages(&request("let x = ", "\n}\n"));

        assert_eq!(messages.len(), 1);
        assert!(messages[0].content.contains(&format!("let x = {CURSOR}")));
    }

    #[test]
    fn the_language_and_file_are_named_for_the_model() {
        let messages = messages(&request("x", ""));

        assert!(messages[0].content.contains("Language: rust"));
        assert!(messages[0].content.contains("File: file:///src/main.rs"));
    }

    #[test]
    fn an_unknown_language_and_file_still_produce_a_usable_prompt() {
        let mut req = request("x", "");
        req.language_id = None;
        req.uri = None;

        let messages = messages(&req);

        assert!(messages[0].content.contains("Language: plain text"));
        assert!(messages[0].content.contains("File: untitled"));
    }

    #[test]
    fn a_fenced_block_is_unwrapped() {
        let cleaned = clean("```rust\ncompute();\n```", &request("let x = ", ""));

        assert_eq!(cleaned, "compute();");
    }

    #[test]
    fn a_fence_without_a_language_tag_is_unwrapped() {
        assert_eq!(
            clean("```\ncompute();\n```", &request("", "")),
            "compute();"
        );
    }

    #[test]
    fn an_unclosed_fence_is_still_unwrapped() {
        assert_eq!(clean("```rust\ncompute();", &request("", "")), "compute();");
    }

    #[test]
    fn unfenced_code_is_left_alone() {
        assert_eq!(clean("compute();", &request("", "")), "compute();");
    }

    #[test]
    fn a_restated_prefix_is_dropped() {
        let cleaned = clean("let x = compute();", &request("let x = ", ""));

        assert_eq!(cleaned, "compute();");
    }

    #[test]
    fn a_restated_suffix_is_dropped() {
        let cleaned = clean("compute();\n}", &request("let x = ", "\n}"));

        assert_eq!(cleaned, "compute();");
    }

    #[test]
    fn indentation_at_the_start_of_a_suggestion_survives() {
        let cleaned = clean("\n    inner();", &request("fn f() {", "\n}"));

        assert_eq!(cleaned, "    inner();");
    }

    #[test]
    fn a_model_declining_to_guess_produces_no_suggestion() {
        assert!(clean("   \n  ", &request("let x = ", "")).is_empty());
        assert!(clean("```\n\n```", &request("let x = ", "")).is_empty());
    }

    #[test]
    fn a_completion_that_is_entirely_an_echo_produces_nothing() {
        assert!(clean("let x = ", &request("let x = ", "")).is_empty());
    }
}
