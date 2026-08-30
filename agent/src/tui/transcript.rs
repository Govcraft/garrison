//! The conversation, and the unfinished tail of it.
//!
//! Owns exactly one thing: the part of the agent's reply that has arrived but
//! is not yet a complete line. Complete lines are not owned at all — they go
//! straight into the terminal's scrollback, where they belong to the terminal
//! and can never be redrawn, which is what makes them cheap.
//!
//! Because this actor owns its own region it can commit a line the moment it
//! is finished, whoever sent it. A message the user types while the agent is
//! working appears in the transcript immediately, in its place in time, rather
//! than waiting for the turn to end.

use super::message::{
    AgentChunk, AgentFinished, CommitHistory, Note, Region, RegionRendered, Wire,
};
use acton_reactive::prelude::*;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// The type every handler returns.
type FutureBox = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync + 'static>>;

/// The most rows of unfinished reply shown above the composer.
///
/// The tail is redrawn every frame, so it is bounded; everything older has
/// already been committed and is scrollable in the terminal.
const MAX_TAIL_ROWS: usize = 6;

/// The part of the reply that is not a complete line yet.
#[acton_actor]
pub struct Transcript {
    /// Text received since the last newline.
    tail: String,
    /// Where finished rows and rendered rows go.
    compositor: Option<ActorHandle>,
}

impl Transcript {
    /// Builds and starts the transcript.
    pub async fn start(runtime: &mut ActorRuntime) -> ActorHandle {
        let mut builder = runtime.new_actor::<Self>();
        configure(&mut builder);
        builder.start().await
    }

    /// Takes in a chunk, returning the lines that are now complete.
    ///
    /// A chunk may end anywhere — mid-word, mid-line, mid-sentence — so only
    /// text up to the last newline is finished. Holding the rest back is what
    /// keeps a half-written line out of the terminal's scrollback, where it
    /// could never be corrected.
    pub fn absorb(&mut self, text: &str) -> Vec<Line<'static>> {
        self.tail.push_str(text);

        let Some(last) = self.tail.rfind('\n') else {
            return Vec::new();
        };

        let complete: String = self.tail.drain(..=last).collect();

        complete
            .strip_suffix('\n')
            .unwrap_or(&complete)
            .split('\n')
            .map(|line| agent_line(line.to_string()))
            .collect()
    }

    /// Finishes the reply, returning whatever was still held back.
    pub fn flush(&mut self) -> Vec<Line<'static>> {
        if self.tail.trim().is_empty() {
            self.tail.clear();
            return Vec::new();
        }

        let remaining = std::mem::take(&mut self.tail);
        vec![agent_line(remaining)]
    }

    /// The rows of the tail currently shown above the composer.
    #[must_use]
    pub fn render(&self) -> RegionRendered {
        if self.tail.is_empty() {
            return RegionRendered::empty(Region::Tail);
        }

        let rows: Vec<Line<'static>> = self
            .tail
            .split('\n')
            .rev()
            .take(MAX_TAIL_ROWS)
            .map(|line| agent_line(line.to_string()))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        RegionRendered::showing(Region::Tail, rows)
    }
}

/// One line of the agent's own voice.
#[must_use]
pub fn agent_line(text: String) -> Line<'static> {
    Line::from(Span::raw(text))
}

/// One line of the user's own voice, as it appears in the transcript.
#[must_use]
pub fn user_line(text: String) -> Line<'static> {
    Line::from(vec![
        Span::styled("› ".to_string(), Style::default().fg(Color::LightBlue)),
        Span::styled(
            text,
            Style::default()
                .fg(Color::LightBlue)
                .add_modifier(Modifier::BOLD),
        ),
    ])
}

/// A line reporting something that went wrong.
#[must_use]
pub fn error_line(text: String) -> Line<'static> {
    Line::from(vec![
        Span::styled("✗ ".to_string(), Style::default().fg(Color::LightRed)),
        Span::styled(text, Style::default().fg(Color::LightRed)),
    ])
}

/// A line reporting something the interface did, rather than the model.
#[must_use]
pub fn notice_line(text: String) -> Line<'static> {
    Line::from(Span::styled(text, Style::default().fg(Color::DarkGray)))
}

/// A line reporting a tool call that finished.
#[must_use]
pub fn tool_line(title: String, succeeded: bool) -> Line<'static> {
    let (mark, status, color) = if succeeded {
        ("✓ ", "ok: ", Color::LightGreen)
    } else {
        ("✗ ", "failed: ", Color::LightRed)
    };

    Line::from(vec![
        Span::styled(mark.to_string(), Style::default().fg(color)),
        Span::styled(status.to_string(), Style::default().fg(color)),
        Span::styled(title, Style::default().fg(Color::Gray)),
    ])
}

/// Wires every handler.
fn configure(builder: &mut ManagedActor<Idle, Transcript>) {
    builder.mutate_on::<Wire>(|actor, context| {
        actor.model.compositor = Some(context.message().compositor.clone());
        Reply::ready()
    });

    builder.mutate_on::<AgentChunk>(|actor, context| {
        let finished = actor.model.absorb(&context.message().text);
        emit(actor, finished)
    });

    builder.mutate_on::<AgentFinished>(|actor, _| {
        let remaining = actor.model.flush();
        emit(actor, remaining)
    });

    builder.mutate_on::<Note>(|actor, context| {
        // A note is already finished, so it goes straight to scrollback —
        // which is why a message typed mid-turn shows up at once.
        let lines = context.message().lines.clone();
        emit(actor, lines)
    });
}

/// Commits finished rows and repaints the tail.
fn emit(actor: &mut ManagedActor<Started, Transcript>, lines: Vec<Line<'static>>) -> FutureBox {
    let rendered = actor.model.render();
    let compositor = actor.model.compositor.clone();

    Reply::pending(async move {
        let Some(compositor) = compositor else {
            return;
        };
        if !lines.is_empty() {
            compositor.send(CommitHistory { lines }).await;
        }
        compositor.send(rendered).await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(line: &Line<'static>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    fn texts(lines: &[Line<'static>]) -> Vec<String> {
        lines.iter().map(text).collect()
    }

    #[test]
    fn a_chunk_without_a_newline_finishes_nothing() {
        let mut transcript = Transcript::default();
        assert!(transcript.absorb("half a ").is_empty());
        assert_eq!(transcript.tail, "half a ");
    }

    #[test]
    fn a_newline_finishes_the_line_before_it_and_keeps_the_rest() {
        let mut transcript = Transcript::default();
        transcript.absorb("first ");
        let finished = transcript.absorb("line\nsecond");

        assert_eq!(texts(&finished), vec!["first line".to_string()]);
        assert_eq!(transcript.tail, "second");
    }

    #[test]
    fn several_newlines_in_one_chunk_finish_several_lines() {
        let mut transcript = Transcript::default();
        let finished = transcript.absorb("one\ntwo\nthree");

        assert_eq!(texts(&finished), vec!["one".to_string(), "two".to_string()]);
        assert_eq!(transcript.tail, "three");
    }

    #[test]
    fn a_blank_line_is_preserved_rather_than_collapsed() {
        let mut transcript = Transcript::default();
        let finished = transcript.absorb("one\n\ntwo\n");

        assert_eq!(
            texts(&finished),
            vec!["one".to_string(), String::new(), "two".to_string()]
        );
    }

    #[test]
    fn flushing_emits_the_held_back_tail_exactly_once() {
        let mut transcript = Transcript::default();
        transcript.absorb("trailing");

        assert_eq!(texts(&transcript.flush()), vec!["trailing".to_string()]);
        assert!(transcript.flush().is_empty());
    }

    #[test]
    fn flushing_whitespace_emits_nothing() {
        let mut transcript = Transcript::default();
        transcript.absorb("done\n   ");

        assert!(transcript.flush().is_empty());
        assert!(transcript.tail.is_empty());
    }

    #[test]
    fn the_tail_region_is_empty_between_replies() {
        assert!(Transcript::default().render().lines.is_empty());
    }

    #[test]
    fn a_long_tail_shows_only_its_last_rows() {
        let mut transcript = Transcript::default();
        transcript.absorb("a\nb\nc\n");
        transcript.tail = (1..=10)
            .map(|n| format!("row{n}"))
            .collect::<Vec<_>>()
            .join("\n");

        let rendered = transcript.render();
        assert_eq!(rendered.lines.len(), MAX_TAIL_ROWS);
        assert_eq!(text(&rendered.lines[0]), "row5");
        assert_eq!(text(rendered.lines.last().expect("rows")), "row10");
    }

    #[test]
    fn tool_results_state_their_outcome_in_words() {
        assert_eq!(text(&tool_line("bash".to_string(), true)), "✓ ok: bash");
        assert_eq!(
            text(&tool_line("bash".to_string(), false)),
            "✗ failed: bash"
        );
    }
}
