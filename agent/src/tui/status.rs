//! What the agent is doing, and for how long.
//!
//! Owns the elapsed clock and the set of tool calls currently in flight, and
//! nothing else. It re-renders itself on a timer while a turn runs and goes
//! silent the moment one ends, so an idle interface costs no frames at all.

use super::message::{
    Region, RegionRendered, StatusTick, ToolEnded, ToolStarted, TurnEnded, TurnStarted, Wire,
};
use acton_reactive::prelude::*;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// The type every handler returns.
type FutureBox = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync + 'static>>;

/// How often the elapsed time and the spinner advance.
const TICK: Duration = Duration::from_millis(250);

/// The most tool calls listed under the status line before it summarizes.
const MAX_DETAIL_ROWS: usize = 3;

/// The spinner, one frame per tick.
const SPINNER: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];

/// The running turn, if there is one.
#[acton_actor]
pub struct Status {
    /// When the current turn began. `None` between turns.
    started: Option<Instant>,
    /// Tool calls in flight, by the agent's id for them.
    ///
    /// Ordered so the list does not reshuffle itself between frames.
    tools: BTreeMap<String, String>,
    /// Which spinner frame is showing.
    frame: usize,
    /// Where rendered rows go.
    compositor: Option<ActorHandle>,
}

impl Status {
    /// Builds and starts the status line.
    pub async fn start(runtime: &mut ActorRuntime) -> ActorHandle {
        let mut builder = runtime.new_actor::<Self>();
        configure(&mut builder);
        builder.start().await
    }

    /// The rows this region shows right now.
    #[must_use]
    pub fn render(&self) -> RegionRendered {
        let Some(started) = self.started else {
            return RegionRendered::empty(Region::Status);
        };

        RegionRendered::showing(
            Region::Status,
            summary(
                SPINNER[self.frame % SPINNER.len()],
                started.elapsed(),
                &self.tools,
            ),
        )
    }
}

/// Builds the status rows for a turn that has been running for `elapsed`.
///
/// Pure, so the wording and the truncation are testable without a clock.
#[must_use]
pub fn summary(
    spinner: &str,
    elapsed: Duration,
    tools: &BTreeMap<String, String>,
) -> Vec<Line<'static>> {
    let accent = Style::default().fg(Color::LightCyan);
    let muted = Style::default().fg(Color::DarkGray);

    let mut lines = vec![Line::from(vec![
        Span::styled(format!("{spinner} "), accent),
        Span::styled("Working".to_string(), accent.add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("  ({} · Esc to interrupt)", humanize(elapsed)),
            muted,
        ),
    ])];

    for title in tools.values().take(MAX_DETAIL_ROWS) {
        lines.push(Line::from(vec![
            Span::styled("  └ ".to_string(), muted),
            Span::styled(title.clone(), Style::default().fg(Color::Gray)),
        ]));
    }

    if tools.len() > MAX_DETAIL_ROWS {
        lines.push(Line::from(Span::styled(
            format!("  └ and {} more", tools.len() - MAX_DETAIL_ROWS),
            muted,
        )));
    }

    lines
}

/// Renders a duration the way a person reads one off a stopwatch.
#[must_use]
pub fn humanize(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    if seconds < 60 {
        return format!("{seconds}s");
    }
    format!("{}m{:02}s", seconds / 60, seconds % 60)
}

/// Wires every handler.
fn configure(builder: &mut ManagedActor<Idle, Status>) {
    builder.mutate_on::<Wire>(|actor, context| {
        actor.model.compositor = Some(context.message().compositor.clone());
        Reply::ready()
    });

    builder.mutate_on::<TurnStarted>(|actor, _| {
        actor.model.started = Some(Instant::now());
        actor.model.frame = 0;
        // The tick is armed only while a turn runs, and re-arms itself from
        // its own handler, so an idle interface schedules nothing.
        drop(actor.handle().send_after(StatusTick, TICK));
        repaint(actor)
    });

    builder.mutate_on::<TurnEnded>(|actor, _| {
        actor.model.started = None;
        actor.model.tools.clear();
        repaint(actor)
    });

    builder.mutate_on::<StatusTick>(|actor, _| {
        if actor.model.started.is_none() {
            return Reply::ready();
        }
        actor.model.frame = actor.model.frame.wrapping_add(1);
        drop(actor.handle().send_after(StatusTick, TICK));
        repaint(actor)
    });

    builder.mutate_on::<ToolStarted>(|actor, context| {
        let message = context.message();
        actor
            .model
            .tools
            .insert(message.id.clone(), message.title.clone());
        repaint(actor)
    });

    builder.mutate_on::<ToolEnded>(|actor, context| {
        actor.model.tools.remove(&context.message().id);
        repaint(actor)
    });
}

/// Sends the current appearance to the compositor.
fn repaint(actor: &mut ManagedActor<Started, Status>) -> FutureBox {
    let rendered = actor.model.render();
    let compositor = actor.model.compositor.clone();

    Reply::pending(async move {
        if let Some(compositor) = compositor {
            compositor.send(rendered).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools(titles: &[&str]) -> BTreeMap<String, String> {
        titles
            .iter()
            .enumerate()
            .map(|(index, title)| (format!("{index:02}"), (*title).to_string()))
            .collect()
    }

    fn text(line: &Line<'static>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn seconds_are_shown_bare_and_minutes_are_shown_padded() {
        assert_eq!(humanize(Duration::from_secs(9)), "9s");
        assert_eq!(humanize(Duration::from_secs(59)), "59s");
        assert_eq!(humanize(Duration::from_secs(61)), "1m01s");
        assert_eq!(humanize(Duration::from_secs(600)), "10m00s");
    }

    #[test]
    fn the_headline_names_the_escape_key_so_interrupting_is_discoverable() {
        let lines = summary("⠋", Duration::from_secs(3), &BTreeMap::new());
        assert_eq!(lines.len(), 1);
        assert!(text(&lines[0]).contains("Esc to interrupt"));
        assert!(text(&lines[0]).contains("3s"));
    }

    #[test]
    fn each_running_tool_gets_its_own_row() {
        let lines = summary("⠋", Duration::from_secs(1), &tools(&["bash", "read_file"]));
        assert_eq!(lines.len(), 3);
        assert!(text(&lines[1]).contains("bash"));
        assert!(text(&lines[2]).contains("read_file"));
    }

    #[test]
    fn more_tools_than_fit_are_counted_rather_than_listed() {
        let lines = summary(
            "⠋",
            Duration::from_secs(1),
            &tools(&["a", "b", "c", "d", "e"]),
        );
        assert_eq!(lines.len(), 1 + MAX_DETAIL_ROWS + 1);
        assert!(text(lines.last().expect("a summary row")).contains("and 2 more"));
    }

    #[test]
    fn a_status_with_no_turn_running_shows_nothing_at_all() {
        let rendered = Status::default().render();
        assert!(rendered.lines.is_empty());
        assert_eq!(rendered.region, Region::Status);
    }

    #[test]
    fn a_status_with_a_turn_running_claims_rows() {
        let status = Status {
            started: Some(Instant::now()),
            ..Status::default()
        };
        assert!(!status.render().lines.is_empty());
    }
}
