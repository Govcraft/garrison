//! The one actor that writes to the terminal.
//!
//! Every other part of the interface renders its own rows and sends them here.
//! This actor holds the [`ViewportTerminal`], stacks the regions in order,
//! sizes the pinned viewport to fit, and paints. Because it is an actor its
//! handlers run one at a time, so two regions changing at once cannot
//! interleave escape sequences — the property that a lock around stdout would
//! have to buy and that message ordering gives for free.
//!
//! # Frames are asked for, never taken
//!
//! A change marks the screen dirty and, if no frame is already armed, asks
//! this actor to draw itself again in [`FRAME_INTERVAL`]. A hundred streaming
//! tokens arriving in one millisecond therefore cost one repaint, not a
//! hundred, and an idle interface costs none at all.

use super::message::{
    ClearHistory, CommitHistory, DrawTick, Region, RegionRendered, ScreenResized, Shutdown, Suspend,
};
use super::viewport::ViewportTerminal;
use super::wrap::wrap_lines;
use acton_reactive::prelude::*;
use ratatui::text::Line;
use std::collections::BTreeMap;
use std::time::Duration;

/// How long a change waits for company before the screen is repainted.
///
/// Short enough that typing feels immediate, long enough that a stream of
/// tokens coalesces into one frame.
const FRAME_INTERVAL: Duration = Duration::from_millis(16);

/// What one region currently looks like.
#[derive(Clone, Debug, Default)]
struct Snapshot {
    lines: Vec<Line<'static>>,
    cursor: Option<(u16, u16)>,
}

/// The terminal, the regions painted into it, and the history above it.
#[acton_actor]
pub struct Compositor {
    /// The terminal itself. `None` once it has been given back.
    terminal: Option<ViewportTerminal>,
    /// The latest rows each region reported.
    regions: BTreeMap<Region, Snapshot>,
    /// Rows waiting to go into scrollback at the next frame.
    ///
    /// Buffering them rather than writing on arrival keeps the scroll and the
    /// repaint in one burst, so history never appears over a stale viewport.
    pending: Vec<Line<'static>>,
    /// Whether anything has changed since the last frame.
    dirty: bool,
    /// Whether a [`DrawTick`] is already on its way.
    armed: bool,
    /// Whether color survives into the terminal output.
    color: bool,
}

impl Compositor {
    /// Builds and starts the compositor, taking over the terminal.
    ///
    /// # Errors
    ///
    /// Any failure putting the terminal into raw mode.
    pub async fn start(
        runtime: &mut ActorRuntime,
        color: bool,
    ) -> Result<ActorHandle, std::io::Error> {
        let terminal = ViewportTerminal::new()?;
        let mut builder = runtime.new_actor::<Self>();
        builder.model.terminal = Some(terminal);
        builder.model.color = color;
        configure(&mut builder);
        Ok(builder.start().await)
    }

    /// Marks the screen dirty and asks for a frame if none is coming.
    fn request_frame(&mut self, handle: &ActorHandle) {
        self.dirty = true;
        if self.armed {
            return;
        }
        self.armed = true;
        drop(handle.send_after(DrawTick, FRAME_INTERVAL));
    }

    /// Sizes the viewport, writes history, and paints one frame.
    fn paint(&mut self) {
        let Some(terminal) = self.terminal.as_mut() else {
            return;
        };

        let width = terminal.width() as usize;
        let (mut rows, cursor) = stack(&self.regions, width);
        if !self.color {
            remove_colors(&mut rows);
        }
        let height = u16::try_from(rows.len()).unwrap_or(u16::MAX).max(1);

        // Sizing before writing, rather than after, is what keeps the
        // transcript against the composer. A reply that finishes shrinks the
        // viewport and commits its last rows to history in the same frame; do
        // the writing first and those rows are pushed into scrollback only for
        // the shrink to open the same number of blank rows behind them.
        if let Err(error) = terminal.set_height(height) {
            tracing::warn!(%error, "could not resize the viewport");
        }

        if !self.pending.is_empty() {
            let mut lines = std::mem::take(&mut self.pending);
            if !self.color {
                remove_colors(&mut lines);
            }
            if let Err(error) = terminal.insert_history(&lines) {
                tracing::warn!(%error, "could not write history to the terminal");
            }
        }
        if let Err(error) = terminal.draw(&rows, cursor) {
            tracing::warn!(%error, "could not paint the viewport");
        }
    }
}

/// Removes foreground, background, and underline colors without losing text.
fn remove_colors(lines: &mut [Line<'static>]) {
    for span in lines.iter_mut().flat_map(|line| &mut line.spans) {
        span.style.fg = None;
        span.style.bg = None;
        span.style.underline_color = None;
    }
}

/// Flattens the regions into rows, and finds where the cursor goes.
///
/// Pure, so the stacking order and the cursor arithmetic are testable without
/// a terminal — which matters, because an off-by-one here puts the cursor in
/// somebody else's region.
#[must_use]
fn stack(
    regions: &BTreeMap<Region, Snapshot>,
    width: usize,
) -> (Vec<Line<'static>>, Option<(u16, u16)>) {
    let mut rows: Vec<Line<'static>> = Vec::new();
    let mut cursor = None;

    for snapshot in regions.values() {
        let wrapped = wrap_lines(&snapshot.lines, width);
        if let Some((x, y)) = snapshot.cursor {
            if cursor.is_none() {
                let offset = u16::try_from(rows.len()).unwrap_or(u16::MAX);
                cursor = Some((x, offset.saturating_add(y)));
            }
        }
        rows.extend(wrapped);
    }

    (rows, cursor)
}

/// Wires every handler.
fn configure(builder: &mut ManagedActor<Idle, Compositor>) {
    builder.mutate_on::<RegionRendered>(|actor, context| {
        let message = context.message();
        let snapshot = Snapshot {
            lines: message.lines.clone(),
            cursor: message.cursor,
        };

        if snapshot.lines.is_empty() && snapshot.cursor.is_none() {
            actor.model.regions.remove(&message.region);
        } else {
            actor.model.regions.insert(message.region, snapshot);
        }

        let handle = actor.handle().clone();
        actor.model.request_frame(&handle);
        Reply::ready()
    });

    builder.mutate_on::<CommitHistory>(|actor, context| {
        actor
            .model
            .pending
            .extend(context.message().lines.iter().cloned());
        let handle = actor.handle().clone();
        actor.model.request_frame(&handle);
        Reply::ready()
    });

    builder.mutate_on::<DrawTick>(|actor, _| {
        actor.model.armed = false;
        if actor.model.dirty {
            actor.model.dirty = false;
            actor.model.paint();
        }
        Reply::ready()
    });

    builder.mutate_on::<ClearHistory>(|actor, _| {
        // Anything queued for scrollback is dropped with everything else: it
        // was never written, and writing it after a clear would leave the one
        // thing on screen that the user just asked to be rid of.
        actor.model.pending.clear();
        if let Some(terminal) = actor.model.terminal.as_mut() {
            if let Err(error) = terminal.clear_history() {
                tracing::warn!(%error, "could not clear the terminal");
            }
        }
        let handle = actor.handle().clone();
        actor.model.request_frame(&handle);
        Reply::ready()
    });

    builder.mutate_on::<ScreenResized>(|actor, context| {
        let size = context.message().size;
        if let Some(terminal) = actor.model.terminal.as_mut() {
            if let Err(error) = terminal.on_resize(size) {
                tracing::warn!(%error, "could not follow the terminal's new size");
            }
        }
        let handle = actor.handle().clone();
        actor.model.request_frame(&handle);
        Reply::ready()
    });

    builder.mutate_on::<Shutdown>(|actor, _| {
        // Anything still buffered is written before the terminal goes back, so
        // a final error message is not lost to the restore that follows it.
        actor.model.dirty = true;
        actor.model.paint();

        if let Some(mut terminal) = actor.model.terminal.take() {
            if let Err(error) = terminal.restore() {
                tracing::warn!(%error, "could not restore the terminal");
            }
        }
        Reply::ready()
    });

    builder.mutate_on::<Suspend>(|actor, _| {
        let Some(mut terminal) = actor.model.terminal.take() else {
            return Reply::ready();
        };
        if let Err(error) = terminal.restore() {
            tracing::warn!(%error, "could not restore the terminal before suspending");
        }
        if let Err(error) = suspend_process() {
            tracing::warn!(%error, "could not suspend to the shell");
        }
        match ViewportTerminal::new() {
            Ok(terminal) => actor.model.terminal = Some(terminal),
            Err(error) => tracing::warn!(%error, "could not retake the terminal after resuming"),
        }
        let handle = actor.handle().clone();
        actor.model.request_frame(&handle);
        Reply::ready()
    });
}

/// Stops this process after terminal modes have been restored.
fn suspend_process() -> std::io::Result<()> {
    // SAFETY: `raise` is called with the fixed, valid SIGTSTP constant. It
    // touches no Rust memory; execution resumes here after the shell sends
    // SIGCONT.
    let result = unsafe { libc::raise(libc::SIGTSTP) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::{Color, Style};
    use ratatui::text::Line;

    fn snapshot(lines: &[&str], cursor: Option<(u16, u16)>) -> Snapshot {
        Snapshot {
            lines: lines
                .iter()
                .map(|text| Line::from((*text).to_string()))
                .collect(),
            cursor,
        }
    }

    fn texts(rows: &[Line<'static>]) -> Vec<String> {
        rows.iter()
            .map(|row| row.spans.iter().map(|span| span.content.as_ref()).collect())
            .collect()
    }

    #[test]
    fn regions_stack_in_declaration_order_regardless_of_insertion_order() {
        let mut regions = BTreeMap::new();
        regions.insert(Region::Composer, snapshot(&["> "], None));
        regions.insert(Region::Tail, snapshot(&["thinking"], None));
        regions.insert(Region::Status, snapshot(&["working"], None));

        let (rows, _) = stack(&regions, 40);
        assert_eq!(
            texts(&rows),
            vec![
                "thinking".to_string(),
                "working".to_string(),
                "> ".to_string()
            ]
        );
    }

    #[test]
    fn the_cursor_is_offset_by_every_row_stacked_above_it() {
        let mut regions = BTreeMap::new();
        regions.insert(Region::Tail, snapshot(&["one", "two"], None));
        regions.insert(Region::Composer, snapshot(&["> hi"], Some((4, 0))));

        let (_, cursor) = stack(&regions, 40);
        assert_eq!(cursor, Some((4, 2)));
    }

    #[test]
    fn disabling_color_preserves_text_and_non_color_attributes() {
        let mut lines = vec![Line::styled(
            "warning",
            Style::default().fg(Color::Red).bg(Color::Black).bold(),
        )];

        remove_colors(&mut lines);

        assert_eq!(texts(&lines), ["warning"]);
        assert_eq!(lines[0].spans[0].style.fg, None);
        assert_eq!(lines[0].spans[0].style.bg, None);
        assert!(lines[0].spans[0]
            .style
            .add_modifier
            .contains(ratatui::style::Modifier::BOLD));
    }

    #[test]
    fn wrapped_rows_above_the_cursor_push_it_down_too() {
        let mut regions = BTreeMap::new();
        regions.insert(Region::Tail, snapshot(&["aaaa bbbb"], None));
        regions.insert(Region::Composer, snapshot(&["> "], Some((2, 0))));

        let (rows, cursor) = stack(&regions, 4);
        assert_eq!(rows.len(), 3);
        assert_eq!(cursor, Some((2, 2)));
    }

    #[test]
    fn the_topmost_region_asking_for_the_cursor_gets_it() {
        let mut regions = BTreeMap::new();
        regions.insert(Region::Approval, snapshot(&["allow?"], Some((1, 0))));
        regions.insert(Region::Composer, snapshot(&["> "], Some((2, 0))));

        let (_, cursor) = stack(&regions, 40);
        assert_eq!(cursor, Some((1, 0)));
    }

    #[test]
    fn an_empty_map_stacks_to_nothing_and_claims_no_cursor() {
        let (rows, cursor) = stack(&BTreeMap::new(), 40);
        assert!(rows.is_empty());
        assert_eq!(cursor, None);
    }
}
