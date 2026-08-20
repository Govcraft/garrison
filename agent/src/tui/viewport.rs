//! The terminal, as a resource with exactly one owner.
//!
//! Garrison's chat does not take over the screen. It pins a few rows to the
//! bottom — the composer, whatever the agent is doing, a permission prompt
//! when one is pending — and writes everything that is *finished* into the
//! terminal's own scrollback, above that viewport. The transcript is then the
//! terminal's to scroll, search, and copy, which is a better transcript than
//! any we could reimplement inside an alternate screen.
//!
//! The trick that makes it work is a DEC scroll region. Restricting scrolling
//! to the rows above the viewport means a newline printed there scrolls only
//! that band, pushing its top row into real scrollback and leaving the pinned
//! rows untouched. See [`ViewportTerminal::insert_history`].
//!
//! # Ownership
//!
//! Nothing here is `Clone` and nothing is shared. Exactly one actor holds a
//! `ViewportTerminal`, and every other part of the interface reaches the
//! screen by sending that actor a message. That is what keeps two writers from
//! interleaving escape sequences into a garbled frame.
//!
//! # Where the rows go
//!
//! This module decides nothing about *which* row anything lands on. That is
//! [`super::geometry`], which is pure arithmetic and tested as such; what is
//! here is the part that cannot be tested without a terminal — issuing the
//! scrolls, the writes, and the clears that carry a decision out.

use super::geometry::{self, Geometry};
use super::wrap::{display_width, wrap_lines};
use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use crossterm::style::{
    Attribute, Color as TermColor, Print, ResetColor, SetAttribute, SetBackgroundColor,
    SetForegroundColor,
};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};
use crossterm::{execute, queue};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Position, Rect, Size};
use ratatui::style::{Color, Modifier};
use ratatui::text::Line;
use ratatui::{Terminal, TerminalOptions, Viewport};
use std::io::{self, Stdout, Write};

/// A terminal running an inline viewport pinned to the bottom of the screen.
pub struct ViewportTerminal {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    geometry: Geometry,
    screen: Size,
}

impl std::fmt::Debug for ViewportTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewportTerminal")
            .field("geometry", &self.geometry)
            .field("screen", &self.screen)
            .finish()
    }
}

impl ViewportTerminal {
    /// Takes over the bottom of the terminal, leaving whatever is above alone.
    ///
    /// The viewport is anchored at the row the cursor is already on, so a chat
    /// started after a `cargo build` begins directly beneath its output rather
    /// than clearing it away.
    ///
    /// # Errors
    ///
    /// Any failure to put the terminal in raw mode or to read its size.
    pub fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnableBracketedPaste)?;

        let mut backend = CrosstermBackend::new(stdout);
        let screen = geometry::usable(backend.size()?);
        let cursor = backend.get_cursor_position().unwrap_or(Position::ORIGIN);
        let geometry = Geometry::new(cursor.y, screen);

        let terminal = Terminal::with_options(
            backend,
            TerminalOptions {
                viewport: Viewport::Fixed(geometry.area(screen)),
            },
        )?;

        Ok(Self {
            terminal,
            geometry,
            screen,
        })
    }

    /// The width available to a line, in columns.
    #[must_use]
    pub const fn width(&self) -> u16 {
        self.screen.width
    }

    /// Re-reads the terminal size after the screen changed shape.
    ///
    /// # Errors
    ///
    /// Failures clearing or repositioning the viewport.
    pub fn on_resize(&mut self, screen: Size) -> io::Result<()> {
        let screen = geometry::usable(screen);
        let narrower = screen.width < self.screen.width;
        self.screen = screen;

        let fitted = geometry::refit(self.geometry, screen);
        // A narrower screen reflows every row that was already written, so
        // nothing above is where we last left it. Ratatui responds by clearing
        // the screen and re-anchoring at the top, and the one thing worse than
        // that is disagreeing with it about where the viewport now is.
        self.geometry = if narrower {
            Geometry {
                y: 0,
                height: fitted.height,
                next: 0,
                pinned: false,
            }
        } else {
            fitted
        };

        let area = self.geometry.area(screen);
        self.terminal.resize(area)
    }

    /// Grows or shrinks the pinned viewport to `height` rows.
    ///
    /// Growth steals rows from the history above by scrolling it up, which is
    /// why this must happen before anything is drawn into the new rows.
    /// Shrinking gives rows back at the top rather than the bottom, so the
    /// composer stays on the row the user last saw it on.
    ///
    /// # Errors
    ///
    /// Failures scrolling, clearing, or resizing.
    pub fn set_height(&mut self, height: u16) -> io::Result<()> {
        let before = self.geometry;
        let plan = geometry::resize(before, height, self.screen);
        if plan.geometry == before {
            return Ok(());
        }

        {
            let backend = self.terminal.backend_mut();
            if plan.scroll_up > 0 {
                backend.scroll_region_up(0..before.y, plan.scroll_up)?;
            }

            // Rows a shrinking viewport gave up still hold the frame it drew
            // there, whether they came off its top or its bottom, and ratatui
            // clears only the new area. Everything from the higher of the two
            // tops downward is either blank already or about to be redrawn, so
            // clearing the lot is both safe and one escape sequence.
            let from = before.y.min(plan.geometry.y);
            queue!(backend, MoveTo(0, from), Clear(ClearType::FromCursorDown))?;
            Backend::flush(backend)?;
        }

        self.geometry = plan.geometry;
        let area = self.geometry.area(self.screen);
        self.terminal.resize(area)
    }

    /// Writes finished lines into the terminal's scrollback, above the viewport.
    ///
    /// # Errors
    ///
    /// Failures writing to the terminal.
    pub fn insert_history(&mut self, lines: &[Line<'static>]) -> io::Result<()> {
        let width = self.screen.width.max(1);
        let wrapped = wrap_lines(lines, width as usize);
        if wrapped.is_empty() {
            return Ok(());
        }

        let rows = u16::try_from(wrapped.len()).unwrap_or(u16::MAX);
        let plan = geometry::insert(self.geometry, rows, self.screen);

        // Sliding the viewport down turns the rows it leaves behind into the
        // blank rows the lines below are written into.
        if plan.shift > 0 {
            self.terminal
                .backend_mut()
                .scroll_region_down(self.geometry.y..self.screen.height, plan.shift)?;
        }
        self.geometry = plan.geometry;
        let area = self.geometry.area(self.screen);
        self.terminal.resize(area)?;

        let top = self.geometry.y;
        let backend = self.terminal.backend_mut();

        // Blank rows above the viewport already sit exactly where the next
        // history belongs, so they are written into directly. Scrolling for
        // them as well is what would open a gap: the band scroll below moves
        // these rows too, and the blank would come to rest between what was
        // already on screen and what is being added.
        for (offset, line) in wrapped.iter().take(plan.direct as usize).enumerate() {
            let row = plan
                .at
                .saturating_add(u16::try_from(offset).unwrap_or(u16::MAX));
            queue!(backend, MoveTo(0, row))?;
            write_line(backend, line, width)?;
        }

        // Whatever is left has nowhere to go but into scrollback. Confining
        // scrolling to the band above the viewport means a newline printed
        // inside it scrolls only that band, so its top row leaves the screen
        // and the pinned rows below never move.
        //
        // ┌─Screen─────────────────────┐
        // │┌╌Scroll region╌╌╌╌╌╌╌╌╌╌╌╌┐│
        // │┆        history           ┆│
        // │█╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘│  <- cursor sits here
        // │╭─Viewport─────────────────╮│
        // │╰──────────────────────────╯│
        // └────────────────────────────┘
        let overflow = &wrapped[usize::from(plan.direct).min(wrapped.len())..];
        if !overflow.is_empty() {
            queue!(backend, Print(set_scroll_region(1, top.max(1))))?;
            queue!(backend, MoveTo(0, top.saturating_sub(1)))?;

            for line in overflow {
                queue!(backend, Print("\r\n"))?;
                write_line(backend, line, width)?;
            }

            queue!(backend, Print(RESET_SCROLL_REGION))?;
        }

        Backend::flush(backend)
    }

    /// Paints the pinned viewport.
    ///
    /// `cursor` is a position within the viewport; `None` hides the cursor,
    /// which is what a modal wants and a text field never does.
    ///
    /// # Errors
    ///
    /// Failures drawing to the terminal.
    pub fn draw(&mut self, lines: &[Line<'static>], cursor: Option<(u16, u16)>) -> io::Result<()> {
        let area = self.geometry.area(self.screen);
        self.terminal.draw(|frame| {
            let buffer = frame.buffer_mut();
            for (row, line) in lines.iter().enumerate() {
                let Ok(offset) = u16::try_from(row) else {
                    break;
                };
                if offset >= area.height {
                    break;
                }
                let target = Rect {
                    x: area.x,
                    y: area.y + offset,
                    width: area.width,
                    height: 1,
                };
                ratatui::widgets::Widget::render(line, target, buffer);
            }

            if let Some((x, y)) = cursor {
                frame.set_cursor_position(Position {
                    x: area.x + x.min(area.width.saturating_sub(1)),
                    y: area.y + y.min(area.height.saturating_sub(1)),
                });
            }
        })?;

        if cursor.is_none() {
            execute!(self.terminal.backend_mut(), Hide)?;
        }
        Ok(())
    }

    /// Erases the screen and the scrollback behind it.
    ///
    /// This is the one operation that reaches past what this program wrote:
    /// `\x1b[3J` asks the terminal to drop its saved lines, so everything
    /// committed to history is gone rather than merely scrolled away. The
    /// viewport moves back to the top of a now-empty screen, because leaving
    /// it pinned to the bottom would open a blank gap nothing will ever fill.
    ///
    /// # Errors
    ///
    /// Failures writing to the terminal.
    pub fn clear_history(&mut self) -> io::Result<()> {
        let backend = self.terminal.backend_mut();
        queue!(
            backend,
            Print(RESET_SCROLL_REGION),
            Clear(ClearType::All),
            Clear(ClearType::Purge),
            MoveTo(0, 0)
        )?;
        Backend::flush(backend)?;

        self.geometry = Geometry {
            y: 0,
            height: self.geometry.height,
            next: 0,
            pinned: false,
        };
        let area = self.geometry.area(self.screen);
        self.terminal.resize(area)
    }

    /// Gives the terminal back, leaving the transcript on screen.
    ///
    /// # Errors
    ///
    /// Failures restoring the terminal's modes. The modes are restored on a
    /// best-effort basis regardless, because a half-restored terminal is worse
    /// than a reported error.
    pub fn restore(&mut self) -> io::Result<()> {
        let top = self.geometry.next;
        let backend = self.terminal.backend_mut();
        let _ = queue!(
            backend,
            Print(RESET_SCROLL_REGION),
            MoveTo(0, top),
            Clear(ClearType::FromCursorDown),
            ResetColor,
            SetAttribute(Attribute::Reset),
            Show
        );
        let _ = Backend::flush(backend);

        execute!(io::stdout(), DisableBracketedPaste)?;
        disable_raw_mode()
    }
}

/// The escape sequence that resets the scroll region to the whole screen.
const RESET_SCROLL_REGION: &str = "\x1b[r";

/// Builds the escape sequence confining scrolling to rows `first..=last`.
///
/// Both bounds are one-based, as the terminal counts them. Pure, so the
/// sequence can be asserted on without a terminal.
#[must_use]
pub fn set_scroll_region(first: u16, last: u16) -> String {
    format!("\x1b[{first};{last}r")
}

/// Writes one already-wrapped line at the cursor, then clears to end of row.
fn write_line<W: Write>(writer: &mut W, line: &Line<'static>, width: u16) -> io::Result<()> {
    let mut used = 0usize;
    let limit = width as usize;

    for span in &line.spans {
        if used >= limit {
            break;
        }
        apply_style(writer, span.style)?;
        queue!(writer, Print(span.content.as_ref()))?;
        used += display_width(span.content.as_ref());
    }

    queue!(
        writer,
        ResetColor,
        SetAttribute(Attribute::Reset),
        Clear(ClearType::UntilNewLine)
    )
}

/// Emits the escape sequences for one span's style.
///
/// Resets first, so a style is never inherited from the span before it.
fn apply_style<W: Write>(writer: &mut W, style: ratatui::style::Style) -> io::Result<()> {
    queue!(writer, SetAttribute(Attribute::Reset), ResetColor)?;

    if let Some(color) = style.fg {
        queue!(writer, SetForegroundColor(to_crossterm(color)))?;
    }
    if let Some(color) = style.bg {
        queue!(writer, SetBackgroundColor(to_crossterm(color)))?;
    }
    for (modifier, attribute) in [
        (Modifier::BOLD, Attribute::Bold),
        (Modifier::DIM, Attribute::Dim),
        (Modifier::ITALIC, Attribute::Italic),
        (Modifier::UNDERLINED, Attribute::Underlined),
        (Modifier::REVERSED, Attribute::Reverse),
    ] {
        if style.add_modifier.contains(modifier) {
            queue!(writer, SetAttribute(attribute))?;
        }
    }
    Ok(())
}

/// Translates a ratatui colour into the crossterm one that names it.
///
/// Pure, and total: every ratatui colour has a crossterm counterpart.
#[must_use]
pub const fn to_crossterm(color: Color) -> TermColor {
    match color {
        Color::Reset => TermColor::Reset,
        Color::Black => TermColor::Black,
        Color::Red => TermColor::DarkRed,
        Color::Green => TermColor::DarkGreen,
        Color::Yellow => TermColor::DarkYellow,
        Color::Blue => TermColor::DarkBlue,
        Color::Magenta => TermColor::DarkMagenta,
        Color::Cyan => TermColor::DarkCyan,
        Color::Gray => TermColor::Grey,
        Color::DarkGray => TermColor::DarkGrey,
        Color::LightRed => TermColor::Red,
        Color::LightGreen => TermColor::Green,
        Color::LightYellow => TermColor::Yellow,
        Color::LightBlue => TermColor::Blue,
        Color::LightMagenta => TermColor::Magenta,
        Color::LightCyan => TermColor::Cyan,
        Color::White => TermColor::White,
        Color::Rgb(r, g, b) => TermColor::Rgb { r, g, b },
        Color::Indexed(index) => TermColor::AnsiValue(index),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scroll_region_sequence_is_one_based_and_inclusive() {
        assert_eq!(set_scroll_region(1, 20), "\x1b[1;20r");
    }

    #[test]
    fn resetting_the_scroll_region_omits_both_bounds() {
        assert_eq!(RESET_SCROLL_REGION, "\x1b[r");
    }

    #[test]
    fn ratatui_light_colours_map_to_the_crossterm_bright_ones() {
        assert!(matches!(to_crossterm(Color::LightRed), TermColor::Red));
        assert!(matches!(to_crossterm(Color::Red), TermColor::DarkRed));
    }

    #[test]
    fn an_rgb_colour_survives_the_translation_intact() {
        assert!(matches!(
            to_crossterm(Color::Rgb(1, 2, 3)),
            TermColor::Rgb { r: 1, g: 2, b: 3 }
        ));
    }

    #[test]
    fn a_styled_span_emits_its_colour_before_its_text() {
        let mut out: Vec<u8> = Vec::new();
        let line = Line::from(vec![ratatui::text::Span::styled(
            "hi",
            ratatui::style::Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        )]);

        write_line(&mut out, &line, 40).expect("writing to a vec cannot fail");
        let rendered = String::from_utf8(out).expect("crossterm emits utf-8");

        let color_at = rendered
            .find("\x1b[38;5;10m")
            .or_else(|| rendered.find("\x1b[92m"));
        let text_at = rendered.find("hi").expect("the text is written");
        assert!(color_at.is_some_and(|at| at < text_at));
        assert!(rendered.ends_with("\x1b[K"));
    }
}
