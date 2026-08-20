//! The input buffer, and the region it owns.
//!
//! Nothing else knows what the user has typed. Keys arrive as messages, the
//! buffer changes, and the resulting rows go to the compositor — so the input
//! line repaints on its own schedule and never waits on a turn.

use super::message::{KeyPressed, Pasted, Quit, Region, RegionRendered, Submitted, Wire};
use super::slash;
use acton_reactive::prelude::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthStr;

/// What the prompt line begins with.
const PROMPT: &str = "› ";

/// What the input buffer is, and where the caret sits in it.
#[acton_actor]
pub struct Composer {
    /// The text, which may contain newlines.
    text: String,
    /// The caret, as a byte offset into `text`. Always on a character boundary.
    caret: usize,
    /// Where rendered rows go.
    compositor: Option<ActorHandle>,
    /// Where finished messages go.
    session: Option<ActorHandle>,
}

/// What a key did to the buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// The buffer changed, or nothing happened; repaint and wait.
    Redraw,
    /// The user finished a message.
    Submit(String),
    /// The user asked to leave.
    Quit,
}

impl Composer {
    /// Builds and starts the composer.
    pub async fn start(runtime: &mut ActorRuntime) -> ActorHandle {
        let mut builder = runtime.new_actor::<Self>();
        configure(&mut builder);
        builder.start().await
    }

    /// The rows this region currently shows, and where the caret is in them.
    ///
    /// Pure: given a buffer and a width, the picture is determined, which is
    /// what makes the caret arithmetic testable without a terminal.
    #[must_use]
    pub fn render(&self, width: u16) -> RegionRendered {
        let indent = UnicodeWidthStr::width(PROMPT);
        let usable = usize::from(width).saturating_sub(indent).max(1);

        let mut lines: Vec<Line<'static>> = Vec::new();
        let mut caret = (0u16, 0u16);
        let mut consumed = 0usize;

        for (index, segment) in self.text.split('\n').enumerate() {
            let prefix = if index == 0 { PROMPT } else { "  " };
            let rows = chunk(segment, usable);

            for (row, piece) in rows.iter().enumerate() {
                let start = consumed;
                let end = consumed + piece.len();
                // `<=` so a caret at the very end of a row lands after its last
                // character rather than falling through to the next row.
                if self.caret >= start && self.caret <= end {
                    let column = UnicodeWidthStr::width(&piece[..self.caret - start]);
                    let x = u16::try_from(indent + column).unwrap_or(u16::MAX);
                    let y = u16::try_from(lines.len()).unwrap_or(u16::MAX);
                    caret = (x, y);
                }
                consumed = end;

                let head = if row == 0 { prefix } else { "  " };
                lines.push(Line::from(vec![
                    Span::styled(head.to_string(), Style::default().fg(Color::DarkGray)),
                    Span::raw(piece.clone()),
                ]));
            }
            // The newline the split consumed.
            consumed += 1;
        }

        if lines.is_empty() {
            lines.push(Line::from(vec![
                Span::styled(PROMPT.to_string(), Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "send a message, /help for commands".to_string(),
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::DIM),
                ),
            ]));
            caret = (u16::try_from(indent).unwrap_or(0), 0);
        }

        RegionRendered {
            region: Region::Composer,
            lines,
            cursor: Some(caret),
        }
    }

    /// Applies one key, reporting what it meant.
    ///
    /// Pure but for `&mut self`, so every binding can be asserted directly.
    pub fn press(&mut self, key: KeyEvent) -> Action {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);

        match key.code {
            // Enter submits. A newline is Ctrl+J, which every terminal sends
            // the same way — unlike Shift+Enter, which most cannot send at all.
            KeyCode::Enter if !control => {
                let text = self.text.trim().to_string();
                if text.is_empty() {
                    return Action::Redraw;
                }
                self.text.clear();
                self.caret = 0;
                Action::Submit(text)
            }
            KeyCode::Char('j') if control => {
                self.insert("\n");
                Action::Redraw
            }
            KeyCode::Char('d') if control => {
                // Only an empty composer quits, so Ctrl+D never discards a
                // message the user is halfway through writing.
                if self.text.is_empty() {
                    Action::Quit
                } else {
                    Action::Redraw
                }
            }
            KeyCode::Char('u') if control => {
                self.text.drain(..self.caret);
                self.caret = 0;
                Action::Redraw
            }
            KeyCode::Char('k') if control => {
                self.text.truncate(self.caret);
                Action::Redraw
            }
            KeyCode::Char('a') if control => {
                self.caret = 0;
                Action::Redraw
            }
            KeyCode::Char('e') if control => {
                self.caret = self.text.len();
                Action::Redraw
            }
            KeyCode::Char('w') if control => {
                self.delete_word();
                Action::Redraw
            }
            KeyCode::Char(character) if !control => {
                self.insert(&character.to_string());
                Action::Redraw
            }
            KeyCode::Backspace => {
                if let Some(previous) = self.previous_boundary() {
                    self.text.drain(previous..self.caret);
                    self.caret = previous;
                }
                Action::Redraw
            }
            KeyCode::Delete => {
                if let Some(next) = self.next_boundary() {
                    self.text.drain(self.caret..next);
                }
                Action::Redraw
            }
            KeyCode::Left => {
                self.caret = self.previous_boundary().unwrap_or(0);
                Action::Redraw
            }
            KeyCode::Right => {
                self.caret = self.next_boundary().unwrap_or(self.caret);
                Action::Redraw
            }
            KeyCode::Home => {
                self.caret = 0;
                Action::Redraw
            }
            KeyCode::End => {
                self.caret = self.text.len();
                Action::Redraw
            }
            _ => Action::Redraw,
        }
    }

    /// Inserts text at the caret and moves it past.
    pub fn insert(&mut self, text: &str) {
        self.text.insert_str(self.caret, text);
        self.caret += text.len();
    }

    /// The byte offset of the character before the caret.
    fn previous_boundary(&self) -> Option<usize> {
        self.text[..self.caret]
            .char_indices()
            .next_back()
            .map(|(offset, _)| offset)
    }

    /// The byte offset just past the character after the caret.
    fn next_boundary(&self) -> Option<usize> {
        self.text[self.caret..]
            .chars()
            .next()
            .map(|character| self.caret + character.len_utf8())
    }

    /// Deletes back to the start of the word the caret is in.
    fn delete_word(&mut self) {
        let head = &self.text[..self.caret];
        let trimmed = head.trim_end_matches(' ');
        let start = trimmed.rfind(' ').map_or(0, |offset| offset + 1);
        self.text.drain(start..self.caret);
        self.caret = start;
    }
}

/// Splits a segment into pieces that each fit `width` columns.
///
/// A segment shorter than the width yields one piece, including when it is
/// empty — an empty line still occupies a row.
fn chunk(segment: &str, width: usize) -> Vec<String> {
    if UnicodeWidthStr::width(segment) <= width {
        return vec![segment.to_string()];
    }

    let mut pieces = Vec::new();
    let mut current = String::new();
    let mut used = 0usize;

    for character in segment.chars() {
        let character_width = UnicodeWidthStr::width(character.to_string().as_str());
        if used + character_width > width && !current.is_empty() {
            pieces.push(std::mem::take(&mut current));
            used = 0;
        }
        used += character_width;
        current.push(character);
    }

    pieces.push(current);
    pieces
}

/// Wires every handler.
fn configure(builder: &mut ManagedActor<Idle, Composer>) {
    builder.mutate_on::<Wire>(|actor, context| {
        actor.model.compositor = Some(context.message().compositor.clone());
        actor.model.session = Some(context.message().session.clone());
        repaint(actor)
    });

    builder.mutate_on::<KeyPressed>(|actor, context| {
        let action = actor.model.press(context.message().key);
        let compositor = actor.model.compositor.clone();
        let session = actor.model.session.clone();
        let rendered = actor.model.render(DEFAULT_WIDTH);

        Reply::pending(async move {
            if let Some(compositor) = compositor {
                compositor.send(rendered).await;
            }
            let Some(session) = session else {
                return;
            };
            match action {
                Action::Redraw => {}
                Action::Submit(text) => session.send(Submitted { text }).await,
                Action::Quit => session.send(Quit).await,
            }
        })
    });

    builder.mutate_on::<Pasted>(|actor, context| {
        // Pasted text is content, never keys: a newline in it must not send
        // the message halfway through the paste.
        actor.model.insert(&context.message().text);
        repaint(actor)
    });
}

/// The width the composer assumes when it renders.
///
/// The compositor rewraps to the terminal's real width, so this only has to be
/// wide enough that the caret's row-and-column arithmetic is done against the
/// same text the user typed.
const DEFAULT_WIDTH: u16 = 80;

/// Sends the current appearance to the compositor.
fn repaint(actor: &mut ManagedActor<Started, Composer>) -> FutureBox {
    let rendered = actor.model.render(DEFAULT_WIDTH);
    let compositor = actor.model.compositor.clone();

    Reply::pending(async move {
        if let Some(compositor) = compositor {
            compositor.send(rendered).await;
        }
    })
}

/// The type every handler returns.
type FutureBox = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync + 'static>>;

/// Whether a submitted line is a slash command rather than a message.
#[must_use]
pub fn is_command(text: &str) -> bool {
    slash::parse(text).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn control(character: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(character), KeyModifiers::CONTROL)
    }

    fn typed(composer: &mut Composer, text: &str) {
        for character in text.chars() {
            composer.press(key(KeyCode::Char(character)));
        }
    }

    #[test]
    fn enter_submits_the_trimmed_buffer_and_empties_it() {
        let mut composer = Composer::default();
        typed(&mut composer, "  hello  ");

        assert_eq!(
            composer.press(key(KeyCode::Enter)),
            Action::Submit("hello".to_string())
        );
        assert!(composer.text.is_empty());
        assert_eq!(composer.caret, 0);
    }

    #[test]
    fn enter_on_an_empty_buffer_sends_nothing() {
        let mut composer = Composer::default();
        assert_eq!(composer.press(key(KeyCode::Enter)), Action::Redraw);
    }

    #[test]
    fn control_j_inserts_a_newline_rather_than_submitting() {
        let mut composer = Composer::default();
        typed(&mut composer, "one");
        composer.press(control('j'));
        typed(&mut composer, "two");

        assert_eq!(composer.text, "one\ntwo");
    }

    #[test]
    fn control_d_quits_only_when_there_is_nothing_to_lose() {
        let mut composer = Composer::default();
        typed(&mut composer, "draft");
        assert_eq!(composer.press(control('d')), Action::Redraw);

        let mut empty = Composer::default();
        assert_eq!(empty.press(control('d')), Action::Quit);
    }

    #[test]
    fn backspace_removes_a_whole_character_not_a_byte() {
        let mut composer = Composer::default();
        typed(&mut composer, "aé");
        composer.press(key(KeyCode::Backspace));

        assert_eq!(composer.text, "a");
        assert_eq!(composer.caret, 1);
    }

    #[test]
    fn the_arrows_step_over_multibyte_characters() {
        let mut composer = Composer::default();
        typed(&mut composer, "é");
        composer.press(key(KeyCode::Left));
        assert_eq!(composer.caret, 0);
        composer.press(key(KeyCode::Right));
        assert_eq!(composer.caret, 2);
    }

    #[test]
    fn control_w_deletes_back_to_the_start_of_the_word() {
        let mut composer = Composer::default();
        typed(&mut composer, "delete this ");
        composer.press(control('w'));

        assert_eq!(composer.text, "delete ");
    }

    #[test]
    fn control_u_clears_only_what_is_behind_the_caret() {
        let mut composer = Composer::default();
        typed(&mut composer, "keep");
        composer.press(key(KeyCode::Home));
        typed(&mut composer, "drop");
        composer.press(control('u'));

        assert_eq!(composer.text, "keep");
    }

    #[test]
    fn a_paste_containing_a_newline_does_not_submit() {
        let mut composer = Composer::default();
        composer.insert("first\nsecond");

        assert_eq!(composer.text, "first\nsecond");
    }

    #[test]
    fn an_empty_composer_shows_a_hint_with_the_caret_after_the_prompt() {
        let rendered = Composer::default().render(80);
        assert_eq!(rendered.lines.len(), 1);
        assert_eq!(rendered.cursor, Some((2, 0)));
    }

    #[test]
    fn the_caret_lands_after_the_last_character_typed() {
        let mut composer = Composer::default();
        typed(&mut composer, "abc");

        assert_eq!(composer.render(80).cursor, Some((5, 0)));
    }

    #[test]
    fn a_second_line_is_indented_under_the_prompt() {
        let mut composer = Composer::default();
        typed(&mut composer, "one");
        composer.press(control('j'));
        typed(&mut composer, "two");

        let rendered = composer.render(80);
        assert_eq!(rendered.lines.len(), 2);
        assert_eq!(rendered.cursor, Some((5, 1)));
    }

    #[test]
    fn a_line_wider_than_the_terminal_wraps_and_carries_the_caret_down() {
        let mut composer = Composer::default();
        typed(&mut composer, "abcdefgh");

        let rendered = composer.render(6);
        assert_eq!(rendered.lines.len(), 2);
        assert_eq!(rendered.cursor, Some((6, 1)));
    }
}
