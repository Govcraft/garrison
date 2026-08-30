//! The permission gate, as a modal that owns its own region.
//!
//! The agent blocks on every `session/request_permission` until it is
//! answered, so this actor's queue is the only thing standing between a tool
//! call and the file system. Two rules follow from that and are enforced here
//! rather than trusted to the caller: an unanswered request is never dropped,
//! and no key except an explicit approval ever means yes.

use super::message::{
    Focus, FocusChanged, KeyPressed, Note, PermissionAnswered, PermissionAsked, PermissionExpired,
    Region, RegionRendered, Wire,
};
use super::status::humanize;
use super::transcript::notice_line;
use crate::protocol::acp;
use crate::protocol::jsonrpc::RequestId;
use acton_reactive::prelude::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use std::collections::VecDeque;
use std::time::Duration;

/// The type every handler returns.
type FutureBox = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync + 'static>>;

/// One choice the user can make about a pending call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Choice {
    /// The option id sent back over ACP.
    pub option: &'static str,
    /// The single key that picks it directly.
    pub key: char,
    /// What the user reads.
    pub label: &'static str,
}

/// The choices offered, in the order they are listed.
///
/// Refusing is last and is also what every key not listed here does.
pub const CHOICES: [Choice; 3] = [
    Choice {
        option: acp::OPTION_ALLOW_ONCE,
        key: 'y',
        label: "Yes, just this once",
    },
    Choice {
        option: acp::OPTION_ALLOW_ALWAYS,
        key: 'a',
        label: "Yes, and stop asking for this tool this session",
    },
    Choice {
        option: acp::OPTION_REJECT,
        key: 'n',
        label: "No, and tell the agent to do something else",
    },
];

/// The fail-closed selection used whenever a prompt first receives focus.
#[must_use]
pub const fn default_selection() -> usize {
    CHOICES.len() - 1
}

/// One request waiting for an answer.
#[derive(Clone, Debug)]
struct Pending {
    id: RequestId,
    title: String,
    detail: Option<String>,
}

/// The queue of permissions the agent is blocked on.
#[acton_actor]
pub struct Approval {
    /// Requests waiting, oldest first. Only the front one is shown.
    pending: VecDeque<Pending>,
    /// Which choice is highlighted for the front request.
    selected: usize,
    /// Whether every request is approved without asking.
    approve_all: bool,
    /// How long a visible request remains answerable.
    expires_after: Duration,
    /// Where rendered rows go.
    compositor: Option<ActorHandle>,
    /// Where the transcript lives.
    transcript: Option<ActorHandle>,
    /// Who to tell when focus moves.
    router: Option<ActorHandle>,
    /// Who writes the answer on the wire.
    session: Option<ActorHandle>,
}

impl Approval {
    /// Builds and starts the gate.
    ///
    /// `approve_all` turns the gate off. It exists for unattended runs and is
    /// named for what it does, because a flag whose default is "allow" is not
    /// a gate.
    pub async fn start(
        runtime: &mut ActorRuntime,
        approve_all: bool,
        expires_after: Duration,
    ) -> ActorHandle {
        let mut builder = runtime.new_actor::<Self>();
        builder.model.approve_all = approve_all;
        builder.model.expires_after = expires_after;
        builder.model.selected = default_selection();
        configure(&mut builder);
        builder.start().await
    }

    /// Whether anything is waiting.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Reads one key as a decision, if it is one.
    ///
    /// Returns `None` for a key that only moves the highlight, and for every
    /// key that means nothing here — an unrecognized key must never be read as
    /// consent.
    pub fn press(&mut self, key: KeyEvent) -> Option<&'static str> {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return matches!(key.code, KeyCode::Char('c')).then_some(acp::OPTION_REJECT);
        }

        match key.code {
            KeyCode::Esc => Some(acp::OPTION_REJECT),
            KeyCode::Enter => Some(CHOICES[self.selected.min(CHOICES.len() - 1)].option),
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
                None
            }
            KeyCode::Down => {
                self.selected = (self.selected + 1).min(CHOICES.len() - 1);
                None
            }
            KeyCode::Char(character) => {
                let lowered = character.to_ascii_lowercase();
                CHOICES
                    .iter()
                    .find(|choice| choice.key == lowered)
                    .map(|choice| choice.option)
            }
            _ => None,
        }
    }

    /// Removes one request when its own timer fires.
    fn take_expired(&mut self, id: &RequestId) -> Option<(String, bool)> {
        let position = self.pending.iter().position(|pending| &pending.id == id)?;
        let was_front = position == 0;
        let expired = self.pending.remove(position)?;
        if was_front {
            self.selected = default_selection();
        }
        Some((expired.title, was_front))
    }

    /// The rows this region shows right now.
    #[must_use]
    pub fn render(&self) -> RegionRendered {
        let Some(pending) = self.pending.front() else {
            return RegionRendered::empty(Region::Approval);
        };

        RegionRendered {
            region: Region::Approval,
            lines: prompt(
                pending.title.as_str(),
                pending.detail.as_deref(),
                self.selected,
                self.pending.len(),
                self.expires_after,
            ),
            cursor: Some(prompt_cursor(pending.detail.is_some(), self.selected)),
        }
    }
}

/// Places the hardware cursor on the marker for the highlighted choice.
///
/// The title occupies the first row, the expiry occupies one more, and an
/// optional detail adds another, so choices begin two or three rows down.
#[must_use]
pub fn prompt_cursor(has_detail: bool, selected: usize) -> (u16, u16) {
    let choice = selected.min(CHOICES.len().saturating_sub(1));
    let row = 2usize
        .saturating_add(usize::from(has_detail))
        .saturating_add(choice);
    (2, u16::try_from(row).unwrap_or(u16::MAX))
}

/// Builds the modal's rows.
///
/// Pure, so the wording and the highlight are testable without a terminal.
#[must_use]
pub fn prompt(
    title: &str,
    detail: Option<&str>,
    selected: usize,
    waiting: usize,
    expires_after: Duration,
) -> Vec<Line<'static>> {
    let muted = Style::default().fg(Color::DarkGray);
    let mut lines = vec![Line::from(vec![
        Span::styled("⚠ ".to_string(), Style::default().fg(Color::LightYellow)),
        Span::styled(
            title.to_string(),
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ),
    ])];

    if let Some(detail) = detail {
        lines.push(Line::from(Span::styled(format!("  {detail}"), muted)));
    }
    lines.push(Line::from(Span::styled(
        format!("  expires in {}", humanize(expires_after)),
        muted,
    )));

    for (index, choice) in CHOICES.iter().enumerate() {
        let chosen = index == selected;
        let style = if chosen {
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };

        lines.push(Line::from(vec![
            Span::styled(if chosen { "  › " } else { "    " }.to_string(), style),
            Span::styled(format!("{}  {}", choice.key, choice.label), style),
        ]));
    }

    if waiting > 1 {
        lines.push(Line::from(Span::styled(
            format!("  {} more waiting", waiting - 1),
            muted,
        )));
    }

    lines
}

/// Names the tool call in a permission request.
///
/// Falls back to the raw kind when the agent sent no title, because an empty
/// prompt is worse than an ugly one.
#[must_use]
pub fn describe(request: &acp::RequestPermissionRequest) -> (String, Option<String>) {
    let title = request.tool_call.fields.title.clone().unwrap_or_default();
    let title = if title.trim().is_empty() {
        "the agent wants to run a tool".to_string()
    } else {
        title
    };

    let detail = request
        .tool_call
        .fields
        .raw_input
        .as_ref()
        .map(|input| one_line(&input.to_string()));

    (title, detail)
}

/// Flattens a value onto one line, short enough to sit in a prompt.
#[must_use]
pub fn one_line(text: &str) -> String {
    const LIMIT: usize = 160;

    let flattened: String = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let squeezed = flattened.split_whitespace().collect::<Vec<_>>().join(" ");

    if squeezed.chars().count() <= LIMIT {
        return squeezed;
    }
    squeezed.chars().take(LIMIT - 1).chain(['…']).collect()
}

/// Wires every handler.
fn configure(builder: &mut ManagedActor<Idle, Approval>) {
    builder.mutate_on::<Wire>(|actor, context| {
        let message = context.message();
        actor.model.compositor = Some(message.compositor.clone());
        actor.model.transcript = Some(message.transcript.clone());
        actor.model.router = Some(message.router.clone());
        actor.model.session = Some(message.session.clone());
        Reply::ready()
    });

    builder.mutate_on::<PermissionAsked>(|actor, context| {
        let message = context.message();
        let (title, detail) = describe(&message.request);

        if actor.model.approve_all {
            return answer(actor, message.id.clone(), acp::OPTION_ALLOW_ONCE, &title);
        }

        let notice = permission_notice(&title);
        actor.model.pending.push_back(Pending {
            id: message.id.clone(),
            title,
            detail,
        });
        if actor.model.pending.len() == 1 {
            actor.model.selected = default_selection();
        }
        let expires_after = actor.model.expires_after;
        let id = message.id.clone();
        drop(
            actor
                .handle()
                .send_after(PermissionExpired { id }, expires_after),
        );
        open(actor, notice)
    });

    builder.mutate_on::<KeyPressed>(|actor, context| {
        let Some(option) = actor.model.press(context.message().key) else {
            return repaint(actor);
        };
        let Some(pending) = actor.model.pending.pop_front() else {
            return repaint(actor);
        };

        actor.model.selected = default_selection();
        answer(actor, pending.id, option, &pending.title)
    });

    builder.mutate_on::<PermissionExpired>(|actor, context| {
        let Some((title, was_front)) = actor.model.take_expired(&context.message().id) else {
            return Reply::ready();
        };
        expire(actor, title, was_front)
    });
}

/// One scrollback line announcing that a permission request arrived.
#[must_use]
pub fn permission_notice(title: &str) -> Line<'static> {
    notice_line(format!("permission required: {title}"))
}

/// Announces the modal in scrollback and paints it.
fn open(actor: &mut ManagedActor<Started, Approval>, notice: Line<'static>) -> FutureBox {
    let rendered = actor.model.render();
    let compositor = actor.model.compositor.clone();
    let transcript = actor.model.transcript.clone();
    let router = actor.model.router.clone();

    Reply::pending(async move {
        if let Some(transcript) = transcript {
            transcript
                .send(Note {
                    lines: vec![notice],
                })
                .await;
        }
        if let Some(router) = router {
            router
                .send(FocusChanged {
                    holder: Focus::Approval,
                })
                .await;
        }
        if let Some(compositor) = compositor {
            compositor.send(rendered).await;
        }
    })
}

/// Sends the answer, notes it, and hands focus back if the queue emptied.
fn answer(
    actor: &mut ManagedActor<Started, Approval>,
    id: RequestId,
    option: &'static str,
    title: &str,
) -> FutureBox {
    let rendered = actor.model.render();
    let still_open = actor.model.is_open();
    let compositor = actor.model.compositor.clone();
    let transcript = actor.model.transcript.clone();
    let router = actor.model.router.clone();
    let session = actor.model.session.clone();
    let note = notice_line(format!("{}: {}", verdict(option), title));

    Reply::pending(async move {
        if let Some(session) = session {
            session.send(PermissionAnswered { id, option }).await;
        }
        if let Some(transcript) = transcript {
            transcript.send(Note { lines: vec![note] }).await;
        }
        if !still_open {
            if let Some(router) = router {
                router
                    .send(FocusChanged {
                        holder: Focus::Composer,
                    })
                    .await;
            }
        }
        if let Some(compositor) = compositor {
            compositor.send(rendered).await;
        }
    })
}

/// Repaints without changing the queue.
fn repaint(actor: &mut ManagedActor<Started, Approval>) -> FutureBox {
    let rendered = actor.model.render();
    let compositor = actor.model.compositor.clone();

    Reply::pending(async move {
        if let Some(compositor) = compositor {
            compositor.send(rendered).await;
        }
    })
}

/// Clears an expired request, says why, and transfers focus when necessary.
fn expire(
    actor: &mut ManagedActor<Started, Approval>,
    title: String,
    was_front: bool,
) -> FutureBox {
    let rendered = actor.model.render();
    let still_open = actor.model.is_open();
    let compositor = actor.model.compositor.clone();
    let transcript = actor.model.transcript.clone();
    let router = actor.model.router.clone();
    let notice = notice_line(format!("permission expired and was refused: {title}"));

    Reply::pending(async move {
        if let Some(transcript) = transcript {
            transcript
                .send(Note {
                    lines: vec![notice],
                })
                .await;
        }
        if was_front && !still_open {
            if let Some(router) = router {
                router
                    .send(FocusChanged {
                        holder: Focus::Composer,
                    })
                    .await;
            }
        }
        if let Some(compositor) = compositor {
            compositor.send(rendered).await;
        }
    })
}

/// How a decision reads in the transcript.
#[must_use]
pub fn verdict(option: &str) -> &'static str {
    match option {
        acp::OPTION_ALLOW_ONCE => "allowed once",
        acp::OPTION_ALLOW_ALWAYS => "allowed for this session",
        _ => "refused",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn text(line: &Line<'static>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn escape_refuses() {
        let mut approval = Approval::default();
        assert_eq!(approval.press(key(KeyCode::Esc)), Some(acp::OPTION_REJECT));
    }

    #[test]
    fn control_c_refuses_rather_than_falling_through_to_the_composer() {
        let mut approval = Approval::default();
        let interrupt = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(approval.press(interrupt), Some(acp::OPTION_REJECT));
    }

    #[test]
    fn a_key_that_means_nothing_here_is_not_consent() {
        let mut approval = Approval::default();
        assert_eq!(approval.press(key(KeyCode::Char('z'))), None);
        assert_eq!(approval.press(key(KeyCode::Tab)), None);
        assert_eq!(approval.press(key(KeyCode::Backspace)), None);
    }

    #[test]
    fn each_letter_picks_the_choice_it_labels() {
        let mut approval = Approval::default();
        assert_eq!(
            approval.press(key(KeyCode::Char('y'))),
            Some(acp::OPTION_ALLOW_ONCE)
        );
        assert_eq!(
            approval.press(key(KeyCode::Char('a'))),
            Some(acp::OPTION_ALLOW_ALWAYS)
        );
        assert_eq!(
            approval.press(key(KeyCode::Char('n'))),
            Some(acp::OPTION_REJECT)
        );
    }

    #[test]
    fn a_capital_letter_picks_the_same_choice() {
        let mut approval = Approval::default();
        assert_eq!(
            approval.press(key(KeyCode::Char('Y'))),
            Some(acp::OPTION_ALLOW_ONCE)
        );
    }

    #[test]
    fn the_highlight_defaults_to_refuse_and_cannot_run_off_either_end() {
        let mut approval = Approval {
            selected: default_selection(),
            ..Approval::default()
        };
        assert_eq!(
            approval.press(key(KeyCode::Enter)),
            Some(acp::OPTION_REJECT)
        );
        approval.press(key(KeyCode::Up));
        assert_eq!(approval.selected, default_selection() - 1);

        for _ in 0..10 {
            approval.press(key(KeyCode::Down));
        }
        assert_eq!(approval.selected, CHOICES.len() - 1);
        assert_eq!(
            approval.press(key(KeyCode::Enter)),
            Some(acp::OPTION_REJECT)
        );
    }

    #[test]
    fn a_gate_with_nothing_pending_shows_nothing() {
        let approval = Approval::default();
        assert!(!approval.is_open());
        assert!(approval.render().lines.is_empty());
    }

    #[test]
    fn the_prompt_lists_every_choice_and_marks_the_selected_one() {
        let lines = prompt(
            "run bash",
            Some("cargo check"),
            1,
            1,
            Duration::from_secs(300),
        );
        assert_eq!(lines.len(), 3 + CHOICES.len());
        assert!(text(&lines[4]).starts_with("  ›"));
        assert!(text(&lines[3]).starts_with("    "));
    }

    #[test]
    fn the_cursor_tracks_the_highlighted_choice() {
        assert_eq!(prompt_cursor(false, 0), (2, 2));
        assert_eq!(prompt_cursor(false, 2), (2, 4));
    }

    #[test]
    fn a_detail_row_pushes_the_approval_cursor_down() {
        assert_eq!(prompt_cursor(true, 0), (2, 3));
        assert_eq!(prompt_cursor(true, 2), (2, 5));
    }

    #[test]
    fn an_out_of_range_selection_keeps_the_cursor_on_the_last_choice() {
        assert_eq!(prompt_cursor(false, usize::MAX), (2, 4));
    }

    #[test]
    fn a_queue_deeper_than_one_says_how_many_are_waiting() {
        let lines = prompt("run bash", None, 0, 3, Duration::from_secs(300));
        assert!(text(lines.last().expect("a tail row")).contains("2 more waiting"));
    }

    #[test]
    fn the_prompt_states_when_permission_expires() {
        let lines = prompt("run bash", None, 0, 1, Duration::from_secs(300));
        assert_eq!(text(&lines[1]), "  expires in 5m00s");
    }

    #[test]
    fn expiry_removes_only_the_correlated_request() {
        let mut approval = Approval::default();
        approval.pending.push_back(Pending {
            id: RequestId::Number(1),
            title: "first".to_string(),
            detail: None,
        });
        approval.pending.push_back(Pending {
            id: RequestId::Number(2),
            title: "second".to_string(),
            detail: None,
        });
        approval.selected = 1;

        assert_eq!(
            approval.take_expired(&RequestId::Number(1)),
            Some(("first".to_string(), true))
        );
        assert_eq!(approval.selected, default_selection());
        assert_eq!(approval.pending.len(), 1);
        assert_eq!(
            approval
                .pending
                .front()
                .map(|pending| pending.title.as_str()),
            Some("second")
        );
        assert!(approval.take_expired(&RequestId::Number(1)).is_none());
    }

    #[test]
    fn permission_arrival_is_worded_for_terminal_scrollback() {
        assert_eq!(
            text(&permission_notice("run cargo check")),
            "permission required: run cargo check"
        );
    }

    #[test]
    fn a_detail_is_flattened_onto_one_line_and_bounded() {
        assert_eq!(one_line("a\n  b\tc"), "a b c");
        assert_eq!(one_line(&"x".repeat(500)).chars().count(), 160);
        assert!(one_line(&"x".repeat(500)).ends_with('…'));
    }

    #[test]
    fn every_option_reads_as_something_in_the_transcript() {
        assert_eq!(verdict(acp::OPTION_ALLOW_ONCE), "allowed once");
        assert_eq!(
            verdict(acp::OPTION_ALLOW_ALWAYS),
            "allowed for this session"
        );
        assert_eq!(verdict(acp::OPTION_REJECT), "refused");
        assert_eq!(verdict("something we never offered"), "refused");
    }
}
