//! What the interface's actors say to each other.
//!
//! The interface is not one object that draws a screen. It is a handful of
//! actors that each own one thing — the input buffer, the status line, the
//! streaming reply, the permission queue, the connection — and one compositor
//! that owns the terminal. A region actor never writes to the screen; it
//! renders its own rows and sends them to the compositor, which is the only
//! writer and therefore the only place a frame can tear.
//!
//! That split is what lets a message the user types mid-turn appear straight
//! away, in the transcript, next to whatever the agent happens to be doing:
//! the transcript owns its own region and does not have to wait for the turn
//! to end before it can say anything.

use crate::duplex::AgentEvent;
use crate::protocol::acp;
use crate::protocol::jsonrpc::RequestId;
use acton_reactive::prelude::*;
use ratatui::layout::Size;
use ratatui::text::Line;
use std::sync::Arc;

/// A band of the pinned viewport, and its place in the stack.
///
/// The ordering is the drawing order, top to bottom, which is why this derives
/// `Ord` rather than leaving the arrangement to whoever iterates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Region {
    /// The unfinished tail of the agent's current reply.
    Tail,
    /// What the agent is doing, and for how long.
    Status,
    /// A permission the agent is blocked on.
    Approval,
    /// Where the user types.
    Composer,
}

/// One region's current appearance.
#[acton_message]
pub struct RegionRendered {
    /// Which band these rows belong to.
    pub region: Region,
    /// The rows, unwrapped; the compositor wraps them to the real width.
    pub lines: Vec<Line<'static>>,
    /// Where the cursor belongs, relative to this region's first row.
    ///
    /// At most one region asks for the cursor at a time; the compositor takes
    /// the topmost that does.
    pub cursor: Option<(u16, u16)>,
}

impl RegionRendered {
    /// A region with nothing to show.
    #[must_use]
    pub const fn empty(region: Region) -> Self {
        Self {
            region,
            lines: Vec::new(),
            cursor: None,
        }
    }

    /// A region showing `lines` and not holding the cursor.
    #[must_use]
    pub const fn showing(region: Region, lines: Vec<Line<'static>>) -> Self {
        Self {
            region,
            lines,
            cursor: None,
        }
    }
}

/// Rows that are finished, for the terminal's own scrollback.
///
/// Once committed they are the terminal's: scrollable, searchable, and
/// selectable, and beyond this program's power to redraw.
#[acton_message]
pub struct CommitHistory {
    /// The rows to write above the viewport.
    pub lines: Vec<Line<'static>>,
}

/// Draw the frame now, if anything changed since the last one.
///
/// Sent to the compositor by itself, on a short delay, so a burst of streaming
/// tokens collapses into one repaint instead of one per token.
#[acton_message]
pub struct DrawTick;

/// The terminal changed shape.
#[acton_message]
pub struct ScreenResized {
    /// The new size, in cells.
    pub size: Size,
}

/// Give the terminal back and stop.
#[acton_message]
pub struct Shutdown;

/// A key the user pressed.
#[acton_message]
pub struct KeyPressed {
    /// The event, exactly as the terminal reported it.
    pub key: crossterm::event::KeyEvent,
}

/// Text the user pasted, which is never interpreted as keys.
#[acton_message]
pub struct Pasted {
    /// The pasted text.
    pub text: String,
}

/// Who keys go to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Focus {
    /// The composer, which is where focus rests.
    #[default]
    Composer,
    /// A modal that has taken over until it is answered.
    Approval,
}

/// Focus moved, because a modal opened or closed.
#[acton_message]
pub struct FocusChanged {
    /// Who has it now.
    pub holder: Focus,
}

/// The user finished a message and pressed Enter.
#[acton_message]
pub struct Submitted {
    /// What they typed.
    pub text: String,
}

/// The user asked to stop whatever is running.
#[acton_message]
pub struct Interrupt {
    /// Whether to leave when there was nothing to stop.
    ///
    /// Ctrl+C means "stop, and if nothing was running, stop the program";
    /// Esc means only the first half. The distinction is settled by whoever
    /// knows whether a turn is open, which is the session, not the keyboard.
    pub quit_when_idle: bool,
}

/// The user asked to leave.
#[acton_message]
pub struct Quit;

/// A turn began.
#[acton_message]
pub struct TurnStarted;

/// A turn ended, however it ended.
#[acton_message]
pub struct TurnEnded;

/// A tool call started.
#[acton_message]
pub struct ToolStarted {
    /// The agent's id for this call.
    pub id: String,
    /// What to show a person.
    pub title: String,
}

/// A tool call finished.
#[acton_message]
pub struct ToolEnded {
    /// The agent's id for this call.
    pub id: String,
}

/// Refresh the elapsed time in the status line.
#[acton_message]
pub struct StatusTick;

/// A piece of the agent's reply arrived.
#[acton_message]
pub struct AgentChunk {
    /// The text, which may end mid-word and mid-line.
    pub text: String,
}

/// The agent's reply is complete; flush whatever is still buffered.
#[acton_message]
pub struct AgentFinished;

/// Something worth putting in the transcript that did not come from the model.
///
/// Errors, notices, the user's own messages, tool outcomes: anything whose
/// styling the sender has already decided.
#[acton_message]
pub struct Note {
    /// The rows to commit, already styled.
    pub lines: Vec<Line<'static>>,
}

/// The agent is blocked on a permission.
#[acton_message]
pub struct PermissionAsked {
    /// The id the answer must carry.
    pub id: RequestId,
    /// What the agent wants to do.
    pub request: Box<acp::RequestPermissionRequest>,
}

/// The visible lifetime of a permission request elapsed without an answer.
#[acton_message]
pub struct PermissionExpired {
    /// The request to remove if it is still pending.
    pub id: RequestId,
}

/// A permission was answered.
#[acton_message]
pub struct PermissionAnswered {
    /// The id being answered.
    pub id: RequestId,
    /// The option chosen, one of the ids in [`acp::permission_options`].
    pub option: &'static str,
}

/// Clear everything the terminal is holding, scrollback included.
#[acton_message]
pub struct ClearHistory;

/// Something the agent said, on its own schedule.
///
/// [`AgentEvent`] is not `Clone` — it carries the only copy of a request the
/// agent is blocked on — so it travels behind an [`Arc`] rather than being
/// duplicated into a message the way everything else here is.
#[acton_message]
pub struct FromAgent {
    /// What arrived.
    pub event: Arc<AgentEvent>,
}

/// Every handle the interface's actors need, delivered once at startup.
///
/// Handles cannot be built before the actors they name, and an actor's model
/// must be `Default`, so wiring is a message rather than a constructor
/// argument. Every actor stores the fields it uses and ignores the rest.
#[acton_message]
pub struct Wire {
    /// The only writer to the terminal.
    pub compositor: ActorHandle,
    /// The transcript and its streaming tail.
    pub transcript: ActorHandle,
    /// The status line.
    pub status: ActorHandle,
    /// The input buffer.
    pub composer: ActorHandle,
    /// The permission queue.
    pub approval: ActorHandle,
    /// The key router.
    pub router: ActorHandle,
    /// The connection to the agent.
    pub session: ActorHandle,
}
