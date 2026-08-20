//! Where the pinned rows sit, and where the next history row goes.
//!
//! All of it is arithmetic on row numbers, and none of it touches a terminal,
//! because getting this wrong is the difference between a transcript and a
//! smear. The rules it encodes are worth stating plainly:
//!
//! * History occupies rows `0..next`. The viewport occupies `y..y + height`.
//!   Rows `next..y` are blank, and are the first place new history goes.
//! * The viewport starts wherever the cursor already was, so a chat begins
//!   under the shell prompt rather than at the bottom of an empty screen, and
//!   slides down as history accumulates beneath it.
//! * Once it reaches the bottom it stays there. A viewport that drifted back
//!   up after every turn would move the place the user types, which is the one
//!   thing on the screen that must not move.
//!
//! That last rule is why shrinking leaves blank rows *above* the viewport
//! rather than below it: the composer stays put on the last row and the gap
//! closes itself, because the next thing committed to history is written into
//! exactly those rows.

use ratatui::layout::{Rect, Size};

/// The rows that must stay above the viewport for history to scroll through.
///
/// The scroll region used to push a line into scrollback needs at least one
/// row to work in, so a viewport is never allowed to cover the whole screen.
pub const MIN_HISTORY_ROWS: u16 = 1;

/// The size assumed when the terminal will not say how big it is.
///
/// A pty opened without one — by `script`, by a CI runner, by a process whose
/// parent had no window — reports zero. Believing that produces a one-column
/// screen and a transcript written one character per row, so it is not
/// believed.
pub const ASSUMED_SIZE: Size = Size {
    width: 80,
    height: 24,
};

/// Replaces a size the terminal could not report with one that works.
#[must_use]
pub const fn usable(size: Size) -> Size {
    if size.width == 0 || size.height == 0 {
        return ASSUMED_SIZE;
    }
    size
}

/// The tallest viewport a screen of this size allows.
#[must_use]
pub const fn ceiling(screen: Size) -> u16 {
    let room = screen.height.saturating_sub(MIN_HISTORY_ROWS);
    if room == 0 {
        1
    } else {
        room
    }
}

/// The screen's current division into history and pinned rows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Geometry {
    /// The viewport's top row, zero-based.
    pub y: u16,
    /// How many rows the viewport occupies.
    pub height: u16,
    /// The row the next history line is written to, zero-based.
    ///
    /// Never greater than `y`; the rows between the two are blank.
    pub next: u16,
    /// Whether the viewport has reached the bottom and stays there.
    pub pinned: bool,
}

impl Geometry {
    /// The geometry a chat starts with: one row, at the cursor.
    #[must_use]
    pub const fn new(cursor_row: u16, screen: Size) -> Self {
        let height = 1;
        let floor = screen.height.saturating_sub(height);
        let y = if cursor_row < floor {
            cursor_row
        } else {
            floor
        };

        Self {
            y,
            height,
            next: y,
            pinned: y == floor,
        }
    }

    /// The row just past the viewport.
    #[must_use]
    pub const fn bottom(&self) -> u16 {
        self.y.saturating_add(self.height)
    }

    /// How many blank rows sit between the history and the viewport.
    #[must_use]
    pub const fn gap(&self) -> u16 {
        self.y.saturating_sub(self.next)
    }

    /// The viewport as a rectangle.
    #[must_use]
    pub const fn area(&self, screen: Size) -> Rect {
        Rect {
            x: 0,
            y: self.y,
            width: screen.width,
            height: self.height,
        }
    }
}

/// What changing the viewport's height requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resize {
    /// Where everything ends up.
    pub geometry: Geometry,
    /// Rows the history above must scroll up to make room for growth.
    pub scroll_up: u16,
    /// Rows the viewport vacated at its top, which are now blank history.
    pub vacated: u16,
}

/// Works out what a new viewport height costs.
///
/// Growth is paid for out of the gap first and out of scrollback only when the
/// gap runs out, which is what keeps a status line appearing and disappearing
/// from scrolling the screen back and forth.
#[must_use]
pub const fn resize(before: Geometry, height: u16, screen: Size) -> Resize {
    let limit = ceiling(screen);
    let height = if height < 1 {
        1
    } else if height > limit {
        limit
    } else {
        height
    };
    let floor = screen.height.saturating_sub(height);

    let target = if before.pinned || before.next > floor {
        floor
    } else {
        before.next
    };

    let scroll_up = if target < before.y {
        (before.y - target).saturating_sub(before.gap())
    } else {
        0
    };
    let vacated = target.saturating_sub(before.y);

    let next = {
        let scrolled = before.next.saturating_sub(scroll_up);
        if scrolled > target {
            target
        } else {
            scrolled
        }
    };

    Resize {
        geometry: Geometry {
            y: target,
            height,
            next,
            pinned: before.pinned || target == floor,
        },
        scroll_up,
        vacated,
    }
}

/// What adding history rows requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insert {
    /// Where everything ends up.
    pub geometry: Geometry,
    /// Rows the viewport must slide down before anything is written.
    pub shift: u16,
    /// The row the directly-written lines start at.
    pub at: u16,
    /// How many lines are written straight into blank rows.
    pub direct: u16,
    /// How many are left to scroll into the band above the viewport.
    pub overflow: u16,
}

/// Works out where `rows` new history lines go.
///
/// Lines land in blank rows while there are any, because writing into a blank
/// row disturbs nothing. Only once the viewport has reached the bottom does a
/// line have to push the screen's top row into scrollback to make space.
#[must_use]
pub const fn insert(before: Geometry, rows: u16, screen: Size) -> Insert {
    let floor = screen.height.saturating_sub(before.height);
    let capacity = floor.saturating_sub(before.next);
    let direct = if rows < capacity { rows } else { capacity };
    let shift = direct.saturating_sub(before.gap());
    let y = before.y.saturating_add(shift);
    let next = before.next.saturating_add(direct);

    Insert {
        geometry: Geometry {
            y,
            height: before.height,
            next,
            pinned: before.pinned || y == floor,
        },
        shift,
        at: before.next,
        direct,
        overflow: rows.saturating_sub(direct),
    }
}

/// Refits the geometry to a screen that changed shape.
///
/// A reflowed screen has moved everything anyway, so this only re-establishes
/// the invariants rather than pretending to know where any particular row
/// ended up.
#[must_use]
pub const fn refit(before: Geometry, screen: Size) -> Geometry {
    let limit = ceiling(screen);
    let height = if before.height > limit {
        limit
    } else {
        before.height
    };
    let floor = screen.height.saturating_sub(height);
    let next = if before.next > floor {
        floor
    } else {
        before.next
    };
    let y = if before.pinned { floor } else { next };

    Geometry {
        y,
        height,
        next,
        pinned: before.pinned || y == floor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCREEN: Size = Size {
        width: 80,
        height: 30,
    };

    fn started() -> Geometry {
        Geometry::new(3, SCREEN)
    }

    #[test]
    fn a_chat_starts_where_the_cursor_already_was() {
        let geometry = started();

        assert_eq!(geometry.y, 3);
        assert_eq!(geometry.next, 3);
        assert!(!geometry.pinned);
    }

    #[test]
    fn a_chat_started_on_the_last_row_is_pinned_at_once() {
        let geometry = Geometry::new(29, SCREEN);

        assert_eq!(geometry.y, 29);
        assert!(geometry.pinned);
    }

    #[test]
    fn history_slides_the_viewport_down_while_there_is_room() {
        let added = insert(started(), 4, SCREEN);

        assert_eq!(added.at, 3);
        assert_eq!(added.direct, 4);
        assert_eq!(added.shift, 4);
        assert_eq!(added.overflow, 0);
        assert_eq!(added.geometry.y, 7);
        assert_eq!(added.geometry.next, 7);
    }

    #[test]
    fn history_stops_sliding_at_the_bottom_and_scrolls_instead() {
        let added = insert(started(), 40, SCREEN);

        // 29 rows of the screen can hold history before the one-row viewport
        // has to sit on the last row; the rest is scrollback's problem.
        assert_eq!(added.direct, 26);
        assert_eq!(added.overflow, 14);
        assert_eq!(added.geometry.y, 29);
        assert!(added.geometry.pinned);
    }

    #[test]
    fn a_pinned_viewport_writes_everything_through_the_scroll_region() {
        let pinned = insert(started(), 40, SCREEN).geometry;
        let added = insert(pinned, 3, SCREEN);

        assert_eq!(added.direct, 0);
        assert_eq!(added.shift, 0);
        assert_eq!(added.overflow, 3);
        assert_eq!(added.geometry, pinned);
    }

    #[test]
    fn growing_below_the_bottom_costs_nothing() {
        let grown = resize(started(), 4, SCREEN);

        assert_eq!(grown.geometry.y, 3);
        assert_eq!(grown.geometry.height, 4);
        assert_eq!(grown.scroll_up, 0);
    }

    #[test]
    fn growing_past_the_bottom_scrolls_the_history_up() {
        let pinned = insert(started(), 40, SCREEN).geometry;
        let grown = resize(pinned, 5, SCREEN);

        assert_eq!(grown.geometry.y, 25);
        assert_eq!(grown.geometry.next, 25);
        assert_eq!(grown.scroll_up, 4);
    }

    #[test]
    fn shrinking_keeps_the_viewport_on_the_last_row() {
        let pinned = insert(started(), 40, SCREEN).geometry;
        let grown = resize(pinned, 6, SCREEN).geometry;
        let shrunk = resize(grown, 1, SCREEN);

        // The composer does not move up the screen when the status line goes
        // away; the rows it gives back become blank history instead.
        assert_eq!(shrunk.geometry.bottom(), SCREEN.height);
        assert_eq!(shrunk.geometry.y, 29);
        assert_eq!(shrunk.geometry.next, 24);
        assert_eq!(shrunk.geometry.gap(), 5);
        assert_eq!(shrunk.vacated, 5);
        assert_eq!(shrunk.scroll_up, 0);
    }

    #[test]
    fn the_gap_a_shrink_leaves_is_filled_by_the_next_history_without_scrolling() {
        let pinned = insert(started(), 40, SCREEN).geometry;
        let grown = resize(pinned, 6, SCREEN).geometry;
        let shrunk = resize(grown, 1, SCREEN).geometry;

        let added = insert(shrunk, 5, SCREEN);

        assert_eq!(added.at, 24);
        assert_eq!(added.direct, 5);
        assert_eq!(added.shift, 0);
        assert_eq!(added.overflow, 0);
        assert_eq!(added.geometry.gap(), 0);
        assert_eq!(added.geometry.y, 29);
    }

    #[test]
    fn regrowing_into_the_gap_scrolls_nothing() {
        let pinned = insert(started(), 40, SCREEN).geometry;
        let shrunk = resize(resize(pinned, 6, SCREEN).geometry, 1, SCREEN).geometry;
        let regrown = resize(shrunk, 6, SCREEN);

        assert_eq!(regrown.scroll_up, 0);
        assert_eq!(regrown.geometry.y, 24);
        assert_eq!(regrown.geometry.next, 24);
    }

    #[test]
    fn a_viewport_never_covers_the_whole_screen() {
        let grown = resize(started(), 999, SCREEN);

        assert_eq!(grown.geometry.height, SCREEN.height - MIN_HISTORY_ROWS);
        assert!(grown.geometry.y >= MIN_HISTORY_ROWS);
    }

    #[test]
    fn a_terminal_that_reports_no_size_is_not_believed() {
        assert_eq!(usable(Size::new(0, 0)), ASSUMED_SIZE);
        assert_eq!(usable(Size::new(0, 40)), ASSUMED_SIZE);
        assert_eq!(usable(Size::new(120, 0)), ASSUMED_SIZE);
    }

    #[test]
    fn a_real_size_is_left_alone() {
        assert_eq!(usable(Size::new(120, 40)), Size::new(120, 40));
    }

    #[test]
    fn a_shorter_screen_pulls_everything_back_inside_it() {
        let pinned = insert(started(), 40, SCREEN).geometry;
        let smaller = Size::new(80, 10);
        let fitted = refit(pinned, smaller);

        assert!(fitted.bottom() <= smaller.height);
        assert!(fitted.next <= fitted.y);
    }
}
