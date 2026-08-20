//! Wrapping styled lines to a width.
//!
//! One function serves two callers that must agree: the scrollback writer,
//! which needs to know how many terminal rows a line will occupy before it
//! scrolls the screen by that many, and the compositor, which needs the same
//! number to size the viewport. If they disagreed the screen would tear, so
//! they share this rather than each approximating.
//!
//! Pure, and therefore testable without a terminal.

use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthStr;

/// How many columns a string occupies.
#[must_use]
pub fn display_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

/// Wraps one styled line to `width` columns, preserving each span's style.
///
/// Breaks at spaces where it can and mid-word where it must, so a long
/// unbroken token still fits instead of running off the screen. A `width` of
/// zero is treated as one, because a terminal that narrow cannot be reasoned
/// about and returning no rows would lose the text entirely.
#[must_use]
pub fn wrap_line(line: &Line<'static>, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);
    let mut rows: Vec<Vec<Span<'static>>> = Vec::new();
    let mut row: Vec<Span<'static>> = Vec::new();
    let mut used = 0usize;

    for span in &line.spans {
        for chunk in split_keeping_spaces(&span.content) {
            let chunk_width = display_width(&chunk);

            // A space that falls exactly on the seam is consumed by the break
            // rather than opening the next row with a stray indent.
            if used + chunk_width > width && chunk.trim().is_empty() {
                rows.push(std::mem::take(&mut row));
                used = 0;
                continue;
            }

            if used + chunk_width > width && used > 0 {
                rows.push(std::mem::take(&mut row));
                used = 0;
            }

            for piece in hard_split(&chunk, width) {
                let piece_width = display_width(&piece);
                if used + piece_width > width && used > 0 {
                    rows.push(std::mem::take(&mut row));
                    used = 0;
                }
                used += piece_width;
                row.push(Span::styled(piece, span.style));
            }
        }
    }

    rows.push(row);
    rows.into_iter()
        .map(|spans| Line::from(spans).style(line.style))
        .collect()
}

/// Wraps a batch of lines, flattening the result.
#[must_use]
pub fn wrap_lines(lines: &[Line<'static>], width: usize) -> Vec<Line<'static>> {
    lines
        .iter()
        .flat_map(|line| wrap_line(line, width))
        .collect()
}

/// A blank line, for spacing.
#[must_use]
pub fn blank() -> Line<'static> {
    Line::from(Vec::<Span<'static>>::new()).style(Style::default())
}

/// Splits text into words and the runs of spaces between them.
///
/// Keeping the spaces as chunks is what lets the caller decide whether a break
/// swallows them, which is the difference between a clean wrap and one that
/// indents every continuation row.
fn split_keeping_spaces(text: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut in_space = false;

    for character in text.chars() {
        let is_space = character == ' ';
        if !current.is_empty() && is_space != in_space {
            chunks.push(std::mem::take(&mut current));
        }
        in_space = is_space;
        current.push(character);
    }

    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Breaks a chunk that cannot fit on any row into width-sized pieces.
///
/// Returns the chunk untouched when it already fits, which is the common case.
fn hard_split(chunk: &str, width: usize) -> Vec<String> {
    if display_width(chunk) <= width {
        return vec![chunk.to_string()];
    }

    let mut pieces = Vec::new();
    let mut current = String::new();
    let mut used = 0usize;

    for character in chunk.chars() {
        let character_width = UnicodeWidthStr::width(character.to_string().as_str());
        if used + character_width > width && !current.is_empty() {
            pieces.push(std::mem::take(&mut current));
            used = 0;
        }
        used += character_width;
        current.push(character);
    }

    if !current.is_empty() {
        pieces.push(current);
    }
    pieces
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(rows: &[Line<'static>]) -> Vec<String> {
        rows.iter()
            .map(|row| row.spans.iter().map(|span| span.content.as_ref()).collect())
            .collect()
    }

    #[test]
    fn a_line_that_fits_is_returned_as_one_row() {
        let rows = wrap_line(&Line::from("hello"), 10);
        assert_eq!(texts(&rows), vec!["hello".to_string()]);
    }

    #[test]
    fn wrapping_breaks_at_a_space_and_drops_it() {
        let rows = wrap_line(&Line::from("hello world"), 5);
        assert_eq!(texts(&rows), vec!["hello".to_string(), "world".to_string()]);
    }

    #[test]
    fn a_word_longer_than_the_width_is_broken_rather_than_lost() {
        let rows = wrap_line(&Line::from("abcdefgh"), 3);
        assert_eq!(
            texts(&rows),
            vec!["abc".to_string(), "def".to_string(), "gh".to_string()]
        );
    }

    #[test]
    fn every_wrapped_row_keeps_the_style_of_the_span_it_came_from() {
        let styled = Line::from(vec![Span::styled(
            "alpha beta",
            Style::default().fg(ratatui::style::Color::Red),
        )]);
        let rows = wrap_line(&styled, 5);

        assert_eq!(rows.len(), 2);
        for row in &rows {
            for span in &row.spans {
                assert_eq!(span.style.fg, Some(ratatui::style::Color::Red));
            }
        }
    }

    #[test]
    fn a_zero_width_still_produces_rows_rather_than_swallowing_the_text() {
        let rows = wrap_line(&Line::from("ab"), 0);
        assert_eq!(texts(&rows), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn an_empty_line_occupies_exactly_one_row() {
        assert_eq!(wrap_line(&blank(), 40).len(), 1);
    }

    #[test]
    fn a_wide_character_counts_for_two_columns() {
        assert_eq!(display_width("漢字"), 4);
        let rows = wrap_line(&Line::from("漢字漢"), 4);
        assert_eq!(texts(&rows), vec!["漢字".to_string(), "漢".to_string()]);
    }

    #[test]
    fn wrapping_a_batch_flattens_every_line() {
        let lines = vec![Line::from("hello world"), Line::from("hi")];
        assert_eq!(wrap_lines(&lines, 5).len(), 3);
    }
}
