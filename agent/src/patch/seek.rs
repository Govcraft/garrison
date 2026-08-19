//! Locating a hunk's context in a file that has drifted since the model read it.
//!
//! Entirely pure: slices of lines in, an answer out. No IO, no allocation of
//! the file, nothing to mock.
//!
//! # Progressive leniency
//!
//! A file changes between the model reading it and the patch arriving —
//! reformatting, a different indent, smart quotes from a paste. So the search
//! runs in tiers, strictest first, and stops at the first tier that finds
//! anything:
//!
//! 1. [`Fidelity::Exact`] — byte-for-byte.
//! 2. [`Fidelity::TrailingWhitespace`] — ignoring what is at the end of a line.
//! 3. [`Fidelity::Whitespace`] — ignoring indentation too.
//! 4. [`Fidelity::Punctuation`] — folding typographic dashes, quotes, and
//!    exotic spaces to their ASCII equivalents.
//!
//! Reporting the tier matters: a match found only at the loosest tier is one a
//! reviewer may want to look at, and an audit entry that recorded merely "it
//! applied" would have thrown that away.
//!
//! # Two or more matches is a failure, not a choice
//!
//! Codex, from which the tiering idea comes, returns the first match. Garrison
//! refuses. Two identical candidate regions mean the patch does not say which
//! one it meant, and silently editing the wrong one of two identical blocks is
//! the failure that costs the most to find later: the code compiles, the tests
//! pass, and the bug is somewhere nobody is looking. A hard failure with both
//! line numbers costs one turn.

/// How closely a match had to be squinted at.
///
/// Ordered strictest to loosest, so `<` means "stricter than".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fidelity {
    /// Byte-for-byte.
    Exact,
    /// Equal once trailing whitespace is ignored.
    TrailingWhitespace,
    /// Equal once leading and trailing whitespace are ignored.
    Whitespace,
    /// Equal once typographic punctuation is folded to ASCII.
    Punctuation,
}

impl Fidelity {
    /// Every tier, strictest first.
    const ALL: [Self; 4] = [
        Self::Exact,
        Self::TrailingWhitespace,
        Self::Whitespace,
        Self::Punctuation,
    ];

    /// Whether two lines are equal at this tier.
    #[must_use]
    pub fn matches(self, left: &str, right: &str) -> bool {
        match self {
            Self::Exact => left == right,
            Self::TrailingWhitespace => left.trim_end() == right.trim_end(),
            Self::Whitespace => left.trim() == right.trim(),
            Self::Punctuation => fold(left) == fold(right),
        }
    }

    /// How the tier reads in a diagnostic.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Exact => "exactly",
            Self::TrailingWhitespace => "ignoring trailing whitespace",
            Self::Whitespace => "ignoring indentation",
            Self::Punctuation => "ignoring typographic punctuation",
        }
    }
}

/// Where a pattern was found, and how hard it had to be looked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    /// Zero-based index of the first line of the match.
    pub index: usize,
    /// The strictest tier at which it matched.
    pub fidelity: Fidelity,
}

/// The best place the pattern nearly matched, for a failure message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NearMiss {
    /// Zero-based index where the near match began.
    pub index: usize,
    /// How many of the pattern's lines lined up before it diverged.
    pub matched: usize,
    /// The pattern line that did not match.
    pub expected: String,
    /// The file line found in its place.
    pub found: String,
}

impl NearMiss {
    /// Renders the miss the way a model can act on it.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "closest match at line {}: {} of {} context lines lined up, then expected {:?} but \
             found {:?}",
            self.index + 1,
            self.matched,
            self.matched + 1,
            self.expected,
            self.found,
        )
    }
}

/// The outcome of a search.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Located {
    /// Exactly one place matched at the strictest tier that matched anything.
    At(Found),
    /// Several places matched equally well, so the patch is under-specified.
    Ambiguous {
        /// The tier at which they all matched.
        fidelity: Fidelity,
        /// Zero-based indices of every candidate, in file order.
        indices: Vec<usize>,
    },
    /// Nothing matched at any tier.
    Missing {
        /// The best near match, when there was any line to compare against.
        closest: Option<NearMiss>,
    },
}

impl Located {
    /// Renders the outcome as a diagnostic a model can act on.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::At(found) => format!(
                "matched at line {} ({})",
                found.index + 1,
                found.fidelity.describe()
            ),
            Self::Ambiguous { fidelity, indices } => {
                let lines: Vec<String> = indices
                    .iter()
                    .map(|index| (index + 1).to_string())
                    .collect();
                format!(
                    "the context matches {} places {} (lines {}); add surrounding lines or an \
                     '@@' anchor so exactly one is meant",
                    indices.len(),
                    fidelity.describe(),
                    lines.join(", "),
                )
            }
            Self::Missing { closest } => match closest {
                Some(miss) => format!("the context was not found; {}", miss.describe()),
                None => {
                    "the context was not found, and the file has no comparable lines".to_string()
                }
            },
        }
    }
}

/// Finds `pattern` in `lines` at or after `start`.
///
/// `at_end_of_file` biases the search to the last possible position, which is
/// what `*** End of File` means. The bias never searches backwards past
/// `start`: a hunk may not land on ground an earlier hunk in the same file
/// already claimed.
#[must_use]
pub fn locate(lines: &[String], pattern: &[String], start: usize, at_end_of_file: bool) -> Located {
    if pattern.is_empty() {
        return Located::At(Found {
            index: start.min(lines.len()),
            fidelity: Fidelity::Exact,
        });
    }
    if pattern.len() > lines.len() {
        return Located::Missing { closest: None };
    }

    let last_start = lines.len() - pattern.len();
    if start > last_start {
        return Located::Missing {
            closest: near_miss(lines, pattern, start.min(last_start)),
        };
    }

    let from = if at_end_of_file {
        last_start.max(start)
    } else {
        start
    };

    for fidelity in Fidelity::ALL {
        let indices: Vec<usize> = (from..=last_start)
            .filter(|index| window_matches(lines, pattern, *index, fidelity))
            .collect();

        match indices.as_slice() {
            [] => {}
            [only] => {
                return Located::At(Found {
                    index: *only,
                    fidelity,
                })
            }
            _ => return Located::Ambiguous { fidelity, indices },
        }
    }

    Located::Missing {
        closest: near_miss(&lines[from..], pattern, from),
    }
}

/// Whether the window at `index` matches the whole pattern at this tier.
fn window_matches(lines: &[String], pattern: &[String], index: usize, fidelity: Fidelity) -> bool {
    pattern
        .iter()
        .enumerate()
        .all(|(offset, wanted)| fidelity.matches(&lines[index + offset], wanted))
}

/// Finds the window that lined up for the most lines before diverging.
///
/// Scored at the loosest tier, because the point is to show a human the place
/// they most likely meant, not to relitigate the match.
fn near_miss(lines: &[String], pattern: &[String], offset: usize) -> Option<NearMiss> {
    if lines.is_empty() || pattern.is_empty() {
        return None;
    }

    let mut best: Option<NearMiss> = None;

    for index in 0..lines.len() {
        let mut matched = 0;
        while matched < pattern.len()
            && index + matched < lines.len()
            && Fidelity::Punctuation.matches(&lines[index + matched], &pattern[matched])
        {
            matched += 1;
        }

        // A window that ran off the end of the file diverged at nothing there
        // is to quote, so it is not the miss to show.
        if index + matched >= lines.len() {
            continue;
        }

        let candidate = NearMiss {
            index: index + offset,
            matched,
            expected: pattern[matched.min(pattern.len() - 1)].clone(),
            found: lines[index + matched].clone(),
        };

        if best
            .as_ref()
            .is_none_or(|current| current.matched < matched)
        {
            best = Some(candidate);
        }
    }

    best
}

/// Folds typographic punctuation to ASCII, and trims.
///
/// Pasted prose acquires curly quotes and en dashes on the way through a chat
/// window. A patch that differs from the file by nothing but the shape of an
/// apostrophe is a patch that should apply.
fn fold(text: &str) -> String {
    text.trim()
        .chars()
        .map(|character| match character {
            '\u{2010}'..='\u{2015}' | '\u{2212}' => '-',
            '\u{2018}'..='\u{201B}' => '\'',
            '\u{201C}'..='\u{201F}' => '"',
            '\u{00A0}' | '\u{2002}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}' => ' ',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|line| (*line).to_string()).collect()
    }

    #[test]
    fn an_exact_match_is_found_at_its_line() {
        let haystack = lines(&["fn one() {}", "fn two() {}", "fn three() {}"]);
        let needle = lines(&["fn two() {}"]);

        assert_eq!(
            locate(&haystack, &needle, 0, false),
            Located::At(Found {
                index: 1,
                fidelity: Fidelity::Exact
            })
        );
    }

    #[test]
    fn drifted_indentation_still_matches_and_says_so() {
        let haystack = lines(&["        let x = 1;", "        let y = 2;"]);
        let needle = lines(&["    let x = 1;", "    let y = 2;"]);

        let located = locate(&haystack, &needle, 0, false);

        assert_eq!(
            located,
            Located::At(Found {
                index: 0,
                fidelity: Fidelity::Whitespace
            })
        );
        assert!(located.describe().contains("ignoring indentation"));
    }

    #[test]
    fn trailing_whitespace_is_forgiven_before_indentation_is() {
        let haystack = lines(&["let x = 1;   "]);
        let needle = lines(&["let x = 1;"]);

        assert_eq!(
            locate(&haystack, &needle, 0, false),
            Located::At(Found {
                index: 0,
                fidelity: Fidelity::TrailingWhitespace
            })
        );
    }

    #[test]
    fn typographic_punctuation_is_folded_as_a_last_resort() {
        let haystack = lines(&["it\u{2019}s a \u{201C}quote\u{201D} \u{2014} really"]);
        let needle = lines(&["it's a \"quote\" - really"]);

        assert_eq!(
            locate(&haystack, &needle, 0, false),
            Located::At(Found {
                index: 0,
                fidelity: Fidelity::Punctuation
            })
        );
    }

    #[test]
    fn two_identical_regions_are_ambiguous_rather_than_first_wins() {
        let haystack = lines(&["a", "target", "b", "target", "c"]);
        let needle = lines(&["target"]);

        let located = locate(&haystack, &needle, 0, false);

        assert_eq!(
            located,
            Located::Ambiguous {
                fidelity: Fidelity::Exact,
                indices: vec![1, 3],
            }
        );
        let message = located.describe();
        assert!(message.contains("lines 2, 4"), "unexpected: {message}");
    }

    #[test]
    fn a_cursor_past_the_first_copy_disambiguates_it() {
        let haystack = lines(&["a", "target", "b", "target", "c"]);
        let needle = lines(&["target"]);

        assert_eq!(
            locate(&haystack, &needle, 2, false),
            Located::At(Found {
                index: 3,
                fidelity: Fidelity::Exact
            })
        );
    }

    #[test]
    fn a_missing_context_reports_where_it_came_closest() {
        let haystack = lines(&["fn one() {}", "    let x = 1;", "    let y = 9;", "}"]);
        let needle = lines(&["    let x = 1;", "    let y = 2;"]);

        let Located::Missing {
            closest: Some(miss),
        } = locate(&haystack, &needle, 0, false)
        else {
            panic!("expected a near miss");
        };

        assert_eq!(miss.index, 1);
        assert_eq!(miss.matched, 1);
        assert_eq!(miss.found, "    let y = 9;");
        assert!(miss.describe().contains("line 2"), "{}", miss.describe());
    }

    #[test]
    fn a_pattern_longer_than_the_file_cannot_match() {
        let haystack = lines(&["only one line"]);
        let needle = lines(&["too", "many", "lines"]);

        assert_eq!(
            locate(&haystack, &needle, 0, false),
            Located::Missing { closest: None }
        );
    }

    #[test]
    fn an_empty_pattern_matches_at_the_cursor() {
        let haystack = lines(&["a", "b"]);

        assert_eq!(
            locate(&haystack, &[], 1, false),
            Located::At(Found {
                index: 1,
                fidelity: Fidelity::Exact
            })
        );
    }

    #[test]
    fn end_of_file_prefers_the_last_position() {
        let haystack = lines(&["x", "y", "x", "y"]);
        let needle = lines(&["x", "y"]);

        assert_eq!(
            locate(&haystack, &needle, 0, true),
            Located::At(Found {
                index: 2,
                fidelity: Fidelity::Exact
            })
        );
    }

    #[test]
    fn end_of_file_never_searches_back_past_the_cursor() {
        // The cursor is already beyond the last possible start, so an
        // end-of-file hunk must fail rather than reapply to claimed ground.
        let haystack = lines(&["x", "y"]);
        let needle = lines(&["x", "y"]);

        assert!(matches!(
            locate(&haystack, &needle, 1, true),
            Located::Missing { .. }
        ));
    }

    #[test]
    fn a_stricter_tier_wins_over_a_looser_ambiguity() {
        // One exact match and two whitespace-only matches: the exact one is
        // unambiguous, so the looser tier is never reached.
        let haystack = lines(&["  target", "target", "\ttarget"]);
        let needle = lines(&["target"]);

        assert_eq!(
            locate(&haystack, &needle, 0, false),
            Located::At(Found {
                index: 1,
                fidelity: Fidelity::Exact
            })
        );
    }
}
