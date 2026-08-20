//! Slash commands.
//!
//! Pure parsing and pure descriptions; what a command *does* lives with the
//! actor that owns the state it changes.

/// Something the user asked for by name rather than by asking the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// List the commands.
    Help,
    /// Start a fresh session, forgetting the conversation so far.
    New,
    /// Show the agent's governance settings.
    Status,
    /// Clear the screen, keeping the session.
    Clear,
    /// Leave.
    Quit,
}

/// Every command, in the order they should be listed.
///
/// Deliberately not alphabetical: this is presentation order, and the useful
/// ones belong at the top.
pub const ALL: [Command; 5] = [
    Command::Help,
    Command::New,
    Command::Status,
    Command::Clear,
    Command::Quit,
];

impl Command {
    /// What the user types, without the slash.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Help => "help",
            Self::New => "new",
            Self::Status => "status",
            Self::Clear => "clear",
            Self::Quit => "quit",
        }
    }

    /// One line describing it.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Help => "list these commands",
            Self::New => "start a new session, forgetting this conversation",
            Self::Status => "show the agent's approval policy and audit settings",
            Self::Clear => "clear the screen",
            Self::Quit => "leave",
        }
    }
}

/// Reads a submitted line as a command, if it is one.
///
/// Returns the command and whatever followed it, trimmed. A line that starts
/// with a slash but names nothing known is *not* a command: it is a message
/// that happens to begin with a slash, and sending it to the model is a better
/// answer than an error about a typo the user may not have made.
#[must_use]
pub fn parse(line: &str) -> Option<(Command, &str)> {
    let rest = line.trim_start().strip_prefix('/')?;
    let (name, arguments) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));

    ALL.iter()
        .find(|command| command.name() == name)
        .map(|command| (*command, arguments.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_command_parses_with_no_arguments() {
        assert_eq!(parse("/quit"), Some((Command::Quit, "")));
    }

    #[test]
    fn arguments_are_returned_trimmed() {
        assert_eq!(
            parse("/new   a fresh start "),
            Some((Command::New, "a fresh start"))
        );
    }

    #[test]
    fn leading_whitespace_does_not_hide_a_command() {
        assert_eq!(parse("  /help"), Some((Command::Help, "")));
    }

    #[test]
    fn a_line_without_a_slash_is_never_a_command() {
        assert_eq!(parse("quit"), None);
    }

    #[test]
    fn an_unknown_slash_word_stays_a_message() {
        assert_eq!(parse("/etc/passwd is a file"), None);
    }

    #[test]
    fn every_command_has_a_distinct_name() {
        let mut names: Vec<&str> = ALL.iter().map(|command| command.name()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    #[test]
    fn every_command_parses_back_to_itself() {
        for command in ALL {
            assert_eq!(parse(&format!("/{}", command.name())), Some((command, "")));
        }
    }
}
