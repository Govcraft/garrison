//! Reading a shell command as the programs it actually runs.
//!
//! # Why a rule cannot be written against the string
//!
//! `bash -lc "rm -rf /"` does not contain the word `rm` in any position a
//! prefix rule could name, and `git status && rm -rf /` runs two programs
//! while looking like one. A policy that matched the shell string would be
//! defeated by whitespace. So the string is taken apart into the sequence of
//! `(program, argv)` pairs it will actually execute, and each of those is
//! decided on its own.
//!
//! # Where the seeing stops
//!
//! Not every shell construct can be read statically, and the ones that cannot
//! are the interesting ones: `$(…)`, backticks, `eval`, aliases, a script
//! whose contents nobody here has. This module does not pretend. Anything it
//! cannot take apart comes back as an [`ArgvError`], and the caller
//! turns that into a prompt — never into an approval. A bundle that wants to
//! close the gap entirely writes a `forbid` rule on `sh`, `bash`, and `eval`,
//! which is documented rather than implied.
//!
//! # What is unwrapped, and what deliberately is not
//!
//! A shell invoked with `-c` is unwrapped, because otherwise every rule in
//! every bundle could be bypassed by prefixing `bash -lc`. `sudo`, `doas`,
//! `nohup`, `time`, and `xargs` are **not** unwrapped: each of them changes
//! what running the inner command means, so a bundle author who wants to
//! allow `sudo systemctl restart x` has to say `sudo`, and will see that they
//! are saying it.

/// One program the shell command will run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    /// The basename of `argv[0]`, so `/usr/bin/git` and `git` are one program.
    pub program: String,
    /// Everything after the program.
    pub argv: Vec<String>,
}

impl Command {
    /// The command as a rule author would write it, for a refusal message.
    #[must_use]
    pub fn display(&self) -> String {
        if self.argv.is_empty() {
            return self.program.clone();
        }
        format!("{} {}", self.program, self.argv.join(" "))
    }
}

/// Why a shell command could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgvError {
    /// The quoting does not close, so there is no word list to decide on.
    Unquoted,
    /// A construct whose result is only known at run time: `$(…)`, a
    /// backtick, a process substitution.
    Dynamic(String),
    /// A shell was invoked with `-c` and no command after it.
    MissingScript,
    /// Shells wrapping shells, past the point worth following.
    TooDeep,
}

impl std::fmt::Display for ArgvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unquoted => write!(f, "the command's quoting does not close"),
            Self::Dynamic(what) => write!(
                f,
                "the command contains {what}, whose result is only known when it runs"
            ),
            Self::MissingScript => write!(f, "a shell was invoked with -c and nothing to run"),
            Self::TooDeep => write!(f, "the command nests shells more deeply than policy reads"),
        }
    }
}

impl std::error::Error for ArgvError {}

/// How many `sh -c` wrappers deep this will follow before giving up.
const MAX_DEPTH: usize = 4;

/// Shells whose `-c` argument is itself a command.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ash", "ksh"];

/// The characters a token is made of when it separates two commands.
///
/// A token rather than a substring: `&&`, `||`, `;`, `|`, `;;`, `|&` and any
/// run of them end one command and begin another. Quoting is already gone by
/// the time this runs, so an argument that is *only* these characters — `grep
/// ";"` — is read as a separator. That splits one command into more, and each
/// piece is still decided, so the error is on the strict side.
const SEPARATOR_CHARS: &[char] = &['&', '|', ';'];

/// Every program a shell command will run, in order.
///
/// Pure. An empty result means the string held no command at all, which the
/// caller treats the way it treats anything it cannot decide.
///
/// # Errors
///
/// [`ArgvError`] when the string cannot be read as a fixed list of programs;
/// see the module docs for why that is never an approval.
pub fn commands_of(shell_command: &str) -> Result<Vec<Command>, ArgvError> {
    parse(shell_command, 0)
}

fn parse(shell_command: &str, depth: usize) -> Result<Vec<Command>, ArgvError> {
    if depth > MAX_DEPTH {
        return Err(ArgvError::TooDeep);
    }
    if let Some(construct) = dynamic_construct(shell_command) {
        return Err(ArgvError::Dynamic(construct.to_string()));
    }

    let tokens = shlex::split(shell_command).ok_or(ArgvError::Unquoted)?;

    let mut commands = Vec::new();
    for segment in segments(&tokens) {
        commands.extend(read_segment(segment, depth)?);
    }
    Ok(commands)
}

/// Splits a token list on the operators that end one command.
fn segments(tokens: &[String]) -> Vec<&[String]> {
    tokens
        .split(|token| is_separator(token))
        .filter(|segment| !segment.is_empty())
        .collect()
}

/// Whether a token is an operator rather than a word.
fn is_separator(token: &str) -> bool {
    !token.is_empty() && token.chars().all(|c| SEPARATOR_CHARS.contains(&c))
}

/// One segment, with its environment prefix stripped and its shell unwrapped.
fn read_segment(segment: &[String], depth: usize) -> Result<Vec<Command>, ArgvError> {
    let segment = strip_environment(segment);
    let Some((first, rest)) = segment.split_first() else {
        return Ok(Vec::new());
    };

    let program = basename(first);
    if SHELLS.contains(&program.as_str()) {
        if let Some(script) = script_of(rest) {
            return parse(script, depth + 1);
        }
        // A shell with no `-c` runs a file or an interactive session; it is
        // decided as itself, which is what a rule naming `bash` is for.
    }

    Ok(vec![Command {
        program,
        argv: rest.to_vec(),
    }])
}

/// Drops a leading `env` and any `VAR=value` assignments.
///
/// `FOO=1 git status` runs `git`, and a rule about `git` must see it. `env`
/// with switches (`env -i`, `env -u FOO`) is left alone: it is then doing
/// something a rule author should have to name.
fn strip_environment(segment: &[String]) -> &[String] {
    let mut rest = segment;
    if rest.first().is_some_and(|token| {
        basename(token) == "env" && !rest.get(1).is_some_and(|next| is_flag(next))
    }) {
        rest = &rest[1..];
    }
    while rest.first().is_some_and(|token| is_assignment(token)) {
        rest = &rest[1..];
    }
    rest
}

/// The script a shell was handed, if it was handed one.
///
/// Any flag cluster containing `c` counts, so `-c`, `-lc`, and `-euc` are all
/// the same laundering attempt. `--` ends the flags.
fn script_of(rest: &[String]) -> Option<&str> {
    for (index, token) in rest.iter().enumerate() {
        if token == "--" {
            return None;
        }
        if is_flag(token) && token.trim_start_matches('-').contains('c') {
            return Some(rest.get(index + 1).map_or("", String::as_str));
        }
    }
    None
}

/// Whether a shell command holds a construct whose result is not knowable now.
fn dynamic_construct(command: &str) -> Option<&'static str> {
    for (needle, name) in [
        ("$(", "a command substitution"),
        ("`", "a backtick substitution"),
        ("<(", "a process substitution"),
        (">(", "a process substitution"),
    ] {
        if command.contains(needle) {
            return Some(name);
        }
    }
    None
}

fn is_flag(token: &str) -> bool {
    token.starts_with('-') && token.len() > 1
}

/// Whether a token is a `VAR=value` assignment rather than a program.
fn is_assignment(token: &str) -> bool {
    let Some((name, _)) = token.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.starts_with(|c: char| c.is_ascii_digit())
}

/// The last path component, so a rule may name `git` and catch `/usr/bin/git`.
fn basename(token: &str) -> String {
    token
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(token)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn programs(command: &str) -> Vec<String> {
        commands_of(command)
            .expect("parses")
            .into_iter()
            .map(|command| command.program)
            .collect()
    }

    #[test]
    fn a_plain_command_is_its_program_and_its_arguments() {
        let commands = commands_of("git status --short").expect("parses");

        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].program, "git");
        assert_eq!(commands[0].argv, ["status", "--short"]);
    }

    #[test]
    fn an_absolute_path_is_the_same_program_as_its_name() {
        assert_eq!(programs("/usr/bin/git status"), ["git"]);
    }

    #[test]
    fn every_program_in_a_chain_is_decided_separately() {
        assert_eq!(
            programs("git status && rm -rf /tmp/x ; ls | wc -l"),
            ["git", "rm", "ls", "wc"]
        );
    }

    #[test]
    fn a_shell_dash_c_cannot_launder_the_command_inside_it() {
        let commands = commands_of("bash -lc \"rm -rf /tmp/x\"").expect("parses");

        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].program, "rm");
        assert_eq!(commands[0].argv, ["-rf", "/tmp/x"]);
    }

    #[test]
    fn every_flag_cluster_containing_c_is_the_same_laundering() {
        for invocation in [
            "sh -c 'rm x'",
            "bash -lc 'rm x'",
            "bash -euc 'rm x'",
            "zsh -c 'rm x'",
            "dash -c 'rm x'",
        ] {
            assert_eq!(programs(invocation), ["rm"], "{invocation}");
        }
    }

    #[test]
    fn a_shell_that_was_not_handed_a_command_is_decided_as_itself() {
        assert_eq!(programs("bash /tmp/setup.sh"), ["bash"]);
        assert_eq!(programs("sh"), ["sh"]);
    }

    #[test]
    fn an_environment_prefix_does_not_hide_the_program() {
        assert_eq!(programs("FOO=1 BAR=2 git status"), ["git"]);
        assert_eq!(programs("env FOO=1 git status"), ["git"]);
    }

    #[test]
    fn env_with_switches_is_a_program_a_rule_must_name() {
        assert_eq!(
            programs("env -i git status"),
            ["env"],
            "clearing the environment is not the same as setting a variable"
        );
    }

    #[test]
    fn sudo_is_not_unwrapped_so_a_bundle_has_to_say_it_allows_sudo() {
        let commands = commands_of("sudo rm -rf /").expect("parses");

        assert_eq!(commands[0].program, "sudo");
        assert_eq!(commands[0].argv, ["rm", "-rf", "/"]);
    }

    #[test]
    fn a_command_substitution_is_refused_rather_than_read_optimistically() {
        let error = commands_of("git $(cat /tmp/evil)").expect_err("cannot be read");

        assert!(matches!(error, ArgvError::Dynamic(_)), "{error}");
        assert!(error.to_string().contains("only known when it runs"));
    }

    #[test]
    fn a_backtick_and_a_process_substitution_are_refused_too() {
        assert!(commands_of("echo `id`").is_err());
        assert!(commands_of("diff <(a) <(b)").is_err());
    }

    #[test]
    fn quoting_that_does_not_close_is_not_guessed_at() {
        assert_eq!(
            commands_of("git commit -m \"oops").unwrap_err(),
            ArgvError::Unquoted
        );
    }

    #[test]
    fn shells_wrapping_shells_stop_being_followed_rather_than_recursing_forever() {
        let nested = "sh -c 'sh -c \"sh -c ' + 'x'";
        // Whatever this parses to, it must not panic or loop.
        let _ = commands_of(nested);

        let deep = (0..8).fold("rm x".to_string(), |inner, _| {
            format!("sh -c {}", shlex::try_quote(&inner).expect("quotable"))
        });
        assert_eq!(commands_of(&deep).unwrap_err(), ArgvError::TooDeep);
    }

    #[test]
    fn a_shell_handed_c_with_nothing_after_it_runs_nothing() {
        assert!(commands_of("bash -c").expect("parses").is_empty());
    }

    #[test]
    fn an_empty_command_holds_no_programs() {
        assert!(commands_of("").expect("parses").is_empty());
        assert!(commands_of("   ").expect("parses").is_empty());
        assert!(commands_of(";;").expect("parses").is_empty());
    }

    #[test]
    fn a_command_prints_as_a_rule_author_would_have_written_it() {
        let commands = commands_of("git status --short").expect("parses");
        assert_eq!(commands[0].display(), "git status --short");

        let bare = commands_of("ls").expect("parses");
        assert_eq!(bare[0].display(), "ls");
    }

    #[test]
    fn an_assignment_is_told_apart_from_a_program_with_an_equals_sign() {
        assert!(is_assignment("FOO=1"));
        assert!(is_assignment("_x="));
        assert!(!is_assignment("=1"));
        assert!(!is_assignment("1FOO=1"));
        assert!(!is_assignment("git"));
        assert!(!is_assignment("--flag=value"));
    }
}
