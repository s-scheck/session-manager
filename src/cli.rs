//! Command-line parsing. Hand-rolled and getopt-style, like abduco: flags may be
//! clustered (`-rq`), `-e` takes its value attached or as the next argument
//! (`-e^b`, `-e ^b`), and everything after the session name is the command,
//! verbatim — including arguments that start with `-`.

use crate::client::{AttachOptions, DETACH_KEY};

pub const USAGE: &str = "\
usage: sm [-a|-A|-c|-n] [-d] [-p] [-r] [-q] [-L] [-f] [-e prefixkey] name [command ...]
       sm -k name                kill a session
       sm -R oldname newname     rename a session
       sm -l [-z]                list sessions (-z: NUL-terminated records)
       sm -v                     print version

detach: press the prefix key (default Ctrl-a) then 'd'. Press the prefix
twice to send one literal prefix to the program. Change it with -e.";

const DEFAULT_PREFIX_KEY: u8 = 0x01; // Ctrl-a; press then 'd' to detach (screen-style)

/// A fully validated invocation.
#[derive(Debug, PartialEq, Eq)]
pub struct Cli {
    pub command: Command,
    /// Suppress informational messages.
    pub quiet: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    List(ListFormat),
    Version,
    Kill { name: String },
    Rename { from: String, to: String },
    Session(SessionArgs),
}

#[derive(Debug, PartialEq, Eq)]
pub struct SessionArgs {
    pub action: Action,
    pub name: String,
    /// The command to run if the session is created; empty for the default.
    pub command: Vec<String>,
    /// Replace a dead session's stale socket.
    pub force: bool,
    pub attach: AttachOptions,
}

/// How `sm -l` prints the sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFormat {
    /// An aligned table for people.
    Table,
    /// -z: one `<status> <name>` record per session, each terminated by a NUL
    /// byte, so that scripts and shell completion can read any name.
    NulTerminated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// -a: attach to an existing session (error if absent).
    Attach,
    /// -A (default): attach if present, else create and attach.
    AttachOrCreate,
    /// -c: create a new session and attach.
    Create,
    /// -n: create a new session, do not attach.
    CreateDetached,
}

/// What the action flags select, before the positionals are checked.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Session(Action),
    Kill,
    Rename,
}

/// Parse the arguments (without the program name).
pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Cli, String> {
    let mut mode = None;
    let mut list = false;
    let mut nul_terminated = false;
    let mut force = false;
    let mut quiet = false;
    let mut attach = AttachOptions {
        readonly: false,
        lowpriority: false,
        passthrough: false,
        detach_others: false,
        prefix_key: DEFAULT_PREFIX_KEY,
    };
    let mut positionals = Vec::new();

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--" {
            positionals.extend(args.by_ref());
            break;
        }
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
            // The session name; everything after it belongs to the command.
            positionals.push(arg);
            positionals.extend(args.by_ref());
            break;
        };
        for (i, flag) in flags.char_indices() {
            let selected = match flag {
                'a' => Mode::Session(Action::Attach),
                'A' => Mode::Session(Action::AttachOrCreate),
                'c' => Mode::Session(Action::Create),
                'n' => Mode::Session(Action::CreateDetached),
                'k' => Mode::Kill,
                'R' => Mode::Rename,
                'd' => {
                    attach.detach_others = true;
                    continue;
                }
                'f' => {
                    force = true;
                    continue;
                }
                'l' => {
                    list = true;
                    continue;
                }
                'L' => {
                    attach.lowpriority = true;
                    continue;
                }
                'p' => {
                    attach.passthrough = true;
                    continue;
                }
                'q' => {
                    quiet = true;
                    continue;
                }
                'r' => {
                    attach.readonly = true;
                    continue;
                }
                'z' => {
                    nul_terminated = true;
                    continue;
                }
                'v' => {
                    return Ok(Cli {
                        command: Command::Version,
                        quiet,
                    });
                }
                'e' => {
                    // The value is the rest of this argument, or the next one.
                    let rest = &flags[i + 1..];
                    let spec = if rest.is_empty() {
                        args.next().ok_or("-e requires a key argument")?
                    } else {
                        rest.to_owned()
                    };
                    attach.prefix_key = parse_prefix_key(&spec)?;
                    break;
                }
                other => return Err(format!("unknown option -{other}")),
            };
            if mode.is_some_and(|m| m != selected) {
                return Err("only one of -a/-A/-c/-n/-k/-R may be given".to_string());
            }
            mode = Some(selected);
        }
    }

    let format = if nul_terminated {
        ListFormat::NulTerminated
    } else {
        ListFormat::Table
    };
    let command = match (list, mode) {
        (true, Some(_)) => {
            return Err("-l cannot be combined with -a/-A/-c/-n/-k/-R".to_string());
        }
        (true, None) if !positionals.is_empty() => {
            return Err("-l does not take a session name".to_string());
        }
        // A bare `sm` lists sessions too.
        (_, None) if positionals.is_empty() => Command::List(format),
        (_, Some(Mode::Kill)) => match <[String; 1]>::try_from(positionals) {
            Ok([name]) => Command::Kill { name },
            Err(_) => return Err("kill takes exactly one name: sm -k name".to_string()),
        },
        (_, Some(Mode::Rename)) => match <[String; 2]>::try_from(positionals) {
            Ok([from, to]) => Command::Rename { from, to },
            Err(_) => {
                return Err("rename takes exactly two names: sm -R oldname newname".to_string());
            }
        },
        (_, Some(Mode::Session(action))) => session(action, positionals, force, attach)?,
        // A name without an action: attach-or-create (friendly default).
        (_, None) => session(Action::AttachOrCreate, positionals, force, attach)?,
    };
    if nul_terminated && !matches!(command, Command::List(_)) {
        return Err("-z only applies to -l".to_string());
    }
    Ok(Cli { command, quiet })
}

fn session(
    action: Action,
    positionals: Vec<String>,
    force: bool,
    attach: AttachOptions,
) -> Result<Command, String> {
    let mut positionals = positionals.into_iter();
    let name = positionals.next().ok_or("a session name is required")?;
    let command: Vec<String> = positionals.collect();
    if action == Action::Attach && !command.is_empty() {
        return Err("-a attaches to an existing session and takes no command".to_string());
    }
    Ok(Command::Session(SessionArgs {
        action,
        name,
        command,
        force,
        attach,
    }))
}

/// Parse a prefix-key spec: caret notation (`^a` = Ctrl-a, `^\`, `^?` = DEL),
/// a single ASCII character, or a decimal byte value below 128.
pub fn parse_prefix_key(spec: &str) -> Result<u8, String> {
    let key = match spec.as_bytes() {
        [b'^', b'?'] => 0x7f,
        [b'^', c] if (b'@'..=b'_').contains(&c.to_ascii_uppercase()) => {
            c.to_ascii_uppercase() & 0x1f
        }
        [c] if c.is_ascii() => *c,
        _ => spec
            .parse::<u8>()
            .ok()
            .filter(u8::is_ascii)
            .ok_or_else(|| format!("invalid prefix key: {spec}"))?,
    };
    if key.eq_ignore_ascii_case(&DETACH_KEY) {
        // prefix + d would be ambiguous between detach and a literal prefix.
        return Err(format!(
            "invalid prefix key: {spec} (the detach command key '{}' cannot be the prefix)",
            DETACH_KEY as char
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(args: &str) -> Result<Cli, String> {
        parse(args.split_whitespace().map(str::to_owned))
    }

    fn session_args(args: &str) -> SessionArgs {
        match parse_str(args).unwrap().command {
            Command::Session(s) => s,
            other => panic!("expected a session command, got {other:?}"),
        }
    }

    #[test]
    fn prefix_key_caret_notation() {
        assert_eq!(parse_prefix_key("^\\").unwrap(), 0x1c);
        assert_eq!(parse_prefix_key("^o").unwrap(), 0x0f);
        assert_eq!(parse_prefix_key("^O").unwrap(), 0x0f);
        assert_eq!(parse_prefix_key("^@").unwrap(), 0x00);
        assert_eq!(parse_prefix_key("^?").unwrap(), 0x7f);
        assert!(parse_prefix_key("^1").is_err());
        assert!(parse_prefix_key("^ä").is_err());
    }

    #[test]
    fn prefix_key_single_char_and_decimal() {
        assert_eq!(parse_prefix_key("q").unwrap(), b'q');
        assert_eq!(parse_prefix_key("28").unwrap(), 28);
        assert!(parse_prefix_key("200").is_err()); // not ASCII
        assert!(parse_prefix_key("abc").is_err());
        assert!(parse_prefix_key("").is_err());
    }

    #[test]
    fn prefix_key_cannot_be_detach_key() {
        assert!(parse_prefix_key("d").is_err());
        assert!(parse_prefix_key("D").is_err());
        assert!(parse_prefix_key("100").is_err());
    }

    #[test]
    fn bare_invocation_lists() {
        let table = Command::List(ListFormat::Table);
        assert_eq!(parse_str("").unwrap().command, table);
        assert_eq!(parse_str("-l").unwrap().command, table);
        assert_eq!(parse_str("-q").unwrap().command, table);
        assert!(parse_str("-l work").is_err());
        assert!(parse_str("-l -c work").is_err());
    }

    #[test]
    fn nul_terminated_listing_is_only_for_lists() {
        let records = Command::List(ListFormat::NulTerminated);
        assert_eq!(parse_str("-lz").unwrap().command, records);
        assert_eq!(parse_str("-z -l").unwrap().command, records);
        assert_eq!(parse_str("-z").unwrap().command, records);
        assert!(parse_str("-z work").is_err());
        assert!(parse_str("-z -k work").is_err());
    }

    #[test]
    fn name_without_action_attaches_or_creates() {
        let s = session_args("work");
        assert_eq!(s.action, Action::AttachOrCreate);
        assert_eq!(s.name, "work");
        assert!(s.command.is_empty());
    }

    #[test]
    fn command_after_name_is_verbatim() {
        let s = session_args("-c work vim -R notes");
        assert_eq!(s.action, Action::Create);
        assert_eq!(s.command, ["vim", "-R", "notes"]);
        // `--` ends the options, so a name may start with '-'.
        let s = session_args("-n -- -odd sh");
        assert_eq!(s.name, "-odd");
        assert_eq!(s.command, ["sh"]);
    }

    #[test]
    fn clustered_flags_and_prefix_values() {
        let s = session_args("-rqLe^b work");
        assert!(s.attach.readonly && s.attach.lowpriority);
        assert_eq!(s.attach.prefix_key, 0x02);
        let cli = parse_str("-q -e ^o -A work").unwrap();
        assert!(cli.quiet);
        let Command::Session(s) = cli.command else {
            panic!("expected a session command")
        };
        assert_eq!(s.attach.prefix_key, 0x0f);
        assert!(parse_str("-e").is_err());
    }

    #[test]
    fn conflicting_actions_are_rejected() {
        assert!(parse_str("-a -c work").is_err());
        assert!(parse_str("-R -n a b").is_err());
        // Repeating the same action is harmless.
        assert_eq!(session_args("-c -c work").action, Action::Create);
    }

    #[test]
    fn rename_takes_exactly_two_names() {
        assert_eq!(
            parse_str("-R old new").unwrap().command,
            Command::Rename {
                from: "old".into(),
                to: "new".into()
            }
        );
        assert!(parse_str("-R old").is_err());
        assert!(parse_str("-R old new extra").is_err());
    }

    #[test]
    fn kill_takes_exactly_one_name() {
        assert_eq!(
            parse_str("-k work").unwrap().command,
            Command::Kill {
                name: "work".into()
            }
        );
        assert!(parse_str("-k").is_err());
        assert!(parse_str("-k work extra").is_err());
        assert!(parse_str("-k -a work").is_err());
        assert!(parse_str("-l -k work").is_err());
    }

    #[test]
    fn detach_others_is_an_attach_option() {
        assert!(session_args("-d -a work").attach.detach_others);
        assert!(session_args("-dA work").attach.detach_others);
        assert!(!session_args("-a work").attach.detach_others);
    }

    #[test]
    fn invalid_invocations() {
        assert!(parse_str("-x work").is_err());
        assert!(parse_str("-c").is_err());
        assert!(parse_str("-a work vim").is_err());
    }

    #[test]
    fn version_short_circuits() {
        assert_eq!(parse_str("-v").unwrap().command, Command::Version);
    }
}
