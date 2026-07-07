# sm — a minimal terminal session manager

`sm` is a from-scratch Rust reimplementation of
[abduco](https://github.com/martanne/abduco). It lets you run a program inside a
detachable session: the program keeps running in a background server even after
you disconnect, and you can reattach to it later — like the session-management
half of `screen`/`tmux`, without any of the multiplexing.

One binary is both the **client** (foreground, attached to your terminal) and the
**server** (a daemon that owns the pty running your command). They talk over a
per-session Unix-domain socket.

## Build

```sh
cargo build --release
# binary at ./target/release/sm
```

Requires a Unix-like OS (developed/tested on macOS; works on Linux). Depends only
on `nix` and `libc`.

## Usage

```
sm [-a|-A|-c|-n] [-p] [-r] [-q] [-l] [-L] [-f] [-e detachkey] name [command ...]
sm -R old new  # rename a session
sm -l          # list sessions
sm -v          # version
```

### Actions
| Flag | Meaning |
|------|---------|
| `-c` | **create** a new session and attach |
| `-a` | **attach** to an existing session (error if absent) |
| `-A` | **attach** if it exists, else **create** and attach |
| `-n` | create a new session but do **not** attach (headless) |
| `-R` | **rename** an existing session: `sm -R oldname newname` |
| *(none)* + name | defaults to `-A` (attach-or-create) |

### Options
| Flag | Meaning |
|------|---------|
| `-e key` | set the detach **prefix** key (default `^a`); accepts `^x`, a single char, or a decimal byte |
| `-r` | read-only: your input is ignored, output still streamed |
| `-L` | low priority: never becomes the window-size-controlling client |
| `-p` | passthrough: forward stdin verbatim, no raw mode / detach key |
| `-q` | quiet: suppress informational messages |
| `-f` | force: replace a **dead** session's stale socket (refuses if still alive) |
| `-l` | list sessions |

If no command is given, `sm` runs `$SM_CMD`, else `$SHELL`, else `/bin/sh`.

### Detaching
Detaching uses a two-key **prefix** sequence (like tmux/screen), so it doesn't
collide with keys your programs use:

- **prefix** then **`d`** → detach (default prefix is **Ctrl-a**, i.e. `Ctrl-a d`).
- **prefix** twice → sends one literal prefix byte to the program.
- **prefix** then any other key → both are sent to the program, so the prefix key
  still works inside apps. A lone prefix press is also forwarded after a short
  timeout.

Reattach with `sm -a name`. Change the prefix with `-e` (e.g. `-e ^b` for Ctrl-b,
`-e ^o` for Ctrl-o). Pick a prefix you don't rely on in your editor.

To keep the prefix reliable and to avoid a program inside the session leaving
your outer shell in a weird state, `sm` keeps the terminal in the classic
keyboard encoding while attached (it filters the kitty keyboard protocol and
xterm `modifyOtherKeys` out of program output) and resets keyboard/mouse/paste
modes on detach. Programs like neovim run in the classic (legacy) key encoding
under `sm`.

## Examples

```sh
sm -c work            # start a shell in session "work", attached
# ... press Ctrl-\ to detach ...
sm -a work            # reattach; your shell is exactly where you left it

sm -n build make      # run `make` headless in the background
sm -l                 # list sessions: * attached, - detached, ? stale
sm -R work project    # rename the "work" session to "project"
sm -A notes vim notes # attach if "notes" exists, else create it running vim
sm -r work            # attach as a read-only spectator
sm -c k -e ^q bash    # override the prefix key (Ctrl-q here; detach = Ctrl-q d)
```

When the supervised command exits, an attached `sm` exits with the command's exit
status.

## Environment
| Variable | Purpose |
|----------|---------|
| `SM_CMD` | default command when none is given |
| `SM_SOCKET_DIR` | preferred directory for session sockets |
| `SM_SESSION` | *(set for the child)* the session name |
| `SM_SOCKET` | *(set for the child)* absolute path of the session socket |

Sockets live in the first usable of: `$SM_SOCKET_DIR`, `$HOME/.session_manager`,
`$TMPDIR/sm/$USER`, `/tmp/sm/$USER`. Session directories are created `0700` and are
verified to be owned by you with no group/other access, so other users cannot
attach to your sessions.

## How it works
- **Create** double-forks and `setsid`s a daemon, which `forkpty`s the command and
  binds the session socket.
- **Attach** connects a client, puts your terminal in raw mode + the alternate
  screen, and proxies bytes both ways; window-size changes propagate via
  `SIGWINCH` → `TIOCSWINSZ`.
- Session state (attached / detached) is encoded in the socket's permission bits,
  so listing reads status from `stat(2)` without connecting; liveness is confirmed
  by a `Pid` handshake.
- The server keeps a small ring buffer (64 KB) of recent pty output and replays it
  when a client attaches, so reattaching repaints your recent output instead of
  showing a blank screen. This is a lightweight replay, not a full terminal
  emulator/scrollback — the last screenful(s) repaint correctly.
- Signals use the self-pipe trick (handlers only `write()` a byte; the event loop
  does the work) so nothing unsafe happens in a signal handler.

Not implemented — deliberately, matching abduco's minimalism: window splitting
(that's a multiplexer's job), config files, and full scrollback / VT emulation
(there's a lightweight replay-on-attach instead, see above).
