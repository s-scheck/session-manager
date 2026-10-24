//! The wire protocol spoken between client and server over the session's
//! Unix-domain socket.
//!
//! Framing mirrors abduco's `Packet`: a fixed 8-byte little-endian header
//! (`type: u32`, `len: u32`) followed by `len` bytes of payload whose meaning
//! depends on the type. Terminal content (`Content`) and the string-carrying
//! packets are variable length; everything else is a small fixed record.
//!
//! Every connection starts with the server sending `Hello`, which carries
//! [`PROTOCOL_VERSION`]. Clients refuse to talk to a server speaking another
//! version, so upgrading `sm` while older sessions are still running yields a
//! clear error instead of misinterpreted packets.

use std::io::{self, Read, Write};

/// Bump whenever the meaning of any packet changes.
pub const PROTOCOL_VERSION: u32 = 1;

/// Max payload bytes carried in a single packet (abduco uses 4096 -
/// 2*sizeof(u32) = 4088). Keeps individual reads/writes bounded; larger
/// terminal content is split across several `Content` packets.
pub const MAX_PAYLOAD: usize = 4096 - HEADER_LEN;

const HEADER_LEN: usize = 8;

// Client flags carried in an `Attach` packet (bitfield), mirroring abduco's
// CLIENT_READONLY / CLIENT_LOWPRIORITY.
pub const FLAG_READONLY: u32 = 1 << 0;
pub const FLAG_LOWPRIORITY: u32 = 1 << 1;

/// One framed message. Decoded/encoded to/from the wire header + payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// Raw terminal bytes. client→server = keystrokes, server→client = output.
    Content(Vec<u8>),
    /// Client → server: start receiving the session's output, with these
    /// flags (readonly / lowpriority).
    Attach { flags: u32 },
    /// Client → server: the attached client is leaving.
    Detach,
    /// Client → server: the client's window size, applied to the pty with
    /// TIOCSWINSZ while that client controls the size.
    Resize { rows: u16, cols: u16 },
    /// Server → attached clients: the supervised command exited with this
    /// status. Always the last packet of a connection.
    Exit(i32),
    /// Server → every new connection, first: the protocol version and the
    /// supervised command's pid.
    Hello { version: u32, pid: u32 },
    /// Client → server: rename the session (and its socket) to this name.
    Rename(String),
    /// Server → client: the requested rename succeeded.
    Renamed,
    /// Server → client: the request failed, with a human-readable reason.
    Error(String),
}

// Wire type tags (must stay stable within one PROTOCOL_VERSION).
const T_CONTENT: u32 = 0;
const T_ATTACH: u32 = 1;
const T_DETACH: u32 = 2;
const T_RESIZE: u32 = 3;
const T_EXIT: u32 = 4;
const T_HELLO: u32 = 5;
const T_RENAME: u32 = 6;
const T_RENAMED: u32 = 7;
const T_ERROR: u32 = 8;

impl Packet {
    fn tag(&self) -> u32 {
        match self {
            Packet::Content(_) => T_CONTENT,
            Packet::Attach { .. } => T_ATTACH,
            Packet::Detach => T_DETACH,
            Packet::Resize { .. } => T_RESIZE,
            Packet::Exit(_) => T_EXIT,
            Packet::Hello { .. } => T_HELLO,
            Packet::Rename(_) => T_RENAME,
            Packet::Renamed => T_RENAMED,
            Packet::Error(_) => T_ERROR,
        }
    }

    /// Serialize this packet (header + payload) into a byte vector, ready to be
    /// appended to an output buffer for non-blocking, buffered sending.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN + 8);
        buf.extend_from_slice(&self.tag().to_le_bytes());
        buf.extend_from_slice(&[0; 4]); // length, patched in below
        match self {
            Packet::Content(bytes) => buf.extend_from_slice(bytes),
            Packet::Attach { flags } => buf.extend_from_slice(&flags.to_le_bytes()),
            Packet::Resize { rows, cols } => {
                buf.extend_from_slice(&rows.to_le_bytes());
                buf.extend_from_slice(&cols.to_le_bytes());
            }
            Packet::Exit(status) => buf.extend_from_slice(&status.to_le_bytes()),
            Packet::Hello { version, pid } => {
                buf.extend_from_slice(&version.to_le_bytes());
                buf.extend_from_slice(&pid.to_le_bytes());
            }
            Packet::Rename(text) | Packet::Error(text) => buf.extend_from_slice(text.as_bytes()),
            Packet::Detach | Packet::Renamed => {}
        }
        let len = buf.len() - HEADER_LEN;
        // Producers split content into MAX_PAYLOAD chunks; anything larger
        // would be rejected by the peer's decoder.
        debug_assert!(len <= MAX_PAYLOAD, "packet payload too large: {len}");
        buf[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        buf
    }

    /// Serialize and write this packet in full. Blocking; handles short writes.
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.encode())?;
        w.flush()
    }

    /// Read exactly one packet. Returns `UnexpectedEof` when the peer has
    /// closed the connection (which callers treat as a disconnect).
    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Packet> {
        let mut header = [0u8; HEADER_LEN];
        r.read_exact(&mut header)?;
        let (tag, len) = parse_header(&header)?;
        let mut payload = vec![0u8; len];
        r.read_exact(&mut payload)?;
        Self::decode(tag, payload)
    }

    /// Try to decode one packet from the front of `buf`, removing its bytes on
    /// success. `Ok(None)` means more bytes are needed; `Err` is a protocol
    /// violation (the caller should disconnect the peer). Used for non-blocking,
    /// incrementally-buffered reads.
    pub fn try_decode(buf: &mut Vec<u8>) -> io::Result<Option<Packet>> {
        let Some(header) = buf.first_chunk::<HEADER_LEN>() else {
            return Ok(None);
        };
        let (tag, len) = parse_header(header)?;
        if buf.len() < HEADER_LEN + len {
            return Ok(None);
        }
        let payload = buf[HEADER_LEN..HEADER_LEN + len].to_vec();
        buf.drain(..HEADER_LEN + len);
        Self::decode(tag, payload).map(Some)
    }

    /// Decode a packet from its tag and payload bytes.
    fn decode(tag: u32, payload: Vec<u8>) -> io::Result<Packet> {
        let packet = match tag {
            T_CONTENT => Packet::Content(payload),
            T_ATTACH => Packet::Attach {
                flags: u32::from_le_bytes(fixed(&payload)?),
            },
            T_DETACH => Packet::Detach,
            T_RESIZE => {
                let [r0, r1, c0, c1] = fixed(&payload)?;
                Packet::Resize {
                    rows: u16::from_le_bytes([r0, r1]),
                    cols: u16::from_le_bytes([c0, c1]),
                }
            }
            T_EXIT => Packet::Exit(i32::from_le_bytes(fixed(&payload)?)),
            T_HELLO => {
                let [v0, v1, v2, v3, p0, p1, p2, p3] = fixed(&payload)?;
                Packet::Hello {
                    version: u32::from_le_bytes([v0, v1, v2, v3]),
                    pid: u32::from_le_bytes([p0, p1, p2, p3]),
                }
            }
            T_RENAME => Packet::Rename(utf8(payload)?),
            T_RENAMED => Packet::Renamed,
            T_ERROR => Packet::Error(utf8(payload)?),
            other => return Err(invalid(format!("unknown packet type {other}"))),
        };
        Ok(packet)
    }
}

/// Read the server's greeting and verify the protocol version. Returns the
/// supervised command's pid. Anything other than a matching `Hello` means the
/// peer is not a compatible `sm` server.
pub fn read_hello<R: Read>(r: &mut R) -> io::Result<u32> {
    match Packet::read_from(r) {
        Ok(Packet::Hello { version, pid }) if version == PROTOCOL_VERSION => Ok(pid),
        Ok(Packet::Hello { version, .. }) => Err(incompatible(&format!(
            "protocol version {version}, expected {PROTOCOL_VERSION}"
        ))),
        Ok(_) => Err(incompatible("unexpected greeting")),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => Err(incompatible(&e.to_string())),
        Err(e) => Err(e),
    }
}

fn incompatible(detail: &str) -> io::Error {
    invalid(format!(
        "session was started by an incompatible version of sm ({detail})"
    ))
}

fn parse_header(header: &[u8; HEADER_LEN]) -> io::Result<(u32, usize)> {
    let [t0, t1, t2, t3, l0, l1, l2, l3] = *header;
    let tag = u32::from_le_bytes([t0, t1, t2, t3]);
    let len = u32::from_le_bytes([l0, l1, l2, l3]) as usize;
    if len > MAX_PAYLOAD {
        return Err(invalid(format!("packet payload too large: {len}")));
    }
    Ok((tag, len))
}

/// The payload as a fixed-size record; a size mismatch is a protocol error.
fn fixed<const N: usize>(payload: &[u8]) -> io::Result<[u8; N]> {
    payload.try_into().map_err(|_| {
        invalid(format!(
            "expected a {N}-byte payload, got {}",
            payload.len()
        ))
    })
}

fn utf8(payload: Vec<u8>) -> io::Result<String> {
    String::from_utf8(payload).map_err(|_| invalid("payload is not valid UTF-8".to_string()))
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(p: Packet) {
        let mut buf = Vec::new();
        p.write_to(&mut buf).unwrap();
        let mut cursor = io::Cursor::new(buf);
        let decoded = Packet::read_from(&mut cursor).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn roundtrip_all_variants() {
        roundtrip(Packet::Content(b"hello world".to_vec()));
        roundtrip(Packet::Content(Vec::new()));
        roundtrip(Packet::Attach {
            flags: FLAG_READONLY | FLAG_LOWPRIORITY,
        });
        roundtrip(Packet::Detach);
        roundtrip(Packet::Resize { rows: 24, cols: 80 });
        roundtrip(Packet::Exit(7));
        roundtrip(Packet::Exit(-1));
        roundtrip(Packet::Hello {
            version: PROTOCOL_VERSION,
            pid: 12345,
        });
        roundtrip(Packet::Rename("new-name".to_string()));
        roundtrip(Packet::Renamed);
        roundtrip(Packet::Error("nope".to_string()));
    }

    #[test]
    fn max_payload_roundtrips() {
        roundtrip(Packet::Content(vec![0xAB; MAX_PAYLOAD]));
    }

    #[test]
    fn try_decode_streams_multiple_packets() {
        // Two packets concatenated, plus a partial third.
        let mut buf = Vec::new();
        buf.extend(Packet::Content(b"ab".to_vec()).encode());
        buf.extend(Packet::Resize { rows: 5, cols: 9 }.encode());
        let partial = Packet::Exit(7).encode();
        buf.extend_from_slice(&partial[..3]); // only 3 bytes of the third

        assert_eq!(
            Packet::try_decode(&mut buf).unwrap(),
            Some(Packet::Content(b"ab".to_vec()))
        );
        assert_eq!(
            Packet::try_decode(&mut buf).unwrap(),
            Some(Packet::Resize { rows: 5, cols: 9 })
        );
        // Third is incomplete -> None, bytes retained.
        assert_eq!(Packet::try_decode(&mut buf).unwrap(), None);
        buf.extend_from_slice(&partial[3..]);
        assert_eq!(Packet::try_decode(&mut buf).unwrap(), Some(Packet::Exit(7)));
        assert!(buf.is_empty());
    }

    #[test]
    fn eof_is_reported() {
        let mut empty = io::Cursor::new(Vec::new());
        let err = Packet::read_from(&mut empty).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn oversized_len_rejected() {
        let mut header = Vec::new();
        header.extend_from_slice(&T_CONTENT.to_le_bytes());
        header.extend_from_slice(&((MAX_PAYLOAD as u32) + 1).to_le_bytes());
        let mut cursor = io::Cursor::new(header);
        let err = Packet::read_from(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn wrong_record_size_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&T_RESIZE.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(&[0, 0, 0]);
        assert!(Packet::try_decode(&mut buf).is_err());
    }

    #[test]
    fn hello_checks_version() {
        let pid = 42;
        let mut ok = io::Cursor::new(
            Packet::Hello {
                version: PROTOCOL_VERSION,
                pid,
            }
            .encode(),
        );
        assert_eq!(read_hello(&mut ok).unwrap(), pid);

        let mut newer = io::Cursor::new(
            Packet::Hello {
                version: PROTOCOL_VERSION + 1,
                pid,
            }
            .encode(),
        );
        assert_eq!(
            read_hello(&mut newer).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        // A pre-versioning server greeted with a 4-byte pid under the same tag.
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&T_HELLO.to_le_bytes());
        legacy.extend_from_slice(&4u32.to_le_bytes());
        legacy.extend_from_slice(&pid.to_le_bytes());
        let err = read_hello(&mut io::Cursor::new(legacy)).unwrap_err();
        assert!(err.to_string().contains("incompatible version"));
    }
}
