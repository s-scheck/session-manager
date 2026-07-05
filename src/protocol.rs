//! The wire protocol spoken between client and server over the session's
//! Unix-domain socket.
//!
//! Framing mirrors abduco's `Packet`: a fixed 8-byte little-endian header
//! (`type: u32`, `len: u32`) followed by `len` bytes of payload whose meaning
//! depends on the type. Terminal content (`Content`) is the only variable
//! length payload; everything else is a small fixed record.

use std::io::{self, Read, Write};

/// Max terminal-content bytes carried in a single packet (abduco uses 4096 -
/// 2*sizeof(u32) = 4088). Keeps individual reads/writes bounded.
pub const MAX_PAYLOAD: usize = 4096 - 2 * 4;

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
    /// Client announcing itself and its flags (readonly / lowpriority).
    Attach { flags: u32 },
    /// Client is leaving; server marks it disconnected.
    Detach,
    /// Window size change, applied to the pty with TIOCSWINSZ.
    Resize { rows: u16, cols: u16 },
    /// Server → clients: the supervised command exited with this status.
    Exit(i32),
    /// Server → new client right after accept: the server's pid.
    Pid(u32),
    /// Client → server: rename the session (and its socket) to this name.
    Rename(String),
}

// Wire type tags (must stay stable across client/server of the same build).
const T_CONTENT: u32 = 0;
const T_ATTACH: u32 = 1;
const T_DETACH: u32 = 2;
const T_RESIZE: u32 = 3;
const T_EXIT: u32 = 4;
const T_PID: u32 = 5;
const T_RENAME: u32 = 6;

impl Packet {
    fn tag(&self) -> u32 {
        match self {
            Packet::Content(_) => T_CONTENT,
            Packet::Attach { .. } => T_ATTACH,
            Packet::Detach => T_DETACH,
            Packet::Resize { .. } => T_RESIZE,
            Packet::Exit(_) => T_EXIT,
            Packet::Pid(_) => T_PID,
            Packet::Rename(_) => T_RENAME,
        }
    }

    /// The payload bytes for this packet (excludes the header).
    fn payload(&self) -> Vec<u8> {
        match self {
            Packet::Content(bytes) => bytes.clone(),
            Packet::Attach { flags } => flags.to_le_bytes().to_vec(),
            Packet::Detach => Vec::new(),
            Packet::Resize { rows, cols } => {
                let mut v = Vec::with_capacity(4);
                v.extend_from_slice(&rows.to_le_bytes());
                v.extend_from_slice(&cols.to_le_bytes());
                v
            }
            Packet::Exit(status) => status.to_le_bytes().to_vec(),
            Packet::Pid(pid) => pid.to_le_bytes().to_vec(),
            Packet::Rename(name) => name.as_bytes().to_vec(),
        }
    }

    /// Serialize and write this packet in full. Blocking; handles short writes.
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let payload = self.payload();
        let mut header = [0u8; HEADER_LEN];
        header[0..4].copy_from_slice(&self.tag().to_le_bytes());
        header[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        w.write_all(&header)?;
        if !payload.is_empty() {
            w.write_all(&payload)?;
        }
        w.flush()
    }

    /// Read exactly one packet. Returns `UnexpectedEof` when the peer has
    /// closed the connection (which callers treat as a disconnect).
    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Packet> {
        let mut header = [0u8; HEADER_LEN];
        r.read_exact(&mut header)?;
        let tag = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let len = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        if len > MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("packet payload too large: {len}"),
            ));
        }
        let mut payload = vec![0u8; len];
        if len > 0 {
            r.read_exact(&mut payload)?;
        }

        let expect = |need: usize| -> io::Result<()> {
            if payload.len() < need {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packet payload too short",
                ))
            } else {
                Ok(())
            }
        };

        match tag {
            T_CONTENT => Ok(Packet::Content(payload)),
            T_ATTACH => {
                expect(4)?;
                Ok(Packet::Attach {
                    flags: u32::from_le_bytes(payload[0..4].try_into().unwrap()),
                })
            }
            T_DETACH => Ok(Packet::Detach),
            T_RESIZE => {
                expect(4)?;
                Ok(Packet::Resize {
                    rows: u16::from_le_bytes(payload[0..2].try_into().unwrap()),
                    cols: u16::from_le_bytes(payload[2..4].try_into().unwrap()),
                })
            }
            T_EXIT => {
                expect(4)?;
                Ok(Packet::Exit(i32::from_le_bytes(
                    payload[0..4].try_into().unwrap(),
                )))
            }
            T_PID => {
                expect(4)?;
                Ok(Packet::Pid(u32::from_le_bytes(
                    payload[0..4].try_into().unwrap(),
                )))
            }
            T_RENAME => {
                let name = String::from_utf8(payload).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "rename name not UTF-8")
                })?;
                Ok(Packet::Rename(name))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown packet type {other}"),
            )),
        }
    }
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
        roundtrip(Packet::Pid(12345));
        roundtrip(Packet::Rename("new-name".to_string()));
    }

    #[test]
    fn max_payload_roundtrips() {
        roundtrip(Packet::Content(vec![0xAB; MAX_PAYLOAD]));
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
}
