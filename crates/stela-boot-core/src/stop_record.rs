//! The record of a stop the USB's boot log could not keep, in the PC's
//! firmware. The log is a file on the stick: from the end of the firmware's
//! boot services until Stela's own drivers have started the stick's
//! controller, its lines wait in memory, and a stop in between loses them.
//! UEFI's variable services still run then, so the stop writes the newest
//! of those lines into non-volatile variables, as Linux keeps a crash
//! record across a restart (`drivers/firmware/efi/efi-pstore.c`), and the
//! next start of Stela on the PC copies them into the log and deletes them.
//!
//! The record is at most [`PIECES`] variables of [`PIECE_BYTES`] bytes,
//! Linux's record size, named `StelaStop0` to `StelaStop7` under
//! [`VENDOR`], and a header, `StelaStopHeader`, written last: a write that
//! was cut short leaves no header, or one whose checksum the pieces do not
//! match, and is never read as a record.
//!
//! | Offset | Bytes | Header field |
//! | --- | --- | --- |
//! | 0 | 8 | magic `STELASTP` |
//! | 8 | 4 | version, 1 |
//! | 12 | 4 | pieces |
//! | 16 | 4 | text bytes in all |
//! | 20 | 4 | CRC-32 of the text |
//! | 24 | 8 | the boot's number in the USB's log, 0 without one |
//!
//! The text is a copy of log lines and holds what they hold, nothing more.
use alloc::string::String;
use stela_contracts::crc::crc32_ieee;
use uefi_raw::{Guid, guid};

/// The variables' vendor GUID, Stela's own.
pub const VENDOR: Guid = guid!("b3e1f6a4-2c5d-4e8f-9a17-6d0c53a7e142");
/// The bytes of one piece.
pub const PIECE_BYTES: usize = 1024;
/// The most pieces of a record.
pub const PIECES: usize = 24;
/// The most text a record holds.
pub const TEXT_BYTES: usize = PIECE_BYTES * PIECES;
pub const HEADER_BYTES: usize = 32;
const MAGIC: &[u8; 8] = b"STELASTP";
const VERSION: u32 = 1;

/// `EFI_VARIABLE_NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS`: kept
/// across a restart, written after boot services and read during them.
pub const ATTRIBUTES: u32 = 0x1 | 0x2 | 0x4;

/// `text` as a NUL-terminated UCS-2 variable name; `N` is one more than its
/// length.
const fn name<const N: usize>(text: &str) -> [u16; N] {
    let bytes = text.as_bytes();
    assert!(bytes.len() + 1 == N);
    let mut name = [0; N];
    let mut at = 0;
    while at < bytes.len() {
        name[at] = bytes[at] as u16;
        at += 1;
    }
    name
}

/// The header's variable name.
pub const HEADER_NAME: [u16; 16] = name("StelaStopHeader");

/// The name of piece `index`, below [`PIECES`].
pub const fn piece_name(index: usize) -> [u16; 11] {
    assert!(index < PIECES);
    let mut name: [u16; 11] = name("StelaStop0");
    // 0 to 9, then A onwards.
    name[9] = if index < 10 {
        b'0' as u16 + index as u16
    } else {
        b'A' as u16 + (index - 10) as u16
    };
    name
}

/// What one variable takes of the store beyond its data: its name and the
/// firmware's own header, which is 60 bytes in EDK II's authenticated
/// store, with room.
const VARIABLE_OVERHEAD: u64 = 128;

/// What a record of `text` bytes takes of the firmware's variable store.
pub const fn store_bytes(text: usize) -> u64 {
    let pieces = text.div_ceil(PIECE_BYTES) as u64;
    text as u64 + HEADER_BYTES as u64 + (pieces + 1) * VARIABLE_OVERHEAD
}

/// The firmware's non-volatile variable store, as `QueryVariableInfo`
/// reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Space {
    /// The store's size.
    pub maximum: u64,
    /// What is free of it.
    pub remaining: u64,
    /// The largest single variable it takes.
    pub largest: u64,
}

/// What stays free in the store after a record: Linux's `EFI_MIN_RESERVE`.
pub const STORE_RESERVE: u64 = 5120;

impl Space {
    /// Whether a record taking `needed` bytes ([`store_bytes`]) may be
    /// written: each piece fits one variable, and [`STORE_RESERVE`] bytes
    /// of the store stay free after it. Some firmware fails once its store
    /// fills; this is the rule of Linux's `efi_query_variable_store`, which
    /// replaced its earlier half-of-the-store rule, since a store is often
    /// more than half full as the firmware ships it.
    pub const fn takes(&self, needed: u64) -> bool {
        self.largest >= PIECE_BYTES as u64 + VARIABLE_OVERHEAD
            && needed <= self.remaining
            && self.remaining - needed >= STORE_RESERVE
            && self.maximum != 0
    }
}

/// The newest whole lines of `text` whose record `space` takes: all of it
/// where it fits, less by whole pieces where the store is short, and none
/// where not one piece fits.
pub fn fitting<'a>(space: &Space, text: &'a [u8]) -> &'a [u8] {
    let mut kept = text;
    loop {
        if kept.is_empty() || space.takes(store_bytes(kept.len())) {
            return kept;
        }
        let shorter = (kept.len() - 1) / PIECE_BYTES * PIECE_BYTES;
        let from = text.len() - shorter;
        // From the start of the first whole line of what is left.
        kept = match text[from.saturating_sub(1)..]
            .iter()
            .position(|&byte| byte == b'\n')
        {
            Some(end) if from != 0 => &text[from - 1 + end + 1..],
            _ => &text[text.len()..],
        };
    }
}

/// The newest [`TEXT_BYTES`] of the lines pushed, in whole lines.
pub struct Tail {
    bytes: [u8; TEXT_BYTES],
    len: usize,
    /// The byte before the kept ones, once any was left out.
    before: Option<u8>,
}

impl Default for Tail {
    fn default() -> Self {
        Self::new()
    }
}

impl Tail {
    pub const fn new() -> Self {
        Self {
            bytes: [0; TEXT_BYTES],
            len: 0,
            before: None,
        }
    }

    /// Add `new` after what is held; the oldest bytes make room.
    pub fn push(&mut self, new: &[u8]) {
        if new.is_empty() {
            return;
        }
        if let Some(skipped) = new.len().checked_sub(TEXT_BYTES) {
            self.before = match skipped {
                0 if self.len == 0 => self.before,
                0 => Some(self.bytes[self.len - 1]),
                skipped => Some(new[skipped - 1]),
            };
            self.bytes.copy_from_slice(&new[skipped..]);
            self.len = TEXT_BYTES;
            return;
        }
        let excess = (self.len + new.len()).saturating_sub(TEXT_BYTES);
        if excess != 0 {
            self.before = Some(self.bytes[excess - 1]);
            self.bytes.copy_within(excess..self.len, 0);
            self.len -= excess;
        }
        self.bytes[self.len..self.len + new.len()].copy_from_slice(new);
        self.len += new.len();
    }

    /// The record's text: what is held, from the start of its first whole
    /// line when older bytes were left out. One line longer than the
    /// record is kept as its newest bytes.
    pub fn text(&self) -> &[u8] {
        let kept = &self.bytes[..self.len];
        if matches!(self.before, None | Some(b'\n')) {
            return kept;
        }
        match kept.iter().position(|&byte| byte == b'\n') {
            Some(end) if end + 1 < kept.len() => &kept[end + 1..],
            _ => kept,
        }
    }
}

/// A record's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The stopped boot's number in the USB's log; 0 without one.
    pub boot: u64,
    bytes: u32,
    checksum: u32,
}

impl Header {
    /// The header of a record holding `text`, which is at most
    /// [`TEXT_BYTES`] long; `None` for no text, which leaves no record.
    pub fn of(boot: u64, text: &[u8]) -> Option<Self> {
        (!text.is_empty() && text.len() <= TEXT_BYTES).then(|| Self {
            boot,
            bytes: text.len() as u32,
            checksum: crc32_ieee(text),
        })
    }

    /// The pieces the text is written in.
    pub fn pieces(&self) -> usize {
        (self.bytes as usize).div_ceil(PIECE_BYTES)
    }

    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(MAGIC);
        header[8..12].copy_from_slice(&VERSION.to_le_bytes());
        header[12..16].copy_from_slice(&(self.pieces() as u32).to_le_bytes());
        header[16..20].copy_from_slice(&self.bytes.to_le_bytes());
        header[20..24].copy_from_slice(&self.checksum.to_le_bytes());
        header[24..32].copy_from_slice(&self.boot.to_le_bytes());
        header
    }

    fn decode(header: &[u8]) -> Result<Self, &'static str> {
        if header.len() != HEADER_BYTES || &header[..8] != MAGIC {
            return Err("its header is not a stop record's");
        }
        let word = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().expect("4 bytes"));
        if word(8) != VERSION {
            return Err("its header has another version");
        }
        let decoded = Self {
            boot: u64::from_le_bytes(header[24..32].try_into().expect("8 bytes")),
            bytes: word(16),
            checksum: word(20),
        };
        if decoded.bytes == 0
            || decoded.bytes as usize > TEXT_BYTES
            || word(12) as usize != decoded.pieces()
        {
            return Err("its header's sizes do not agree");
        }
        Ok(decoded)
    }
}

/// The pieces `text` is written in, in order: piece `index` is the value of
/// [`piece_name`]`(index)`.
pub fn pieces(text: &[u8]) -> impl Iterator<Item = &[u8]> {
    text.chunks(PIECE_BYTES)
}

/// What the firmware's variables hold of a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kept {
    /// No variable of a record.
    Absent,
    /// Variables that are no whole record, and why: a write that was cut
    /// short, or changed values.
    Damaged(&'static str),
    /// A stop's lines. Bytes that are not UTF-8 read as U+FFFD.
    Record { boot: u64, text: String },
}

/// Read a record from the header variable's value and each piece's, `None`
/// for a variable that does not exist.
pub fn read<P: AsRef<[u8]>>(header: Option<&[u8]>, pieces: &[Option<P>; PIECES]) -> Kept {
    let Some(header) = header else {
        return match pieces.iter().any(Option::is_some) {
            true => Kept::Damaged("it has no header: its write did not end"),
            false => Kept::Absent,
        };
    };
    let header = match Header::decode(header) {
        Ok(header) => header,
        Err(why) => return Kept::Damaged(why),
    };
    let mut text = alloc::vec::Vec::with_capacity(header.bytes as usize);
    for piece in &pieces[..header.pieces()] {
        let Some(piece) = piece else {
            return Kept::Damaged("a piece is missing");
        };
        text.extend_from_slice(piece.as_ref());
    }
    if text.len() != header.bytes as usize || crc32_ieee(&text) != header.checksum {
        return Kept::Damaged("its pieces do not match its header's checksum");
    }
    Kept::Record {
        boot: header.boot,
        text: String::from_utf8_lossy(&text).into_owned(),
    }
}

/// What a stop's line holds before its reason (`output::fatal`).
const FATAL: &str = "STELA FATAL ";
/// The most of a reason the screen shows ([`carried_notice`]).
const REASON_CHARACTERS: usize = 200;

/// The reason a record's stop gave, the text after [`FATAL`] on the newest
/// line that holds it; `None` where none does, as in a record whose stop
/// line was never written.
pub fn stop_reason(text: &str) -> Option<&str> {
    text.lines()
        .rev()
        .find_map(|line| line.split_once(FATAL).map(|(_, reason)| reason.trim()))
        .filter(|reason| !reason.is_empty())
}

/// What the screen says at the start after a stop whose record this PC's
/// firmware kept: the last start stopped, why where the record says
/// ([`stop_reason`]), and where its lines are now; `in_log` when the USB's
/// log took them. A stop that left no screen, as one after the GPU's
/// reset, is then told at the next start.
pub fn carried_notice(reason: Option<&str>, in_log: bool) -> String {
    let mut notice = String::from("The last start of Stela on this PC stopped");
    if let Some(reason) = reason {
        notice.push_str(": ");
        match reason.char_indices().nth(REASON_CHARACTERS) {
            Some((end, _)) => {
                notice.push_str(&reason[..end]);
                notice.push_str("...");
            }
            None => notice.push_str(reason),
        }
    }
    notice.push_str(if in_log {
        ". This PC kept its last lines, now in the log on this USB: on another computer, plug \
         in this USB and run `stela log`, which saves it to log.txt; include that file in a \
         report."
    } else {
        ". This PC keeps its last lines, but the log on this USB did not take them; they stay \
         for the next start."
    });
    notice
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    #[test]
    fn the_stop_reason_is_the_newest_fatal_line() {
        let text = "[  27.553] LINUX <6> kthreadd pid 2 published\n\
                    [  28.001] STELA FATAL first\n\
                    [  28.002] x86 exception\n\
                    [  28.003] STELA FATAL unexpected x86 exception: vector=6 drivers=here \n\
                    [  28.004] STELA STOPPED code=0x11; power off to continue\n";
        assert_eq!(
            stop_reason(text),
            Some("unexpected x86 exception: vector=6 drivers=here")
        );
        assert_eq!(stop_reason("[ 1.000] STEP Starting the GPU\n"), None);
        assert_eq!(stop_reason("STELA FATAL \n"), None);
        assert_eq!(stop_reason(""), None);
    }

    #[test]
    fn the_carried_notice_says_why_and_where_the_lines_are() {
        let logged = carried_notice(Some("GPU startup exceeded its deadline"), true);
        assert!(logged.starts_with(
            "The last start of Stela on this PC stopped: GPU startup exceeded its deadline. "
        ));
        assert!(logged.contains("`stela log`"));
        let kept = carried_notice(None, false);
        assert!(kept.starts_with("The last start of Stela on this PC stopped. "));
        assert!(kept.contains("did not take them"));
        // A long reason is cut on a character, not a byte.
        let long = "é".repeat(REASON_CHARACTERS + 5);
        let cut = carried_notice(Some(&long), true);
        assert!(cut.contains(&alloc::format!("{}...", "é".repeat(REASON_CHARACTERS))));
        assert!(!cut.contains(&"é".repeat(REASON_CHARACTERS + 1)));
    }

    /// What a stop writes for `text`: the header's value and each piece's.
    fn written(boot: u64, text: &[u8]) -> (Option<Vec<u8>>, [Option<Vec<u8>>; PIECES]) {
        let mut values = [const { None }; PIECES];
        let Some(header) = Header::of(boot, text) else {
            return (None, values);
        };
        assert_eq!(pieces(text).count(), header.pieces());
        for (value, piece) in values.iter_mut().zip(pieces(text)) {
            assert!(piece.len() <= PIECE_BYTES);
            *value = Some(piece.to_vec());
        }
        (Some(header.encode().to_vec()), values)
    }

    fn lines(count: usize) -> Vec<u8> {
        (0..count)
            .flat_map(|line| alloc::format!("[{line:5}.000] STEP line {line}\n").into_bytes())
            .collect()
    }

    #[test]
    fn names_are_nul_terminated_and_distinct() {
        let text = |name: &[u16]| String::from_utf16(&name[..name.len() - 1]).unwrap();
        assert_eq!(text(&HEADER_NAME), "StelaStopHeader");
        assert_eq!(HEADER_NAME[15], 0);
        for index in 0..PIECES {
            let name = piece_name(index);
            let digit = char::from_digit(index as u32, 36)
                .unwrap()
                .to_ascii_uppercase();
            assert_eq!(text(&name), alloc::format!("StelaStop{digit}"));
            assert_eq!(name[10], 0);
        }
    }

    #[test]
    fn no_text_leaves_no_record() {
        let tail = Tail::new();
        assert!(tail.text().is_empty());
        assert_eq!(Header::of(7, tail.text()), None);
        let (header, values) = written(7, tail.text());
        assert_eq!(read(header.as_deref(), &values), Kept::Absent);
    }

    #[test]
    fn text_shorter_than_one_piece_reads_back_whole() {
        let mut tail = Tail::new();
        tail.push(b"[    1.000] STEP Taking control\n");
        tail.push(b"[    1.250] STELA FATAL handoff refused\n");
        let text = tail.text().to_vec();
        let (header, values) = written(12, &text);
        assert_eq!(values.iter().flatten().count(), 1);
        assert_eq!(
            read(header.as_deref(), &values),
            Kept::Record {
                boot: 12,
                text: String::from_utf8(text).unwrap()
            }
        );
    }

    #[test]
    fn text_longer_than_the_record_keeps_its_newest_whole_lines() {
        let all = lines(4000);
        assert!(all.len() > 2 * TEXT_BYTES);
        // Pushed in uneven parts, as the log's ring hands them over.
        let mut tail = Tail::new();
        for part in all.chunks(777) {
            tail.push(part);
        }
        let text = tail.text();
        assert!(text.len() <= TEXT_BYTES && text.len() > TEXT_BYTES - 64);
        assert!(all.ends_with(text));
        assert!(text.starts_with(b"["), "starts at a line's start");
        assert!(
            text.ends_with(b"STEP line 3999\n"),
            "the stop's reason stays"
        );
        // In one part, too.
        let mut once = Tail::new();
        once.push(&all);
        assert_eq!(once.text(), text);
        let (header, values) = written(3, text);
        assert_eq!(values.iter().flatten().count(), PIECES);
        assert!(matches!(
            read(header.as_deref(), &values),
            Kept::Record { boot: 3, text: kept } if kept.as_bytes() == text
        ));
    }

    #[test]
    fn a_cut_at_a_line_boundary_drops_no_line_and_one_long_line_is_kept() {
        // Exactly one byte too many, and that byte ends a line.
        let mut exact = vec![b'\n'];
        exact.extend(lines(2000).into_iter().take(TEXT_BYTES));
        let mut tail = Tail::new();
        tail.push(&exact);
        assert_eq!(tail.text(), &exact[1..]);
        let mut tail = Tail::new();
        tail.push(&exact[..1]);
        tail.push(&exact[1..]);
        assert_eq!(tail.text(), &exact[1..]);
        // A line longer than the record has no boundary to cut at.
        let mut long = vec![b'x'; TEXT_BYTES + 100];
        long.push(b'\n');
        let mut tail = Tail::new();
        tail.push(&long);
        assert_eq!(tail.text(), &long[long.len() - TEXT_BYTES..]);
    }

    #[test]
    fn a_torn_record_is_never_read_as_one() {
        let text = lines(200);
        let text = &text[..3 * PIECE_BYTES + 10];
        let (header, values) = written(1, text);
        // Stopped before the header: pieces alone.
        assert!(matches!(read(None, &values), Kept::Damaged(_)));
        // An older record's header over a newer, shorter write's pieces.
        let (_, mut newer) = written(2, &lines(200)[..PIECE_BYTES + 5]);
        newer[2] = values[2].clone();
        newer[3] = values[3].clone();
        assert!(matches!(read(header.as_deref(), &newer), Kept::Damaged(_)));
        // A piece the firmware lost.
        let mut missing = values.clone();
        missing[1] = None;
        assert!(matches!(
            read(header.as_deref(), &missing),
            Kept::Damaged(_)
        ));
        // Pieces past the header's count are not read.
        let mut surplus = values.clone();
        surplus[7] = Some(vec![0xff; PIECE_BYTES]);
        assert!(matches!(
            read(header.as_deref(), &surplus),
            Kept::Record { boot: 1, .. }
        ));
    }

    #[test]
    fn a_changed_piece_or_header_fails_the_check() {
        let text = lines(40);
        let (header, values) = written(9, &text);
        let header = header.unwrap();
        let mut changed = values.clone();
        changed[0].as_mut().unwrap()[17] ^= 0x20;
        assert_eq!(
            read(Some(&header), &changed),
            Kept::Damaged("its pieces do not match its header's checksum")
        );
        for (at, why) in [
            (0, "its header is not a stop record's"),
            (8, "its header has another version"),
            (12, "its header's sizes do not agree"),
            (16, "its pieces do not match its header's checksum"),
            (20, "its pieces do not match its header's checksum"),
        ] {
            let mut damaged = header.clone();
            damaged[at] ^= 1;
            assert_eq!(read(Some(&damaged), &values), Kept::Damaged(why), "{at}");
        }
        assert!(matches!(
            read(Some(&header[..HEADER_BYTES - 1]), &values),
            Kept::Damaged(_)
        ));
        // A length past the record never reads past the pieces.
        let mut long = header.clone();
        long[16..20].copy_from_slice(&(TEXT_BYTES as u32 + 1).to_le_bytes());
        assert!(matches!(read(Some(&long), &values), Kept::Damaged(_)));
    }

    #[test]
    fn bytes_that_are_not_utf8_are_kept_and_read_as_replacements() {
        let mut tail = Tail::new();
        tail.push(b"STEP caf\xc3\xa9 \xff\xfe\n");
        // A cut inside a character: the record starts after a whole line,
        // so only a line longer than the record can begin with one.
        let (header, values) = written(0, tail.text());
        assert_eq!(
            read(header.as_deref(), &values),
            Kept::Record {
                boot: 0,
                text: String::from("STEP caf\u{e9} \u{fffd}\u{fffd}\n")
            }
        );
    }

    #[test]
    fn a_short_store_keeps_the_newest_whole_lines_that_fit() {
        let mut text = Vec::new();
        for line in 0..400u32 {
            text.extend_from_slice(format!("line {line:04} of the stopped boot\n").as_bytes());
        }
        let text = &text[..];
        assert!(text.len() > 8 * PIECE_BYTES && text.len() <= TEXT_BYTES);
        let space = |remaining| Space {
            maximum: 0x20000,
            remaining,
            largest: 0x2000,
        };
        // Room for all of it.
        assert_eq!(fitting(&space(0x10000), text), text);
        // Room for a part: the newest whole lines, in a record that fits.
        let short = space(STORE_RESERVE + store_bytes(4 * PIECE_BYTES));
        let kept = fitting(&short, text);
        assert!(!kept.is_empty() && kept.len() <= 4 * PIECE_BYTES);
        assert!(kept.len() > 3 * PIECE_BYTES - 64);
        assert!(text.ends_with(kept) && kept.starts_with(b"line "));
        assert!(short.takes(store_bytes(kept.len())));
        // Room for nothing.
        assert!(fitting(&space(STORE_RESERVE), text).is_empty());
        assert!(fitting(&space(0x10000), b"").is_empty());
    }

    #[test]
    fn pieces_past_the_tenth_are_named_by_letters() {
        let last = |index| piece_name(index)[9];
        assert_eq!(last(0), u16::from(b'0'));
        assert_eq!(last(9), u16::from(b'9'));
        assert_eq!(last(10), u16::from(b'A'));
        assert_eq!(last(PIECES - 1), u16::from(b'A') + (PIECES - 11) as u16);
    }

    #[test]
    fn a_record_is_written_only_into_a_store_it_leaves_a_reserve_in() {
        let needed = store_bytes(TEXT_BYTES);
        assert!(needed > TEXT_BYTES as u64 && needed < 2 * TEXT_BYTES as u64);
        let space = |maximum, remaining, largest| Space {
            maximum,
            remaining,
            largest,
        };
        assert!(space(0x10000, 0xe000, 0x2000).takes(needed));
        // A store two thirds full, as firmware often ships it.
        assert!(space(0x20000, 0xa000, 0x2000).takes(needed));
        assert!(space(0x10000, STORE_RESERVE + needed, 0x2000).takes(needed));
        assert!(!space(0x10000, STORE_RESERVE + needed - 1, 0x2000).takes(needed));
        // Less free than the record needs.
        assert!(!space(0x10000, needed - 1, 0x2000).takes(needed));
        // No store at all.
        assert!(!space(0, 0, 0).takes(needed));
        // Its largest variable is smaller than a piece.
        assert!(!space(0x10000, 0xe000, 0x200).takes(needed));
        // A short record needs less.
        assert!(store_bytes(100) < store_bytes(PIECE_BYTES + 1));
        assert!(space(0x10000, STORE_RESERVE + store_bytes(100), 0x2000).takes(store_bytes(100)));
        assert!(!space(0x10000, STORE_RESERVE + store_bytes(100), 0x2000).takes(needed));
    }
}
