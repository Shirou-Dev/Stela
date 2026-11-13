//! Which host-drivers calls a service turn's store may put off.
//!
//! `stela-boot` reaches every host disk through one lock, which another
//! processor can hold for hundreds of milliseconds (a USB stick's command
//! start, a GPU pump). The boot log's and the NOR's stores run in a service
//! turn, which holds its PE inside one exit, and XNU's watchdog resets the
//! machine once an exit passes about half a second. In a turn such a store
//! never waits for the lock to look at its disk: a look (a command's
//! completion, a posted completion, whether the disk signals) or a commit
//! that finds the lock taken is put off to the next turn, and the disk has
//! no room for a new command while another processor holds the lock, so its
//! start does not wait either. A start rings its doorbell at once, as a
//! commit can be put off. Outside a turn every call waits, as before.

/// A disk call that needs the host drivers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    /// A command's completion, a posted completion or whether the disk
    /// signals: nothing yet is an answer the caller polls again for.
    Look,
    /// A new command: only after the disk said it has room.
    Start,
    /// The doorbell of commands started without one.
    Commit,
}

/// How a call takes the host drivers' lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// Wait for the lock.
    Wait,
    /// Take it only when free, else put the call off.
    Try,
}

/// How `call` takes the lock, in a turn's store when `turn`.
pub const fn entry(turn: bool, call: Call) -> Entry {
    match (turn, call) {
        (true, Call::Look | Call::Commit) => Entry::Try,
        _ => Entry::Wait,
    }
}

/// Whether the disk takes a command now: `device` when it has room, and in
/// a turn not while another processor holds the drivers (`taken`).
pub const fn room(turn: bool, taken: bool, device: bool) -> bool {
    device && !(turn && taken)
}

/// Whether a started command's doorbell rings at once: unless `more`
/// follow, and always in a turn, whose commit may be put off.
pub const fn rings_at_once(turn: bool, more: bool) -> bool {
    turn || !more
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_turn_puts_off_looks_and_commits() {
        assert_eq!(entry(true, Call::Look), Entry::Try);
        assert_eq!(entry(true, Call::Commit), Entry::Try);
        // A start comes only after room said the lock was free.
        assert_eq!(entry(true, Call::Start), Entry::Wait);
    }

    #[test]
    fn outside_a_turn_every_call_waits() {
        for call in [Call::Look, Call::Start, Call::Commit] {
            assert_eq!(entry(false, call), Entry::Wait);
        }
    }

    #[test]
    fn a_turn_finds_no_room_while_the_drivers_are_taken() {
        assert!(!room(true, true, true));
        assert!(room(true, false, true));
        assert!(room(false, true, true));
        assert!(!room(false, false, false));
        assert!(!room(true, false, false));
    }

    #[test]
    fn a_turn_rings_every_start_at_once() {
        assert!(rings_at_once(true, true));
        assert!(rings_at_once(true, false));
        assert!(rings_at_once(false, false));
        assert!(!rings_at_once(false, true));
    }
}
