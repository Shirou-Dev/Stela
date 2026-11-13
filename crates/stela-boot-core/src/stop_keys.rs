//! Ctrl+Alt+Delete from the 8042 keyboard controller's scancodes, the PC's
//! restart request, for a stopped boot that no longer has a keyboard
//! driver. The controller translates to scancode set 1 by default: a make
//! code, the same code with bit 7 set as its break, and an `E0` prefix
//! before the right-hand and the grey keys.

const EXTENDED: u8 = 0xe0;
const BREAK: u8 = 0x80;
const CONTROL: u8 = 0x1d;
const ALT: u8 = 0x38;
const DELETE: u8 = 0x53;

/// The keys held, from the bytes read so far.
#[derive(Debug, Default, Clone, Copy)]
pub struct Keys {
    extended: bool,
    /// Left and right.
    control: [bool; 2],
    alt: [bool; 2],
}

impl Keys {
    pub const fn new() -> Self {
        Self {
            extended: false,
            control: [false; 2],
            alt: [false; 2],
        }
    }

    /// Take the next byte from the keyboard; whether it is Delete pressed
    /// with a Control and an Alt key held.
    pub fn feed(&mut self, byte: u8) -> bool {
        if byte == EXTENDED {
            self.extended = true;
            return false;
        }
        let side = usize::from(core::mem::take(&mut self.extended));
        let pressed = byte & BREAK == 0;
        match byte & !BREAK {
            CONTROL => self.control[side] = pressed,
            ALT => self.alt[side] = pressed,
            // The grey Delete and the keypad's.
            DELETE if pressed => {
                return self.control.contains(&true) && self.alt.contains(&true);
            }
            _ => {}
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed every byte; whether any of them was the request.
    fn feed(keys: &mut Keys, bytes: &[u8]) -> bool {
        let mut hit = false;
        for byte in bytes {
            hit |= keys.feed(*byte);
        }
        hit
    }

    #[test]
    fn delete_counts_only_with_control_and_alt_held() {
        let mut keys = Keys::new();
        assert!(!feed(&mut keys, &[0xe0, 0x53, 0xe0, 0xd3]));
        assert!(!feed(&mut keys, &[0x1d, 0xe0, 0x53, 0xe0, 0xd3]));
        // Left Control, left Alt, grey Delete.
        assert!(feed(&mut keys, &[0x38, 0xe0, 0x53]));
        // Alt released: Delete alone again.
        assert!(!feed(&mut keys, &[0xb8, 0xe0, 0x53]));
    }

    #[test]
    fn right_hand_keys_and_the_keypad_delete_count_and_releases_do_not() {
        let mut keys = Keys::new();
        // Right Control and right Alt, the keypad's Delete.
        assert!(feed(&mut keys, &[0xe0, 0x1d, 0xe0, 0x38, 0x53]));
        // The break of Delete is no press.
        assert!(!feed(&mut keys, &[0xd3]));
        // Releasing the right Control leaves the left one unheld too.
        assert!(!feed(&mut keys, &[0xe0, 0x9d, 0x53]));
        // Other keys between change nothing.
        assert!(feed(&mut keys, &[0x1d, 0x1e, 0x9e, 0xe0, 0x53]));
    }
}
