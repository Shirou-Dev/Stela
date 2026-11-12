//! Stela's palette on the standard Clack prompt layout, all orange: a muted
//! frame, a light orange for what is selected or finished, a vivid one for
//! warnings, and dim grey for everything else. The colors are xterm-256
//! entries 173, 215 and 208, so 256-color terminals match.
//!
//! Glyphs are written directly rather than through `console::Emoji`, which
//! falls back to ASCII outside Windows Terminal. Every glyph is present in
//! Consolas, so conhost windows such as the elevated one match other shells.
use cliclack::{StringCursor, Theme, ThemeState, termwrap};
use console::{Style, measure_text_width};

const STEP_ACTIVE: &str = "♦";
const STEP_SUBMIT: &str = "◊";
const STEP_CANCEL: &str = "■";
const STEP_ERROR: &str = "▲";
const BAR: &str = "│";
const BAR_START: &str = "┌";
const BAR_END: &str = "└";
const BAR_H: &str = "─";
const CONNECT_LEFT: &str = "├";
const CORNER_TOP_RIGHT: &str = "╮";
const CORNER_BOTTOM_RIGHT: &str = "╯";

#[derive(Default)]
pub(crate) struct Stela;

pub(crate) fn accent() -> Style {
    Style::new().true_color(215, 135, 95)
}

fn selection() -> Style {
    Style::new().true_color(255, 175, 95)
}

fn warning() -> Style {
    Style::new().true_color(255, 135, 0).bold()
}

/// The timeline's glyphs, for the progress phases that continue it.
pub(crate) fn rail() -> crate::progress::Rail {
    crate::progress::Rail {
        active: accent().apply_to(STEP_ACTIVE).to_string(),
        done: selection().apply_to(STEP_SUBMIT).to_string(),
        stopped: Style::new().red().apply_to(STEP_CANCEL).to_string(),
        bar: accent().apply_to(BAR).to_string(),
    }
}

impl Stela {
    pub(crate) fn bar(&self, state: &ThemeState) -> String {
        self.bar_color(state).apply_to(BAR).to_string()
    }

    fn framed(&self, state: &ThemeState, text: &str, style: &Style) -> String {
        text.lines()
            .map(|line| format!("{}  {}\n", self.bar(state), style.apply_to(line)))
            .collect()
    }
}

impl Theme for Stela {
    fn state_symbol(&self, state: &ThemeState) -> String {
        self.state_symbol_color(state)
            .apply_to(match state {
                ThemeState::Active => STEP_ACTIVE,
                ThemeState::Cancel => STEP_CANCEL,
                ThemeState::Submit => STEP_SUBMIT,
                ThemeState::Error(_) => STEP_ERROR,
            })
            .to_string()
    }

    fn radio_symbol(&self, state: &ThemeState, selected: bool) -> String {
        if !matches!(state, ThemeState::Active | ThemeState::Error(_)) {
            return String::new();
        }
        if selected {
            selection().apply_to("●")
        } else {
            Style::new().dim().apply_to("○")
        }
        .to_string()
    }

    fn checkbox_symbol(&self, state: &ThemeState, selected: bool, active: bool) -> String {
        if !matches!(state, ThemeState::Active | ThemeState::Error(_)) {
            return String::new();
        }
        let style = if selected || active {
            selection()
        } else {
            Style::new().dim()
        };
        style.apply_to(if selected { "■" } else { "□" }).to_string()
    }

    fn remark_symbol(&self) -> String {
        self.bar_color(&ThemeState::Submit)
            .apply_to(CONNECT_LEFT)
            .to_string()
    }

    fn info_symbol(&self) -> String {
        selection().apply_to("●").to_string()
    }

    fn warning_symbol(&self) -> String {
        warning().apply_to("▲").to_string()
    }

    fn error_symbol(&self) -> String {
        Style::new().red().apply_to("■").to_string()
    }

    fn active_symbol(&self) -> String {
        accent().apply_to(STEP_ACTIVE).to_string()
    }

    fn submit_symbol(&self) -> String {
        selection().apply_to(STEP_SUBMIT).to_string()
    }

    fn checkbox_style(&self, state: &ThemeState, selected: bool, active: bool) -> Style {
        match state {
            ThemeState::Cancel if selected => Style::new().dim().strikethrough(),
            ThemeState::Submit => Style::new().dim(),
            _ if active => Style::new().bold(),
            _ if selected => Style::new(),
            _ => Style::new().dim(),
        }
    }

    fn format_intro(&self, title: &str) -> String {
        let color = self.bar_color(&ThemeState::Submit);
        format!(
            "{}  {title}\n{}\n",
            color.apply_to(BAR_START),
            color.apply_to(BAR)
        )
    }

    fn format_outro(&self, message: &str) -> String {
        format!(
            "{}  {message}\n",
            self.bar_color(&ThemeState::Submit).apply_to(BAR_END)
        )
    }

    fn format_outro_cancel(&self, message: &str) -> String {
        format!(
            "{}  {}\n",
            self.bar_color(&ThemeState::Submit).apply_to(BAR_END),
            Style::new().red().apply_to(message)
        )
    }

    fn format_header(&self, state: &ThemeState, prompt: &str) -> String {
        prompt
            .lines()
            .enumerate()
            .map(|(i, line)| {
                let symbol = if i == 0 {
                    self.state_symbol(state)
                } else {
                    self.bar(state)
                };
                format!("{symbol}  {line}\n")
            })
            .collect()
    }

    fn format_footer_with_message(&self, state: &ThemeState, message: &str) -> String {
        let text = match state {
            ThemeState::Active if message.is_empty() => "↑/↓ move · Enter choose · Esc cancel",
            ThemeState::Active => message,
            ThemeState::Cancel => "Operation cancelled.",
            ThemeState::Error(error) => error,
            ThemeState::Submit => "",
        };
        if matches!(state, ThemeState::Submit) {
            format!("{}\n", self.bar(state))
        } else {
            format!("{}  {text}\n", self.bar_color(state).apply_to(BAR_END))
        }
    }

    fn format_scroll_indicator(
        &self,
        state: &ThemeState,
        has_above: bool,
        has_below: bool,
    ) -> String {
        if !has_above && !has_below {
            return String::new();
        }
        let arrow = |shown: bool, glyph: &str| {
            if shown {
                accent().apply_to(glyph.to_owned())
            } else {
                Style::new().dim().apply_to(glyph.to_owned())
            }
        };
        format!(
            "{}{}{}",
            arrow(has_above, "↑"),
            self.bar_color(state).apply_to('/'),
            arrow(has_below, "↓")
        )
    }

    fn format_input(&self, state: &ThemeState, cursor: &StringCursor) -> String {
        let style = self.input_style(state);
        let mut input = match state {
            ThemeState::Active | ThemeState::Error(_) => self.cursor_with_style(cursor, &style),
            _ => cursor.to_string(),
        };
        if input.ends_with('\n') {
            input.push('\n');
        }
        self.framed(state, &input, &style)
    }

    fn format_placeholder(&self, state: &ThemeState, cursor: &StringCursor) -> String {
        let style = self.placeholder_style(state);
        let placeholder = match state {
            ThemeState::Active | ThemeState::Error(_) => self.cursor_with_style(cursor, &style),
            ThemeState::Cancel => String::new(),
            _ => cursor.to_string(),
        };
        self.framed(state, &placeholder, &style)
    }

    fn format_select_item(
        &self,
        state: &ThemeState,
        selected: bool,
        label: &str,
        hint: &str,
    ) -> String {
        if matches!(state, ThemeState::Submit | ThemeState::Cancel) && !selected {
            return String::new();
        }
        let bar = self.bar(state);
        let label = if selected && matches!(state, ThemeState::Active) {
            Style::new().bold().apply_to(label).to_string()
        } else {
            label.to_owned()
        };
        let mut row = format!("{bar}  {}\n", self.radio_item(state, selected, &label, ""));
        if matches!(state, ThemeState::Active | ThemeState::Error(_)) && !hint.is_empty() {
            row.push_str(&format!(
                "{bar}      {}\n",
                Style::new().dim().apply_to(hint)
            ));
        }
        row
    }

    fn format_multiselect_item(
        &self,
        state: &ThemeState,
        selected: bool,
        active: bool,
        label: &str,
        hint: &str,
    ) -> String {
        if matches!(state, ThemeState::Submit | ThemeState::Cancel) && !selected {
            return String::new();
        }
        let bar = self.bar(state);
        let mut row = format!(
            "{bar}  {}\n",
            self.checkbox_item(state, selected, active, label, "")
        );
        if matches!(state, ThemeState::Active | ThemeState::Error(_)) && !hint.is_empty() {
            row.push_str(&format!(
                "{bar}      {}\n",
                Style::new().dim().apply_to(hint)
            ));
        }
        row
    }

    fn format_note_with_symbol(
        &self,
        is_outro: bool,
        symbol: &str,
        prompt: &str,
        message: &str,
    ) -> String {
        let prompt = termwrap(prompt, 7);
        let message = termwrap(message, 6);
        let color = self.bar_color(&ThemeState::Submit);
        let text = Style::new();
        let bar = color.apply_to(BAR).to_string();
        let symbol = if is_outro {
            color.apply_to(CONNECT_LEFT).to_string()
        } else {
            symbol.to_owned()
        };
        let prompt_lines: Vec<&str> = prompt
            .lines()
            .filter(|_| measure_text_width(&prompt) > 0)
            .collect();
        let message = if prompt_lines.is_empty() {
            message
        } else {
            format!("\n{message}")
        };
        let title = prompt_lines
            .last()
            .map(|line| format!("  {line} "))
            .unwrap_or_default();
        let width = message
            .lines()
            .map(|line| measure_text_width(line) + 2)
            .chain([measure_text_width(&title)])
            .max()
            .unwrap_or(0);
        let mut note = String::new();
        let preamble = prompt_lines.len().saturating_sub(1);
        for (i, line) in prompt_lines[..preamble].iter().enumerate() {
            let left = if i == 0 { &symbol } else { &bar };
            note.push_str(&format!("{left}  {line}\n"));
        }
        let left = if preamble > 0 { &bar } else { &symbol };
        note.push_str(&format!(
            "{left}{title}{}\n",
            color.apply_to(BAR_H.repeat(2 + width - measure_text_width(&title)) + CORNER_TOP_RIGHT)
        ));
        for line in message.lines() {
            note.push_str(&format!(
                "{bar}  {}{}{bar}\n",
                text.apply_to(line),
                " ".repeat(width - measure_text_width(line))
            ));
        }
        let corner = if is_outro { BAR_END } else { CONNECT_LEFT };
        note.push_str(&format!(
            "{}\n",
            color.apply_to(format!(
                "{corner}{}{CORNER_BOTTOM_RIGHT}",
                BAR_H.repeat(width + 2)
            ))
        ));
        if !is_outro {
            note.push_str(&format!("{bar}\n"));
        }
        note
    }

    fn format_log_with_spacing(&self, text: &str, symbol: &str, spacing: bool) -> String {
        let bar = self.bar(&ThemeState::Submit);
        let mut lines = text.lines().chain(spacing.then_some(""));
        let mut log = lines
            .next()
            .map(|first| format!("{symbol}  {first}\n"))
            .unwrap_or_default();
        for line in lines {
            log.push_str(&format!("{bar}  {line}\n"));
        }
        log
    }

    /// One frame color for every step, finished or not.
    fn bar_color(&self, state: &ThemeState) -> Style {
        match state {
            ThemeState::Active | ThemeState::Submit => accent(),
            ThemeState::Cancel => Style::new().red(),
            ThemeState::Error(_) => warning(),
        }
    }

    fn state_symbol_color(&self, state: &ThemeState) -> Style {
        match state {
            ThemeState::Submit => selection(),
            _ => self.bar_color(state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts_use_unicode_glyphs_outside_windows_terminal() {
        console::set_colors_enabled_stderr(false);
        console::set_colors_enabled(false);
        let theme = Stela;
        assert_eq!(
            theme.format_header(&ThemeState::Active, "Pick"),
            "♦  Pick\n"
        );
        assert_eq!(theme.radio_symbol(&ThemeState::Active, true), "●");
        assert_eq!(theme.radio_symbol(&ThemeState::Active, false), "○");
        assert_eq!(theme.checkbox_symbol(&ThemeState::Active, true, false), "■");
        assert_eq!(theme.checkbox_symbol(&ThemeState::Active, false, true), "□");
        assert_eq!(
            theme.format_note("Review", "USB  disk"),
            "◊  Review ────╮\n│             │\n│  USB  disk  │\n├─────────────╯\n│\n"
        );
    }
}
