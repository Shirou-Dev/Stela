//! Capacity-aware menus with fixed hint rows.
use anyhow::{Result, ensure};
use cliclack::{Theme, ThemeState};
use console::{Key, Style, Term, truncate_str};
use std::io;

#[derive(Clone)]
pub(crate) struct Item {
    pub value: usize,
    pub label: String,
    pub hint: String,
    pub enabled: bool,
}
struct Cursor(Term);
impl Drop for Cursor {
    fn drop(&mut self) {
        let _ = self.0.show_cursor();
    }
}
/// The value of the item chosen; Escape is an `Interrupted` error, which
/// the caller reports.
pub(crate) fn select(prompt: &str, items: &[Item], initial: usize) -> Result<usize> {
    ensure!(
        items.iter().any(|item| item.enabled),
        "{prompt}: nothing here can be chosen"
    );
    let term = Term::stderr();
    term.hide_cursor()?;
    let _cursor = Cursor(term.clone());
    let theme = super::theme::Stela;
    let hints = items.iter().any(|item| !item.hint.is_empty());
    let mut chosen = initial;
    let mut printed = 0;
    loop {
        let visible: Vec<_> = (0..items.len()).collect();
        let enabled: Vec<_> = visible
            .iter()
            .copied()
            .filter(|&i| items[i].enabled)
            .collect();
        let cursor = enabled
            .iter()
            .position(|&i| items[i].value == chosen)
            .unwrap_or(0);
        let selected = enabled[cursor];
        chosen = items[selected].value;
        let current_row = visible.iter().position(|&i| i == selected).unwrap();
        let start = current_row.saturating_sub(if hints { 5 } else { 8 });
        let rows = if hints { 6 } else { 9 };
        let mut lines: Vec<String> = theme
            .format_header(&ThemeState::Active, prompt)
            .lines()
            .map(str::to_owned)
            .collect();
        for &index in visible.iter().skip(start).take(rows) {
            let item = &items[index];
            // A menu with hint rows shows them below each label.
            let label = if item.enabled || hints {
                item.label.clone()
            } else {
                format!("{} [unavailable]", item.label)
            };
            let line = theme
                .format_select_item(&ThemeState::Active, index == selected, &label, "")
                .trim_end()
                .to_owned();
            lines.push(if item.enabled {
                line
            } else {
                Style::new().dim().apply_to(line).to_string()
            });
            if hints {
                lines.push(format!(
                    "{}      {}",
                    theme.bar(&ThemeState::Active),
                    Style::new().dim().apply_to(&item.hint)
                ));
            }
        }
        let help = "↑/↓ move · Enter choose · Esc cancel";
        lines.extend(
            theme
                .format_footer_with_message(&ThemeState::Active, help)
                .lines()
                .map(str::to_owned),
        );
        term.clear_last_lines(printed)?;
        let width = usize::from(term.size().1).saturating_sub(1).max(20);
        for line in &lines {
            term.write_line(&truncate_str(line, width, "…"))?;
        }
        printed = lines.len();
        match term.read_key()? {
            Key::ArrowUp => chosen = items[enabled[cursor.saturating_sub(1)]].value,
            Key::ArrowDown => chosen = items[enabled[(cursor + 1).min(enabled.len() - 1)]].value,
            Key::Enter => {
                term.clear_last_lines(printed)?;
                let text = theme.format_header(&ThemeState::Submit, prompt)
                    + &theme.format_select_item(
                        &ThemeState::Submit,
                        true,
                        &items[selected].label,
                        "",
                    )
                    + &theme.format_footer(&ThemeState::Submit);
                term.write_str(&text)?;
                return Ok(chosen);
            }
            Key::Escape | Key::CtrlC => {
                term.clear_last_lines(printed)?;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled").into());
            }
            _ => {}
        }
    }
}
