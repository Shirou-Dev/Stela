//! Capacity-aware menus with fixed hint rows and Escape-to-parent submenus.
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
pub(crate) fn select(prompt: &str, items: &[Item], initial: usize) -> Result<usize> {
    run(prompt, items, initial, false)
}
pub(crate) fn submenu(prompt: &str, items: &[Item], initial: usize) -> Result<Option<usize>> {
    let mut rows = items.to_vec();
    rows.push(Item {
        value: usize::MAX,
        label: "Back".into(),
        hint: String::new(),
        enabled: true,
    });
    Ok(match run(prompt, &rows, initial, true)? {
        usize::MAX => None,
        value => Some(value),
    })
}
fn run(prompt: &str, items: &[Item], initial: usize, submenu: bool) -> Result<usize> {
    ensure!(
        items.iter().any(|item| item.enabled),
        "{prompt}: nothing here can be chosen"
    );
    let term = Term::stderr();
    term.hide_cursor()?;
    let _cursor = Cursor(term.clone());
    let theme = super::theme::Stela;
    let hints = !submenu && items.iter().any(|item| !item.hint.is_empty());
    let mut query = String::new();
    let mut chosen = initial;
    let mut printed = 0;
    loop {
        let visible: Vec<_> = items
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                !submenu
                    || item.value == usize::MAX
                    || item.label.to_lowercase().contains(&query.to_lowercase())
            })
            .map(|(i, _)| i)
            .collect();
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
        if submenu {
            lines.push(format!(
                "{}  {}",
                theme.bar(&ThemeState::Active),
                Style::new().dim().apply_to(if query.is_empty() {
                    "Type to filter".into()
                } else {
                    format!("Filter: {query}")
                })
            ));
        }
        for &index in visible.iter().skip(start).take(rows) {
            let item = &items[index];
            // A submenu shows the chosen row's hint, and every greyed-out
            // row's reason, beside its label; a menu with hint rows shows
            // them below.
            let beside = submenu && (index == selected || !item.enabled);
            let label = if beside && !item.hint.is_empty() {
                format!(
                    "{}  {}",
                    item.label,
                    Style::new().dim().apply_to(&item.hint)
                )
            } else if item.enabled || hints {
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
        let help = if submenu {
            "↑/↓ move · Enter choose · Esc back · Type to filter"
        } else {
            "↑/↓ move · Enter choose · Esc cancel"
        };
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
                if submenu && chosen == usize::MAX {
                    return Ok(chosen);
                }
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
            Key::Escape if submenu => {
                term.clear_last_lines(printed)?;
                return Ok(usize::MAX);
            }
            Key::Escape | Key::CtrlC => {
                cliclack::outro_cancel("Setup cancelled. Your USB was not changed.")?;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "setup cancelled").into());
            }
            Key::Backspace if submenu => {
                query.pop();
            }
            Key::Char(c) if submenu && !c.is_control() => {
                query.push(c);
            }
            _ => {}
        }
    }
}
