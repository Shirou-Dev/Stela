//! Every question `stela` asks, behind one interface: the terminal's
//! Clack-style prompts ([`Terminal`]), none at all for scripts
//! ([`NoTerminal`]), and in tests a script of answers that records what was
//! asked (`Scripted`). Each question can be declined, and declining changes
//! nothing.
use anyhow::{Result, bail};
use std::io::IsTerminal;

/// A check of typed text: the reason it is refused.
pub(super) type Validate = Box<dyn Fn(&str) -> Result<(), String>>;

pub(super) trait Ui {
    /// Whether someone can answer: a terminal on standard input and error.
    fn interactive(&self) -> bool;
    /// A line of text that is not shown.
    fn password(&self, prompt: &str, valid: Validate) -> Result<String>;
    /// Yes or no; no unless answered.
    fn confirm(&self, question: &str) -> Result<bool>;
}

/// The terminal's prompts, in Stela's Clack theme.
pub(super) struct Terminal;

impl Terminal {
    /// The terminal when standard input and error are one, else no one.
    pub(super) fn or_none() -> &'static dyn Ui {
        if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
            cliclack::set_theme(super::wizard::theme::Stela);
            &Terminal
        } else {
            &NoTerminal
        }
    }
}

impl Ui for Terminal {
    fn interactive(&self) -> bool {
        true
    }
    fn password(&self, prompt: &str, valid: Validate) -> Result<String> {
        Ok(cliclack::password(prompt)
            .mask('•')
            .validate(move |text: &String| valid(text))
            .interact()?)
    }
    fn confirm(&self, question: &str) -> Result<bool> {
        Ok(cliclack::confirm(question)
            .initial_value(false)
            .interact()?)
    }
}

/// No one to ask: scripts, CI and piped input. Every question is refused,
/// so a command stops before it changes anything it would ask about.
pub(super) struct NoTerminal;

impl Ui for NoTerminal {
    fn interactive(&self) -> bool {
        false
    }
    fn password(&self, prompt: &str, _: Validate) -> Result<String> {
        bail!("{prompt}: stela cannot ask without a terminal")
    }
    fn confirm(&self, question: &str) -> Result<bool> {
        bail!("{question} stela cannot ask without a terminal")
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque};

    /// What happens on the computer once a question is answered.
    type Hook<'a> = Option<Box<dyn Fn(&str) + 'a>>;

    /// A person at a terminal who gives these answers in order, and what
    /// they were asked: each prompt as `? prompt`. Answers are the text
    /// typed, or `yes` and `no`; `cancel` presses Escape.
    pub(crate) struct Scripted<'a> {
        answers: RefCell<VecDeque<String>>,
        pub(crate) shown: RefCell<Vec<String>>,
        hook: Hook<'a>,
    }

    impl<'a> Scripted<'a> {
        pub(crate) fn new(answers: &[&str]) -> Self {
            Self {
                answers: RefCell::new(answers.iter().map(|a| (*a).to_owned()).collect()),
                shown: RefCell::default(),
                hook: None,
            }
        }

        /// The same person, and `hook` run with each answer they give.
        pub(crate) fn with_hook(answers: &[&str], hook: impl Fn(&str) + 'a) -> Self {
            Self {
                hook: Some(Box::new(hook)),
                ..Self::new(answers)
            }
        }

        /// Everything shown, one line each.
        pub(crate) fn transcript(&self) -> String {
            self.shown.borrow().join("\n")
        }

        /// Whether every answer was taken.
        pub(crate) fn done(&self) -> bool {
            self.answers.borrow().is_empty()
        }

        fn show(&self, line: String) {
            self.shown.borrow_mut().push(line);
        }

        fn answer(&self, prompt: &str) -> Result<String> {
            let answer =
                self.answers.borrow_mut().pop_front().unwrap_or_else(|| {
                    panic!("no answer left for {prompt:?}:\n{}", self.transcript())
                });
            if answer == "cancel" {
                return Err(
                    std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled").into(),
                );
            }
            if let Some(hook) = &self.hook {
                hook(&answer);
            }
            Ok(answer)
        }
    }

    impl Ui for Scripted<'_> {
        fn interactive(&self) -> bool {
            true
        }
        fn password(&self, prompt: &str, valid: Validate) -> Result<String> {
            self.show(format!("? {prompt}"));
            let answer = self.answer(prompt)?;
            valid(&answer).unwrap_or_else(|why| panic!("{answer:?} refused: {why}"));
            Ok(answer)
        }
        fn confirm(&self, question: &str) -> Result<bool> {
            self.show(format!("? {question}"));
            Ok(self.answer(question)? == "yes")
        }
    }
}
