/*!
Handles OOB Invitation UI flow
*/

use crate::{App, InputType, Windows};
use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::layout::Position;
use ratatui::prelude::Widget;
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Flex, Layout, Rect},
    widgets::{Block, Clear},
};
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

pub struct Settings {
    pub active_field: InputType,
    pub mediator_did: Input,
    pub mediator_did_scroll: usize,
    pub mediator_did_error: Option<String>,
    pub avatar_path: Input,
    pub avatar_path_scroll: usize,
    pub avatar_path_error: Option<String>,
    pub input_position: Position,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            active_field: InputType::MediatorDID,
            mediator_did: Input::default(),
            mediator_did_scroll: 0,
            mediator_did_error: None,
            avatar_path: Input::default(),
            avatar_path_scroll: 0,
            avatar_path_error: None,
            input_position: Position::default(),
        }
    }
}

impl App {
    fn _reset_inputs(&mut self) {
        self.current_focus = self.previous_focus.clone();
        self.settings_input.mediator_did = Input::new(self.history.mediator_did.clone());
        self.settings_input.avatar_path = Input::new(self.history.our_avatar_path.clone());
        self.settings_input.active_field = InputType::None;
    }

    /// Checks the settings inputs for errors
    /// Returns true on success, false on error
    pub async fn settings_checks(&mut self) -> bool {
        let mut ok_flag = true;
        if let Err(e) = self._check_avatar_path() {
            self.settings_input.avatar_path_error = Some(e.to_string());
            ok_flag = false;
        } else {
            self.settings_input.avatar_path_error = None;
        }
        if let Err(e) = self._check_mediator_did().await {
            self.settings_input.mediator_did_error = Some(e.to_string());
            ok_flag = false;
        } else {
            self.settings_input.mediator_did_error = None;
        }

        ok_flag
    }

    pub(crate) async fn settings_keys(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::F(2) => {
                // switch back to the previous focus
                self._reset_inputs();
                self.settings_checks().await;
            }
            KeyCode::Enter => {
                // Save this configuration
                self.settings_checks().await;
                if self.settings_input.mediator_did_error.is_some()
                    || self.settings_input.avatar_path_error.is_some()
                {
                    return;
                }

                self.history.mediator_did = self.settings_input.mediator_did.value().to_string();
                self.history.our_avatar_path = self.settings_input.avatar_path.value().to_string();
                self.history_changed = true;
                self._reset_inputs();
            }
            KeyCode::Up => {
                self.settings_checks().await;
                // Switch to the next input field
                match self.settings_input.active_field {
                    InputType::MediatorDID => {
                        self.settings_input.active_field = InputType::AvatarPath;
                    }
                    InputType::AvatarPath => {
                        self.settings_input.active_field = InputType::MediatorDID;
                    }
                    _ => {}
                }
            }
            KeyCode::Down => {
                self.settings_checks().await;
                // Switch to the next input field
                match self.settings_input.active_field {
                    InputType::MediatorDID => {
                        self.settings_input.active_field = InputType::AvatarPath;
                    }
                    InputType::AvatarPath => {
                        self.settings_input.active_field = InputType::MediatorDID;
                    }
                    _ => {}
                }
            }
            KeyCode::Tab => {
                self.settings_checks().await;
                // Switch to the next input field
                match self.settings_input.active_field {
                    InputType::MediatorDID => {
                        self.settings_input.active_field = InputType::AvatarPath;
                    }
                    InputType::AvatarPath => {
                        self.settings_input.active_field = InputType::MediatorDID;
                    }
                    _ => {}
                }
            }
            KeyCode::Esc => {
                self.settings_checks().await;
                // switch back to the previous focus
                self._reset_inputs();
            }
            _ => match self.settings_input.active_field {
                InputType::MediatorDID => {
                    self.settings_input
                        .mediator_did
                        .handle_event(&Event::Key(key));
                }
                InputType::AvatarPath => {
                    self.settings_input
                        .avatar_path
                        .handle_event(&Event::Key(key));
                }
                _ => {}
            },
        }
    }

    pub(crate) fn render_settings_popup(&mut self, area: Rect, buf: &mut Buffer) {
        if self.current_focus == Windows::Settings {
            if self.settings_input.active_field == InputType::None {
                // Reset to the first field in case we are coming in cold...
                self.settings_input.active_field = InputType::MediatorDID;
            }
            let outer_block = Block::bordered()
                .title("Settings")
                .style(Style::default().bg(Color::White).fg(Color::Black).bold());
            let vertical = Layout::vertical([Constraint::Percentage(25)]).flex(Flex::Center);
            let horizontal = Layout::horizontal([Constraint::Percentage(50)]).flex(Flex::Center);
            let [outer_area] = vertical.areas(area);
            let [outer_area] = horizontal.areas(outer_area);
            Clear.render(outer_area, buf);

            let inner_area = outer_block.inner(outer_area);

            // <Mediator Input>
            // Mediator error message?
            // <Avatar  Input>
            // Avatar error message?
            // Help Text
            let vertical = Layout::vertical([
                Constraint::Length(3),
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(inner_area);

            outer_block.render(outer_area, buf);

            // Mediator DID Input
            let width = vertical[0].width.max(3) - 3;
            let input_area = match self.settings_input.active_field {
                InputType::MediatorDID => {
                    self.settings_input.mediator_did_scroll = self
                        .settings_input
                        .mediator_did
                        .visual_scroll(width as usize);
                    vertical[0]
                }
                InputType::AvatarPath => {
                    self.settings_input.avatar_path_scroll = self
                        .settings_input
                        .avatar_path
                        .visual_scroll(width as usize);
                    vertical[2]
                }
                _ => vertical[0],
            };

            // Mediator DID
            let input = Paragraph::new(self.settings_input.mediator_did.value())
                .style(
                    if self.settings_input.active_field == InputType::MediatorDID {
                        Style::default().fg(Color::Cyan)
                    } else {
                        Style::default().fg(Color::Black)
                    },
                )
                .scroll((0, self.settings_input.mediator_did_scroll as u16))
                .block(Block::bordered().title("Mediator DID"));
            input.render(vertical[0], buf);

            // Mediator DID error?
            if let Some(error) = &self.settings_input.mediator_did_error {
                let error = Line::styled(error, Style::default().fg(Color::Red));
                error.render(vertical[1], buf);
            }

            // Avatar Image URL
            let avatar = Paragraph::new(self.settings_input.avatar_path.value())
                .style(
                    if self.settings_input.active_field == InputType::AvatarPath {
                        Style::default().fg(Color::Cyan)
                    } else {
                        Style::default().fg(Color::Black)
                    },
                )
                .scroll((0, self.settings_input.avatar_path_scroll as u16))
                .block(Block::bordered().title("Avatar Image Path"));
            avatar.render(vertical[2], buf);

            // Avatar path error?
            if let Some(error) = &self.settings_input.avatar_path_error {
                let error = Line::styled(error, Style::default().fg(Color::Red));
                error.render(vertical[3], buf);
            }

            // Help text
            let help_line = Line::from(vec![
                Span::styled("<TAB> ", Style::default().fg(Color::LightRed).bold()),
                Span::styled("to change input, ", Style::default()),
                Span::styled("<ENTER> ", Style::default().fg(Color::LightRed).bold()),
                Span::styled("to save, ", Style::default()),
                Span::styled("<ESCAPE> ", Style::default().fg(Color::LightRed).bold()),
                Span::styled("to quit, ", Style::default()),
            ]);
            let help = Paragraph::new(help_line).left_aligned();
            help.render(vertical[4], buf);

            // set the cursor position
            self.settings_input.input_position = (
                // Put cursor past the end of the input text
                if self.settings_input.active_field == InputType::MediatorDID {
                    input_area.x
                        + ((self.settings_input.mediator_did.visual_cursor())
                            .max(self.settings_input.mediator_did_scroll)
                            - self.settings_input.mediator_did_scroll)
                            as u16
                        + 1
                } else {
                    input_area.x
                        + ((self.settings_input.avatar_path.visual_cursor())
                            .max(self.settings_input.avatar_path_scroll)
                            - self.settings_input.avatar_path_scroll)
                            as u16
                        + 1
                },
                // Move one line down, from the border to the input line
                input_area.y + 1,
            )
                .into();
        }
    }

    async fn _check_mediator_did(&mut self) -> Result<(), std::io::Error> {
        let value = self.settings_input.mediator_did.value();

        if value.is_empty() {
            return Ok(()); // Empty is fine
        }

        if let Err(e) = self.did_resolver.resolve(value).await {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Mediator DID is invalid: {}", e),
            ))
        } else {
            Ok(())
        }
    }

    /// Checks if the avatar path is correct
    fn _check_avatar_path(&mut self) -> Result<(), std::io::Error> {
        let value = self.settings_input.avatar_path.value();

        if value.is_empty() {
            return Ok(()); // Empty is fine
        }

        let metadata = std::fs::metadata(value)?;
        if metadata.is_file() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Avatar path is not a file",
            ))
        }
    }
}
