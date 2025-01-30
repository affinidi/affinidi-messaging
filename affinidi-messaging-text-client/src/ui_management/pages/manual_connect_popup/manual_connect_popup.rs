/*!
 * Popup that allows you to enter a remote DID to directly connect to
 * This will create a local DID
 *
 * There is no disovery occurring here - it is a point-to-point connection
 */
use crate::{
    state_store::{actions::Action, State},
    ui_management::components::{Component, ComponentRender},
};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    layout::{Constraint, Flex, Layout, Position},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Widget},
    Frame,
};
use tokio::sync::mpsc::UnboundedSender;
use tui_input::{backend::crossterm::EventHandler, Input};

pub struct Props {
    pub show: bool,
    pub remote_did: String,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            show: state.manual_connect_popup.show,
            remote_did: state.manual_connect_popup.remote_did.clone(),
        }
    }
}

pub struct ManualConnectPopup {
    pub action_tx: UnboundedSender<Action>,
    // Mapped Props from State
    pub props: Props,
    // Child Components
    pub remote_did: Input,
}

impl ManualConnectPopup {
    fn _reset_inputs(&mut self) {
        self.remote_did = Input::new(self.props.remote_did.clone());
    }
}

impl Component for ManualConnectPopup {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        ManualConnectPopup {
            action_tx: action_tx.clone(),
            props: Props::from(state),
            remote_did: Input::from(state.manual_connect_popup.remote_did.clone()),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        ManualConnectPopup {
            props: Props::from(state),
            ..self
        }
    }

    fn name(&self) -> &str {
        "Manual Connect"
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        fn _convert_input(input: &str) -> String {
            if input.is_empty() {
                String::new()
            } else {
                input.to_string()
            }
        }

        if key.kind != KeyEventKind::Press {
            return;
        }

        match key.code {
            KeyCode::Enter => {
                let _ = self.action_tx.send(Action::ManualConnect {
                    remote_did: _convert_input(self.remote_did.value()),
                });
            }
            KeyCode::Esc => {
                self._reset_inputs();
                let _ = self.action_tx.send(Action::ManualConnectPopupStop);
            }
            _ => {
                self.remote_did.handle_event(&Event::Key(key));
            }
        }
    }
}

impl ComponentRender<()> for ManualConnectPopup {
    fn render(&self, frame: &mut Frame, _props: ()) {
        let outer_block = Block::bordered()
            .title(vec![
                Span::styled("Accept Invitation", Style::default().bold()),
                //Span::styled(&chat.name, Style::default().fg(Color::Blue)),
            ])
            .style(Style::default().bg(Color::White).fg(Color::Black).bold());
        let vertical = Layout::vertical([Constraint::Percentage(30)]).flex(Flex::Center);
        let horizontal = Layout::horizontal([Constraint::Percentage(80)]).flex(Flex::Center);
        let [outer_area] = vertical.areas(frame.area());
        let [outer_area] = horizontal.areas(outer_area);
        let inner_area = outer_block.inner(outer_area);

        // Clear the popup area first
        frame.render_widget(Clear, outer_area);

        // render the outer block
        outer_block.render(outer_area, frame.buffer_mut());

        let vertical = Layout::vertical([
            Constraint::Length(3), // Invite Link
            Constraint::Length(1), // Invite Error message?
            Constraint::Min(1),    // Messages
            Constraint::Length(1), // Help text
        ])
        .split(inner_area);

        // Invitation Link
        let width = vertical[0].width.max(3) - 3;
        let remote_did_scroll = self.remote_did.visual_scroll(width as usize);

        // Mediator DID
        let input = Paragraph::new(self.remote_did.value())
            .style(Style::default().fg(Color::Cyan))
            .scroll((0, remote_did_scroll as u16))
            .block(Block::bordered().title("Remote Did?"));
        input.render(vertical[0], frame.buffer_mut());

        // set the cursor position
        let cursor: Position = (
            // Put cursor past the end of the input text
            vertical[0].x
                + ((self.remote_did.visual_cursor()).max(remote_did_scroll) - remote_did_scroll)
                    as u16
                + 1,
            // Move one line down, from the border to the input line
            vertical[0].y + 1,
        )
            .into();

        // Help text
        let help_line = Line::from(vec![
            Span::styled("<ENTER> ", Style::default().fg(Color::LightRed).bold()),
            Span::styled("to save, ", Style::default()),
            Span::styled("<ESCAPE> ", Style::default().fg(Color::LightRed).bold()),
            Span::styled("to quit, ", Style::default()),
        ]);
        let help = Paragraph::new(help_line).centered();
        help.render(vertical[3], frame.buffer_mut());

        frame.set_cursor_position(cursor);
    }
}
