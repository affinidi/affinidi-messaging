use crate::{
    state_store::{
        actions::{chat_list::Chat, Action},
        ChatDetailsPopupState, State,
    },
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
use tracing::{error, info};

pub struct Props {}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {}
    }
}

pub struct AcceptInvitePopup {
    pub action_tx: UnboundedSender<Action>,
    // Mapped Props from State
    pub props: Props,
    // Child Components
}

impl Component for AcceptInvitePopup {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        AcceptInvitePopup {
            action_tx: action_tx.clone(),
            props: Props::from(state),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        AcceptInvitePopup {
            props: Props::from(state),
            ..self
        }
    }

    fn name(&self) -> &str {
        "Accept Invite"
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        match key.code {
            KeyCode::Esc => {
                let _ = self.action_tx.send(Action::CloseChatDetails);
            }
            _ => {}
        }
    }
}

impl ComponentRender<()> for AcceptInvitePopup {
    fn render(&self, frame: &mut Frame, _props: ()) {
        let outer_block = Block::bordered()
            .title(vec![
                Span::styled("Chat Details: ", Style::default().bold()),
                //Span::styled(&chat.name, Style::default().fg(Color::Blue)),
            ])
            .style(Style::default().bg(Color::White).fg(Color::Black).bold());
        let vertical = Layout::vertical([Constraint::Percentage(25)]).flex(Flex::Center);
        let horizontal = Layout::horizontal([Constraint::Percentage(70)]).flex(Flex::Center);
        let [outer_area] = vertical.areas(frame.area());
        let [outer_area] = horizontal.areas(outer_area);
        let inner_area = outer_block.inner(outer_area);

        // Clear the popup area first
        frame.render_widget(Clear, outer_area);

        // render the outer block
        outer_block.render(outer_area, frame.buffer_mut());

        let mut lines = vec![Line::default()];

        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled("<ESCAPE> ", Style::default().fg(Color::LightRed).bold()),
            Span::styled("to close, ", Style::default()),
        ]));

        Paragraph::new(lines)
            .left_aligned()
            .render(inner_area, frame.buffer_mut());
    }
}
