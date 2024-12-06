use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    state_store::{actions::Action, State},
    ui_management::{
        components::{Component, ComponentRender},
        pages::main_page::section::{
            usage::{HasUsageInfo, UsageInfo, UsageInfoLine},
            SectionActivation,
        },
    },
};
pub struct ChatState {
    pub name: String,
    pub description: String,
    pub has_unread: bool,
}

struct Props {
    /// List of chats and current state of those chats
    chats: Vec<ChatState>,
    /// Current active chat
    active_chat: Option<String>,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        let mut chats = state
            .chat_data_map
            .iter()
            .map(|(name, chat_data)| ChatState {
                name: name.clone(),
                description: chat_data.description.clone(),
                has_unread: chat_data.has_unread,
            })
            .collect::<Vec<ChatState>>();

        chats.sort_by(|chat_a, chat_b| chat_a.name.cmp(&chat_b.name));

        Self {
            chats,
            active_chat: state.active_chat.clone(),
        }
    }
}

impl ChatList {
    fn next(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.props.chats.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.props.chats.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };

        self.list_state.select(Some(i));
    }

    pub(super) fn chats(&self) -> &Vec<ChatState> {
        &self.props.chats
    }

    fn get_chat_idx(&self, name: &str) -> Option<usize> {
        self.props
            .chats
            .iter()
            .enumerate()
            .find_map(|(idx, chat_state)| {
                if chat_state.name == name {
                    Some(idx)
                } else {
                    None
                }
            })
    }
}

pub struct ChatList {
    action_tx: UnboundedSender<Action>,
    props: Props,
    pub list_state: ListState,
}

impl Component for ChatList {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self {
        Self {
            action_tx,
            props: Props::from(state),
            list_state: ListState::default(),
        }
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        Self {
            props: Props::from(state),
            ..self
        }
    }

    fn name(&self) -> &str {
        "Chat List"
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        match key.code {
            KeyCode::Up => {
                self.previous();
            }
            KeyCode::Down => {
                self.next();
            }
            KeyCode::Enter if self.list_state.selected().is_some() => {
                let selected_idx = self.list_state.selected().unwrap();

                let chats = self.chats();
                let chat_state = chats.get(selected_idx).unwrap();

                // TODO: handle the error scenario somehow
                let _ = self.action_tx.send(Action::SelectChat {
                    chat: chat_state.name.clone(),
                });
            }
            _ => (),
        }
    }
}

impl SectionActivation for ChatList {
    fn activate(&mut self) {
        let idx: usize = self
            .props
            .active_chat
            .as_ref()
            .and_then(|chat_name| self.get_chat_idx(chat_name.as_str()))
            .unwrap_or(0);

        *self.list_state.offset_mut() = 0;
        self.list_state.select(Some(idx));
    }

    fn deactivate(&mut self) {
        *self.list_state.offset_mut() = 0;
        self.list_state.select(None);
    }
}

pub struct RenderProps {
    pub border_color: Color,
    pub area: Rect,
}

impl ComponentRender<RenderProps> for ChatList {
    fn render(&self, frame: &mut Frame, props: RenderProps) {
        let active_chat = self.props.active_chat.clone();
        let chat_list: Vec<ListItem> = self
            .chats()
            .iter()
            .map(|room_state| {
                let room_tag = format!(
                    "#{}{}",
                    room_state.name,
                    if room_state.has_unread { "*" } else { "" }
                );
                let content = Line::from(Span::raw(room_tag));

                let style = if self.list_state.selected().is_none()
                    && active_chat.is_some()
                    && active_chat.as_ref().unwrap().eq(&room_state.name)
                {
                    Style::default().add_modifier(Modifier::BOLD)
                } else if room_state.has_unread {
                    Style::default().add_modifier(Modifier::SLOW_BLINK | Modifier::ITALIC)
                } else {
                    Style::default()
                };

                ListItem::new(content).style(style.bg(Color::Reset))
            })
            .collect();

        let chat_list = List::new(chat_list)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(props.border_color))
                    .title("Chats"),
            )
            .highlight_style(
                Style::default()
                    // yellow that would work for both dark / light modes
                    .bg(Color::Rgb(255, 223, 102))
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">");

        let mut app_chat_list_state = self.list_state.clone();
        frame.render_stateful_widget(chat_list, props.area, &mut app_chat_list_state);
    }
}

impl HasUsageInfo for ChatList {
    fn usage_info(&self) -> UsageInfo {
        UsageInfo {
            description: Some("Select the chat to talk in".into()),
            lines: vec![
                UsageInfoLine {
                    keys: vec!["Esc".into()],
                    description: "to cancel".into(),
                },
                UsageInfoLine {
                    keys: vec!["↑".into(), "↓".into()],
                    description: "to navigate".into(),
                },
                UsageInfoLine {
                    keys: vec!["Enter".into()],
                    description: "to join room".into(),
                },
            ],
        }
    }
}
