use chrono::Local;
use ratatui::{
    style::{Color, Style, Stylize},
    text::Line,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum ChatEffect {
    Ballons,
    Confetti,
    #[default]
    System,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum ChatMessageType {
    Inbound,
    Outbound,
    #[default]
    Error,
    Effect {
        effect: ChatEffect,
    },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChatMessage {
    pub _type: ChatMessageType,
    pub message: String,
    pub timestamp: chrono::DateTime<Local>,
}

impl ChatMessage {
    pub fn new(_type: ChatMessageType, message: String) -> Self {
        Self {
            _type,
            message,
            timestamp: Local::now(),
        }
    }

    pub fn render(&self) -> Line {
        match &self._type {
            ChatMessageType::Inbound => Line::styled(
                format!(
                    "{}: << {}",
                    self.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    self.message
                ),
                Style::default().fg(Color::Blue).bold(),
            ),
            ChatMessageType::Outbound => Line::styled(
                format!(
                    "{}: >> {}",
                    self.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    self.message
                ),
                Style::default().italic().fg(Color::LightBlue),
            ),
            ChatMessageType::Error => Line::styled(
                format!(
                    "{}: ERROR: {}",
                    self.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    self.message
                ),
                Style::default().red(),
            ),
            ChatMessageType::Effect { effect } => match effect {
                ChatEffect::Ballons => Line::styled(
                    format!(
                        "{}: << EFFECT:   You received some balloons!!!",
                        self.timestamp.format("%Y-%m-%d %H:%M:%S")
                    ),
                    Style::default().fg(Color::LightGreen),
                ),
                ChatEffect::Confetti => Line::styled(
                    format!(
                        "{}: << EFFECT:   You received some confetti!!!",
                        self.timestamp.format("%Y-%m-%d %H:%M:%S")
                    ),
                    Style::default().fg(Color::LightGreen),
                ),
                ChatEffect::System => Line::styled(
                    format!(
                        "{}: System Message: {}",
                        self.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        self.message
                    ),
                    Style::default().fg(Color::Yellow),
                ),
            },
        }
    }
}
