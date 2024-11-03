use ratatui::{
    buffer::Buffer,
    layout::Rect,
    prelude::Stylize,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, List, ListState, StatefulWidget},
};

use crate::{App, Windows};

#[derive(Default)]
pub(crate) struct ChannelList {
    pub(crate) channels: Vec<Channel>,
    pub(crate) state: ListState,
}

impl FromIterator<(String, u32)> for ChannelList {
    fn from_iter<I: IntoIterator<Item = (String, u32)>>(iter: I) -> Self {
        let channels = iter
            .into_iter()
            .map(|(name, unread_msgs)| Channel::new(name, unread_msgs))
            .collect();
        let state = ListState::default();
        Self { channels, state }
    }
}

pub(crate) struct Channel {
    pub(crate) name: String,
    pub(crate) unread_msgs: u32,
}

impl Channel {
    pub(crate) fn new(name: String, unread_msgs: u32) -> Self {
        Self { name, unread_msgs }
    }
}

impl App {
    pub(crate) fn render_channels(&mut self, area: Rect, buf: &mut Buffer) {
        let mut list = Vec::new();

        let name_style = Style::default().fg(Color::LightBlue).bold();
        let count_style = Style::default().fg(Color::Green).bold();
        self.channels.channels.iter().for_each(|channel| {
            list.push(Line::from(vec![
                Span::styled(channel.name.to_string(), name_style),
                Span::styled(format!(" ({})", channel.unread_msgs), count_style),
            ]));
        });

        let channel_style = if self.current_focus == Windows::Channels {
            Style::new().fg(Color::LightGreen).bg(Color::Reset).bold()
        } else {
            Style::new().fg(Color::White).bg(Color::Reset)
        };

        let channels = List::new(list)
            .block(Block::bordered().title("Channels"))
            .style(channel_style)
            .highlight_style(Style::new().italic().bg(Color::Gray))
            .direction(ratatui::widgets::ListDirection::TopToBottom);

        StatefulWidget::render(channels, area, buf, &mut self.channels.state);
    }
}
