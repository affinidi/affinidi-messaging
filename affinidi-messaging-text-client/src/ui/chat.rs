use crate::{App, Windows};
use ratatui::prelude::Widget;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    prelude::Stylize,
    style::{Color, Style},
    widgets::Block,
};

impl App {
    pub(crate) fn render_chat(&mut self, area: Rect, buf: &mut Buffer) {
        let window_style = if self.current_focus == Windows::Chat {
            Style::new().fg(Color::LightGreen).bg(Color::Reset).bold()
        } else {
            Style::new().fg(Color::White).bg(Color::Reset)
        };

        Block::bordered()
            .title("Chat Window")
            .style(window_style)
            .render(area, buf);
    }
}
