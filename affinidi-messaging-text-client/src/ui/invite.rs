/*!
Handles OOB Invitation UI flow
*/

use ratatui::layout::Alignment;
use ratatui::prelude::Widget;
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, StatefulWidget, Wrap};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Flex, Layout, Rect},
    widgets::{Block, Clear},
};
use ratatui_image::{Resize, StatefulImage};

use crate::{App, Windows};

impl App {
    pub(crate) fn render_invite_popup(&mut self, area: Rect, buf: &mut Buffer) {
        if self.current_focus == Windows::Invite {
            let outer_block = Block::bordered()
                .title("OOB Invitation")
                .style(Style::default().bg(Color::White).fg(Color::Black).bold());
            let vertical = Layout::vertical([Constraint::Percentage(25)]).flex(Flex::Center);
            let horizontal = Layout::horizontal([Constraint::Percentage(50)]).flex(Flex::Center);
            let [outer_area] = vertical.areas(area);
            let [outer_area] = horizontal.areas(outer_area);
            Clear.render(outer_area, buf);

            let inner_area = outer_block.inner(outer_area);

            let inner_blocks = Layout::default()
                .direction(ratatui::layout::Direction::Horizontal)
                .constraints(vec![
                    Constraint::Max((inner_area.height * 2) + 2),
                    Constraint::Fill(1),
                ])
                .split(inner_area);

            let lines = vec![
                Line::from(vec![
                    Span::styled(
                        "Scan the QR code to accept this invitation.",
                        Style::default().bold(),
                    ),
                    Span::styled(" <escape> ", Style::default().bold().fg(Color::LightRed)),
                    Span::styled("to close this invitation pop-up.", Style::default().bold()),
                ]),
                Line::default(),
                Line::styled("Invitation Link", Style::default().bold().underlined()),
                Line::styled(
                    "http://example.com/oob/22899283472942",
                    Style::default().bold().fg(Color::LightBlue),
                ),
                Line::default(),
                Line::styled(
                    "Any DIDComm compatible agent can accept this invitation",
                    Style::default().bold(),
                ),
                Line::styled(
                    "Of course, we suggest using Affinidi Messenger",
                    Style::default().bold(),
                ),
                Line::styled(
                    "For more information, please visit:",
                    Style::default().bold(),
                ),
                Line::styled(
                    " https://affinidi.com/product/messaging",
                    Style::default().bold().fg(Color::LightBlue),
                ),
            ];
            let paragraph = Paragraph::new(lines)
                .alignment(Alignment::Left)
                .block(Block::bordered())
                .wrap(Wrap { trim: true });
            outer_block.render(outer_area, buf);

            // Render the QR Code
            let t_b = Block::bordered().title("Inner");
            t_b.render(inner_blocks[0], buf);
            let image = StatefulImage::new(None).resize(Resize::Fit(None));
            //println!("Inner Block {}", inner_blocks[0]);
            StatefulWidget::render(image, inner_blocks[0], buf, &mut self.image);
            //image.render(inner_blocks[0], buf, &mut self.image);

            paragraph.render(inner_blocks[1], buf);
        }
    }
}
