use crate::App;
use ratatui::{prelude::*, widgets::*};
use tui_logger::{TuiLoggerLevelOutput, TuiLoggerWidget};

impl App {
    /// Renders the top status bar
    pub(crate) fn render_top_status(&self, area: Rect, buf: &mut Buffer) {
        let elements = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        text::Line::from(vec![
            Span::styled(
                "Mediator Status: ",
                Style::default().fg(Color::LightBlue).bold(),
            ),
            Span::styled(
                " DISCONNECTED ",
                Style::default().bg(Color::Red).fg(Color::White).bold(),
            ),
        ])
        .render(elements[0], buf);

        Paragraph::new(self.time.format("%Y-%m-%d %H:%M:%S").to_string())
            .light_blue()
            .bold()
            .right_aligned()
            .render(elements[1], buf);
    }

    /// Renders the bottom Menu bar
    pub(crate) fn render_bottom_menu(&self, area: Rect, buf: &mut Buffer) {
        text::Line::from(vec![
            Span::styled(" F1", Style::default().fg(Color::Gray).bold()),
            Span::styled(" Help ", Style::default().bg(Color::Cyan).fg(Color::Black)),
            Span::styled(" F2", Style::default().fg(Color::Gray).bold()),
            Span::styled(" Setup ", Style::default().bg(Color::Cyan).fg(Color::Black)),
            Span::styled(" F3", Style::default().fg(Color::Gray).bold()),
            Span::styled(
                " Invite ",
                Style::default().bg(Color::Cyan).fg(Color::Black),
            ),
            Span::styled(" F4", Style::default().fg(Color::Gray).bold()),
            Span::styled(
                " Accept ",
                Style::default().bg(Color::Cyan).fg(Color::Black),
            ),
            Span::styled(" F10", Style::default().fg(Color::Gray).bold()),
            Span::styled(" Quit ", Style::default().bg(Color::Cyan).fg(Color::Black)),
        ])
        .render(area, buf);
    }

    pub(crate) fn render_logs(&self, area: Rect, buf: &mut Buffer) {
        TuiLoggerWidget::default()
            .block(Block::bordered().title("Log Window"))
            .style_error(Style::default().fg(Color::Red))
            .style_debug(Style::default().fg(Color::Green))
            .style_warn(Style::default().fg(Color::Yellow))
            .style_trace(Style::default().fg(Color::Magenta))
            .style_info(Style::default().fg(Color::Cyan))
            .output_level(Some(TuiLoggerLevelOutput::Abbreviated))
            .render(area, buf);
    }
}
