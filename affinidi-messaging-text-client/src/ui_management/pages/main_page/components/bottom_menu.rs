use ratatui::{
    layout::Rect,
    style::{Color, Style, Stylize},
    text::{self, Span},
    Frame,
};

use crate::ui_management::components::ComponentRender;

pub struct BottomMenu;

pub struct RenderProps {
    pub area: Rect,
}

impl ComponentRender<RenderProps> for BottomMenu {
    fn render(&self, frame: &mut Frame, props: RenderProps) {
        let menu = text::Line::from(vec![
            Span::styled(" F1", Style::default().fg(Color::Gray).bold()),
            Span::styled(" Setup ", Style::default().bg(Color::Cyan).fg(Color::Black)),
            Span::styled(" F2", Style::default().fg(Color::Gray).bold()),
            Span::styled(
                " Invite ",
                Style::default().bg(Color::Cyan).fg(Color::Black),
            ),
            Span::styled(" F3", Style::default().fg(Color::Gray).bold()),
            Span::styled(
                " Accept Invite ",
                Style::default().bg(Color::Cyan).fg(Color::Black),
            ),
            Span::styled(" F10", Style::default().fg(Color::Gray).bold()),
            Span::styled(" Quit ", Style::default().bg(Color::Cyan).fg(Color::Black)),
        ]);

        frame.render_widget(menu, props.area);
    }
}
