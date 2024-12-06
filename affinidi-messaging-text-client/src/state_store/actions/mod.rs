use super::CommonSettings;

pub mod invitation;

#[derive(Debug, Clone)]
pub enum Action {
    SettingsPopupToggle,
    SettingsCheck { settings: CommonSettings },
    SettingsUpdate { settings: CommonSettings },
    InvitePopupStart,
    InvitePopupStop,
    SendMessage { content: String },
    SelectChat { chat: String },
    Exit,
}
