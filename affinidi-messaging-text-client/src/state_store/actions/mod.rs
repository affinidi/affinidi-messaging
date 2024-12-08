use super::CommonSettings;

pub mod chat_list;
pub mod invitation;

#[derive(Debug, Clone)]
pub enum Action {
    SettingsPopupToggle,
    SettingsCheck { settings: CommonSettings },
    SettingsUpdate { settings: CommonSettings },
    InvitePopupStart,
    InvitePopupStop,
    SendMessage { content: String },
    ShowChatDetails { chat: String },
    CloseChatDetails,
    DeleteChat { chat: String },
    Exit,
}
