use super::CommonSettings;

pub mod chat_list;
pub mod invitation;

#[derive(Debug, Clone)]
pub enum Action {
    // Settings Related
    SettingsPopupToggle,
    SettingsCheck { settings: CommonSettings },
    SettingsUpdate { settings: CommonSettings },
    // OOB Invitation Create
    InvitePopupStart,
    InvitePopupStop,
    // Chat information
    ShowChatDetails { chat: String },
    CloseChatDetails,
    DeleteChat { chat: String },
    SetCurrentChat { chat: String },
    // other
    SendMessage { content: String },
    Exit,
}
