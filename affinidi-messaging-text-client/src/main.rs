use std::{
    collections::HashMap,
    sync::{LazyLock, RwLock},
    time::{Duration, Instant},
};

use affinidi_did_resolver_cache_sdk::{config::ClientConfigBuilder, DIDCacheClient};
use affinidi_messaging_sdk::{config::ConfigBuilder, ATM};
use chrono::prelude::*;
use color_eyre::Result;
use config::ClientConfig;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use image::ImageReader;
use log::LevelFilter;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    widgets::Widget,
    DefaultTerminal, Frame,
};
use ratatui_image::{picker::Picker, protocol::StatefulProtocol};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tui_input::Input;
use tui_logger::TuiWidgetState;
use ui::{channels::ChannelList, settings::Settings};

mod config;
mod messages;
mod ui;

// Global variable to store the ATM instances
static mut ATMS: RwLock<LazyLock<HashMap<String, ATM>>> =
    RwLock::new(LazyLock::new(|| HashMap::new()));

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tui_logger::tracing_subscriber_layer())
        .init();
    tui_logger::init_logger(LevelFilter::Info).unwrap();

    color_eyre::install()?;
    let terminal = ratatui::init();
    let app_result = App::new().await.run(terminal).await;
    ratatui::restore();

    match app_result {
        Ok(app) => {
            if app.history_changed {
                println!("Saving configuration...");
                ClientConfig::save(&app.history, "client_config.json")?;
            } else {
                println!("No configuration changes detected. Exiting...");
            }
        }
        Err(e) => {
            eprintln!("An error occurred: {}", e);
        }
    }

    Ok(())
}

#[derive(Clone, PartialEq)]
pub enum Windows {
    Channels,
    Chat,
    Help,
    Invite,
    Settings,
}

#[derive(Clone, PartialEq)]
pub enum InputType {
    None,
    MediatorDID,
    AvatarPath,
    ChatMessage,
}

struct App {
    did_resolver: DIDCacheClient,
    time: DateTime<Local>,
    channels: ChannelList,
    should_exit: bool,
    current_focus: Windows,
    previous_focus: Windows,
    image: StatefulProtocol,
    pub(crate) history: ClientConfig,
    history_changed: bool,
    settings_input: Settings,
    logging_state: TuiWidgetState,
}

impl App {
    async fn new() -> Self {
        let mut picker = Picker::from_query_stdio().unwrap();
        let dyn_img = ImageReader::open("./qr_code.png")
            .expect("Couldn't open image")
            .decode()
            .expect("Couldn't decode image");

        let resolver_config = ClientConfigBuilder::default().build();

        let mut app = App {
            did_resolver: DIDCacheClient::new(resolver_config)
                .await
                .expect("Failed to create DID Resolver"),
            time: Local::now(),
            channels: ChannelList::default(),
            should_exit: false,
            current_focus: Windows::Channels,
            previous_focus: Windows::Channels,
            image: picker.new_resize_protocol(dyn_img),
            history: ClientConfig::default(),
            history_changed: false,
            settings_input: Settings::default(),
            logging_state: TuiWidgetState::default(),
        };

        if let Ok(conf) = ClientConfig::load("client_config.json") {
            app.history = conf;

            app.settings_input.avatar_path = Input::new(app.history.our_avatar_path.clone());
            app.settings_input.mediator_did = Input::new(app.history.mediator_did.clone());
            // Connect to the mediator here?
        } else {
            // Default to asking for the mediator DID
            app.current_focus = Windows::Settings;
        }

        // Check the settings
        if app.settings_checks().await {
            let mut atm_config =
                ConfigBuilder::default().with_external_did_resolver(&app.did_resolver);

            for contact in app.history.contacts.iter() {
                /*ATMS.write()
                .unwrap()
                .insert(contact.alias, ATM::new(atm_config.build()).await?);*/
            }
        } else {
            // If the settings are not valid, switch to the settings window
            app.current_focus = Windows::Settings;
        }

        app
    }

    async fn run(mut self, mut terminal: DefaultTerminal) -> Result<Self> {
        let tick_rate = Duration::from_secs(1);
        let mut last_tick = Instant::now();

        while !self.should_exit {
            terminal.draw(|frame| {
                frame.render_widget(&mut self, frame.area());
                // Set the input cursor as needed. Only active when an input box is active
                self.set_cursor(frame);
            })?;

            let timeout = tick_rate.saturating_sub(last_tick.elapsed());
            if event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    self.handle_key(key).await;
                };
            }
            if last_tick.elapsed() >= tick_rate {
                self.on_tick();
                last_tick = Instant::now();
            }
        }
        Ok(self)
    }

    fn on_tick(&mut self) {
        self.time = Local::now();
    }

    async fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        match self.current_focus {
            Windows::Invite => {
                match key.code {
                    KeyCode::F(3) => {
                        // switch back to the previous focus
                        self.current_focus = self.previous_focus.clone();
                    }
                    KeyCode::Esc => {
                        // switch back to the previous focus
                        self.current_focus = self.previous_focus.clone();
                    }
                    _ => {}
                }
                return;
            }
            Windows::Settings => {
                self.settings_keys(key).await;
                return;
            }
            Windows::Channels => match key.code {
                KeyCode::Down => {
                    self.channels.state.select_next();
                }
                KeyCode::Up => {
                    self.channels.state.select_previous();
                }
                KeyCode::Right => self.select_chat_window(),
                _ => {}
            },
            Windows::Chat => match key.code {
                KeyCode::Left => self.select_channel_window(),
                KeyCode::Enter => {}
                _ => {}
            },
            _ => {}
        }

        match key.code {
            KeyCode::F(2) => {
                self.previous_focus = self.current_focus.clone();
                self.current_focus = Windows::Settings;
            }
            KeyCode::F(3) => {
                self.previous_focus = self.current_focus.clone();
                self.current_focus = Windows::Invite;
            }
            KeyCode::F(10) => self.should_exit = true,
            _ => {}
        }
    }

    fn select_chat_window(&mut self) {
        self.current_focus = Windows::Chat;
    }

    fn select_channel_window(&mut self) {
        self.current_focus = Windows::Channels;
    }

    fn set_cursor(&self, frame: &mut Frame) {
        if self.settings_input.active_field == InputType::None {
            // Hide the cursor
            //frame.hide_cursor();
        } else {
            // Make the cursor visible and ask tui-rs to put it at the specified coordinates after rendering
            frame.set_cursor_position(self.settings_input.input_position);
        }
    }
}

impl Widget for &mut App {
    fn render(self, area: Rect, buf: &mut Buffer) {
        use Constraint::{Length, Min};

        let vertical = Layout::vertical([Length(1), Min(0), Length(15), Length(2)]);
        let [top_status, main_area, log_area, bottom_status] = vertical.areas(area);

        let main_horizontal = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(vec![Constraint::Min(20), Constraint::Percentage(75)])
            .split(main_area);

        self.render_top_status(top_status, buf);
        self.render_channels(main_horizontal[0], buf);

        self.render_chat(main_horizontal[1], buf);
        self.render_logs(log_area, buf);
        self.render_bottom_menu(bottom_status, buf);

        // These are optional popups that are overlaid on top of the main UI
        self.render_invite_popup(area, buf);
        self.render_settings_popup(area, buf);
    }
}
