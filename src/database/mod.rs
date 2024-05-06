use didcomm::Message;
use redb::Database;
use std::process;
use tokio::sync::mpsc;
use tracing::{event, Level};

use crate::{common::errors::MediatorError, SharedData};

pub enum RecordType {
    Message(MessageRecord),
    Pointer(PointerRecord),
}

pub struct MessageRecord {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub message: String,
}

pub struct PointerRecord {
    pub pointers: Vec<String>,
}

pub async fn run(shared_state: SharedData, mut db_rx: mpsc::Receiver<Message>) {
    event!(Level::INFO, "Database handler thread starting...");

    let db = match open_database(&shared_state.config.database_file) {
        Ok(db) => db,
        Err(err) => {
            event!(Level::ERROR, "Error opening database: {}", err);
            event!(Level::ERROR, "Exiting...");
            process::exit(1);
        }
    };

    event!(Level::INFO, "Database handler thread running...");

    loop {
        let message = db_rx.recv().await;
        if let Some(message) = message {
            let message = message.clone();
        }
    }
}

fn open_database(file_name: &str) -> Result<Database, MediatorError> {
    let mut db = Database::create(file_name).map_err(|err| {
        event!(
            Level::ERROR,
            "Error creating database({}): {}",
            file_name,
            err
        );
        MediatorError::DatabaseError(
            "NA".into(),
            format!("Error creating database({}): {}", file_name, err),
        )
    })?;
    event!(Level::INFO, "Database({}) opened", file_name);

    // When opening, try compacting database first time
    db.compact().map_err(|err| {
        event!(
            Level::ERROR,
            "Error compacting database({}): {}",
            file_name,
            err
        );
        MediatorError::DatabaseError(
            "NA".into(),
            format!("Error compacting database({}): {}", file_name, err),
        )
    })?;

    event!(Level::INFO, "Database compacted successfully...");

    Ok(db)
}
