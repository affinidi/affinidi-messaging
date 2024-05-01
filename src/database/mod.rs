use redb::{Database, TableDefinition};
use tracing::{event, Level};

use crate::common::errors::MediatorError;

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

pub fn open_database(file_name: &str) -> Result<Database, MediatorError> {
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
