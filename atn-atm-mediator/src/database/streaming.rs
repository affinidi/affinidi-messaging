use super::DatabaseHandler;
use crate::common::errors::MediatorError;
use redis::{from_redis_value, Value};
use tracing::{event, Level};

impl DatabaseHandler {
    pub async fn clean_start_streaming(&self, uuid: &str) -> Result<(), MediatorError> {
        let mut conn = self.get_connection().await?;

        let response: Vec<Value> = deadpool_redis::redis::pipe()
            .atomic()
            .cmd("FCALL")
            .arg("clean_start_streaming")
            .arg(1)
            .arg(uuid)
            .query_async(&mut conn)
            .await
            .map_err(|err| {
                event!(
                    Level::ERROR,
                    "redis function clean_start_streaming() failed. Reason: {}",
                    err
                );
                MediatorError::DatabaseError(
                    "NA".into(),
                    format!(
                        "redis function clean_start_streaming() failed. Reason: {}",
                        err
                    ),
                )
            })?;

        if let Ok(count) = from_redis_value::<i64>(&response[0]) {
            event!(
                Level::INFO,
                "clean_start_streaming() cleaned {} sessions",
                count
            );
            Ok(())
        } else {
            event!(
                Level::ERROR,
                "clean_start_streaming() failed to parse response: {:?}",
                response
            );
            Err(MediatorError::DatabaseError(
                "NA".into(),
                format!(
                    "redis fn clean_start_streaming() failed. Response ({:?})",
                    response
                ),
            ))
        }
    }
}
