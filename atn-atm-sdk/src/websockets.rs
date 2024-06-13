use http::{header::AUTHORIZATION, HeaderName};
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::client::IntoClientRequest};

use crate::{errors::ATMError, ATM};

impl<'c> ATM<'c> {
    pub async fn connect_websocket(&mut self) -> Result<(), ATMError> {
        // Check if authenticated
        let tokens = self.authenticate().await?;

        let mut request = self
            .config
            .atm_api_ws
            .clone()
            .into_client_request()
            .unwrap();

        let headers = request.headers_mut();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {}", tokens.access_token)
                .parse()
                .map_err(|e| {
                    ATMError::TransportError(format!("Could not set Authorization header: {:?}", e))
                })?,
        );

        let (ws_stream, _) =
            connect_async_tls_with_config(request, None, false, Some(self.ws_connector.clone()))
                .await
                .expect("Failed to connect");

        Ok(())
    }
}
