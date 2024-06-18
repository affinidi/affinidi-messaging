use crate::{errors::ATMError, ATM};
use http::header::AUTHORIZATION;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async_tls_with_config, tungstenite::client::IntoClientRequest, MaybeTlsStream,
    WebSocketStream,
};
use tracing::{debug, span, Instrument, Level};

pub mod sending;

impl<'c> ATM<'c> {
    /// Starts websocket connection to the ATM API
    /// Example:
    /// ```
    /// use atm_sdk::ATM;
    ///
    /// // Configure and create ATM instance
    /// let atm = ATM::new(config).await?;
    ///
    /// // Get a websocket connection (should be mutable as it will be used to send messages)
    /// let mut ws = atm.get_websocket().await?;
    /// ```
    pub async fn start_websocket(
        &mut self,
    ) -> Result<&mut WebSocketStream<MaybeTlsStream<TcpStream>>, ATMError> {
        let _span = span!(Level::DEBUG, "start_websocket");
        async move {
            // Check if authenticated
            let tokens = self.authenticate().await?;

            // Create a custom websocket request, turn this into a client_request
            // Allows adding custom headers later
            let mut request = self
                .config
                .atm_api_ws
                .clone()
                .into_client_request()
                .map_err(|e| {
                    ATMError::TransportError(format!(
                        "Could not create websocket request. Reason: {}",
                        e
                    ))
                })?;

            // Add the Authorization header to the request
            let headers = request.headers_mut();
            headers.insert(
                AUTHORIZATION,
                format!("Bearer {}", tokens.access_token)
                    .parse()
                    .map_err(|e| {
                        ATMError::TransportError(format!(
                            "Could not set Authorization header: {:?}",
                            e
                        ))
                    })?,
            );

            // Connect to the websocket
            let (ws_stream, _) = connect_async_tls_with_config(
                request,
                None,
                false,
                Some(self.ws_connector.clone()),
            )
            .await
            .expect("Failed to connect");

            self.ws_stream = Some(ws_stream);

            Ok(self.ws_stream.as_mut().unwrap())
        }
        .instrument(_span)
        .await
    }

    /// Close the WebSocket connection gracefully
    pub async fn close_websocket(&mut self) -> Result<(), ATMError> {
        if let Some(ws_stream) = self.ws_stream.as_mut() {
            match ws_stream.close(None).await {
                Ok(_) => {}
                Err(e) => {
                    return Err(ATMError::TransportError(format!(
                        "Failed to close websocket connection: {:?}",
                        e
                    )))
                }
            }
        } else {
            debug!("No websocket connection to close");
        }

        self.ws_stream = None;
        Ok(())
    }
}
