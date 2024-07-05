use crate::{config::Config, errors::ATMError, ATM};
use did_peer::DIDPeer;
use ssi::did::DIDMethods;
use tokio::sync::mpsc;

pub mod sending;
pub mod ws_handler;

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
    pub async fn start_websocket(&mut self) -> Result<(), ATMError> {
        // Some hackery to get around the Rust lifetimes by various items in the SDK
        // Create a copy of ATM with owned values
        let mut config = Config {
            ssl_certificates: Vec::new(),
            ..self.config.clone()
        };

        for cert in &self.config.ssl_certificates {
            config.ssl_certificates.push(cert.clone().into_owned())
        }

        let mut atm = ATM {
            config,
            did_methods_resolver: DIDMethods::default(),
            did_resolver: self.did_resolver.clone(),
            secrets_resolver: self.secrets_resolver.clone(),
            client: self.client.clone(),
            authenticated: self.authenticated,
            jwt_tokens: self.jwt_tokens.clone(),
            ws_connector: self.ws_connector.clone(),
            ws_enabled: self.ws_enabled,
            ws_handler: None,
            ws_send_stream: None,
            ws_websocket: None,
        };

        // TODO: This is another dirty hack, there doesn't seem to be a nice way to add traits dynamically
        atm.add_did_method(Box::new(DIDPeer));

        // Create a new channel with a capacity of at most 32.
        let (tx, mut rx) = mpsc::channel::<String>(32);

        self.ws_send_stream = Some(tx);

        // Start the websocket connection
        let mut web_socket = self._create_socket(&mut atm).await?;
        self.ws_websocket = Some(self._create_socket(&mut atm).await?);

        self.ws_handler = Some(tokio::spawn(async move {
            let _ = ATM::ws_handler(&mut atm, &mut rx, &mut web_socket).await;
        }));

        Ok(())
    }

    /// Close the WebSocket connection gracefully
    pub async fn abort_websocket(&mut self) -> Result<(), ATMError> {
        // Close the websocket connection

        if let Some(websocket) = self.ws_websocket.as_mut() {
            let _ = websocket.close(None).await;
        }

        // Abort the fetch task if running
        //if let Some(ws_handler) = &self.ws_handler {
        //     ws_handler.abort();
        // }
        /*
        if let Some(ws_stream) = self.ws_stream.as_mut() {
            match ws_stream.write().await.close(None).await {
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

        // Abort the fetch task if running
        if let Some(fetch_task) = &self.fetch_task_handle {
            fetch_task.abort();
        }*/

        Ok(())
    }
}
