use crate::{errors::ATMError, ATM};
use atn_atm_didcomm::Message;
use futures_util::sink::SinkExt;
use http::header::AUTHORIZATION;
use std::collections::HashMap;
use tokio::{
    net::TcpStream,
    select,
    sync::mpsc::{Receiver, Sender},
};
use tokio_stream::StreamExt;
use tokio_tungstenite::{
    connect_async_tls_with_config, tungstenite::client::IntoClientRequest, MaybeTlsStream,
    WebSocketStream,
};
use tracing::{debug, error, info, span, Instrument, Level};

struct FetchTask {
    cache: HashMap<String, Message>,
}

impl<'c> ATM<'c> {
    pub(crate) async fn _create_socket(
        &mut self,
        //atm: &mut ATM<'_>,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, ATMError> {
        // Check if authenticated
        let tokens = self.authenticate().await?;

        debug!("Creating websocket connection");
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
                    ATMError::TransportError(format!("Could not set Authorization header: {:?}", e))
                })?,
        );

        // Connect to the websocket
        let (ws_stream, _) =
            connect_async_tls_with_config(request, None, false, Some(self.ws_connector.clone()))
                .await
                .expect("Failed to connect");

        debug!("Completed websocket connection");

        Ok(ws_stream)
    }

    /// WebSocket streaming handler
    /// from_sdk is an MPSC channel used to receive messages from the main thread that will be sent to the websocket
    /// to_sdk is an MPSC channel used to send messages to the main thread that were received from the websocket
    /// web_socket is the websocket stream itself which can be used to send and receive messages
    pub(crate) async fn ws_handler(
        atm: &mut ATM<'_>,
        from_sdk: &mut Receiver<String>,
        to_sdk: &Sender<String>,
        // web_socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    ) -> Result<(), ATMError> {
        let _span = span!(Level::INFO, "ws_handler");
        async move {
            debug!("Starting websocket handler");
            let mut web_socket = atm._create_socket().await?;
            to_sdk.send("Hello from the websocket handler".to_string()).await.map_err(|err| {
                ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
            })?;
            loop {
                select! {
                    value = web_socket.next() => {
                        if let Some(msg) = value {
                            if let Ok(payload) = msg {
                                info!("Received message: {:?}", payload);
                            } else {
                                error!("Error getting payload from message");
                                continue;
                            }
                        } else {
                            error!("Error getting message");
                            break;
                        }
                    }
                    value = from_sdk.recv() => {
                        if let Some(msg) = value {
                            if msg == "EXIT" {
                                debug!("Received EXIT message, closing channel");
                                break;
                            }
                            debug!("Received message: {}", msg);
                            web_socket.send(msg.into()).await.map_err(|err| {
                                ATMError::TransportError(format!("Could not send websocket message: {:?}", err))
                            })?;
                        } else {
                            info!("Channel Closed");
                            break;
                        }
                    }
                }
            }

            let _ = web_socket.close(None).await;
            from_sdk.close();

            debug!("Channel closed, stopping websocket handler");
            Ok(())
        }
        .instrument(_span)
        .await
    }
}
