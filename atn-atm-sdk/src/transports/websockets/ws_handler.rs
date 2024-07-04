use crate::{errors::ATMError, ATM};
use atn_atm_didcomm::Message;
use futures_util::sink::SinkExt;
use http::header::AUTHORIZATION;
use std::collections::HashMap;
use tokio::{net::TcpStream, select, sync::mpsc::Receiver};
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
        &self,
        atm: &mut ATM<'_>,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, ATMError> {
        // Check if authenticated
        let tokens = atm.authenticate().await?;

        // Create a custom websocket request, turn this into a client_request
        // Allows adding custom headers later
        let mut request = atm
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
            connect_async_tls_with_config(request, None, false, Some(atm.ws_connector.clone()))
                .await
                .expect("Failed to connect");

        Ok(ws_stream)
    }

    /// WebSocket streaming handler
    /// recv is an MPSC channel used to receive messages from the main thread that will be sent to the websocket
    /// web_socket is the websocket stream itself which can be used to send and receive messages
    pub(crate) async fn ws_handler(
        atm: &mut ATM<'_>,
        recv: &mut Receiver<String>,
        web_socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    ) -> Result<(), ATMError> {
        let _span = span!(Level::INFO, "ws_handler");
        async move {
            debug!("Starting websocket handler");
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
                    value = recv.recv() => {
                        if let Some(msg) = value {
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
            recv.close();

            error!("Channel closed, stopping websocket handler");
            Ok(())
        }
        .instrument(_span)
        .await
    }
}
