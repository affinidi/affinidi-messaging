use super::handshake;
use crate::errors::ATMError;
use rustls::{
    pki_types::{DnsName, ServerName},
    ClientConfig,
};
use rustls_platform_verifier::ConfigVerifierExt;
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tracing::error;
use url::Url;
use web_socket::WebSocket;

#[derive(Debug)]
pub struct HttpRequest {
    pub prefix: String,
    headers: HashMap<String, String>,
}

impl std::ops::Deref for HttpRequest {
    type Target = HashMap<String, String>;

    fn deref(&self) -> &Self::Target {
        &self.headers
    }
}

impl std::ops::DerefMut for HttpRequest {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.headers
    }
}

impl HttpRequest {
    pub async fn parse<IO>(reader: &mut IO) -> Result<Self, ATMError>
    where
        IO: Unpin + AsyncBufRead,
    {
        let mut lines = reader.lines();

        let Some(prefix) = lines.next_line().await.map_err(|err| {
            ATMError::TransportError(format!("Incorrect response from WebSocket Setup: {}", err))
        })?
        else {
            return Err(ATMError::TransportError(
                "WebSocket Prefix not returned from server".into(),
            ));
        };

        let mut headers = HashMap::new();

        while let Some(line) = lines.next_line().await.map_err(|err| {
            ATMError::TransportError(format!("Incorrect response from WebSocket Setup: {}", err))
        })? {
            if line.is_empty() {
                break;
            }
            let (key, value) = line.split_once(":").unwrap();
            headers.insert(key.to_ascii_lowercase(), value.trim_start().into());
        }
        Ok(Self { prefix, headers })
    }
}

pub async fn connect(
    url: &Url,
    authorization_token: &str,
) -> Result<WebSocket<BufReader<TlsStream<TcpStream>>>, ATMError> {
    let (host, path) = if let Some(host) = url.host() {
        (host.to_string(), url.path().to_string())
    } else {
        error!("Websocket address {}: no valid host found", url);
        return Err(ATMError::TransportError(format!(
            "Websocket address {}: no valid host found",
            url
        )));
    };

    let dns_name = match DnsName::try_from_str(host.as_str()) {
        Ok(dns_name) => dns_name.to_owned(),
        Err(err) => {
            error!("Websocket address {}: invalid host name: {}", url, err);
            return Err(ATMError::TransportError(format!(
                "Websocket address {}: invalid host name: {}",
                url, err
            )));
        }
    };

    let address = match url.socket_addrs(|| None) {
        Ok(mut addrs) => {
            if addrs.is_empty() {
                error!("Websocket address {}: no valid address found", url);
                return Err(ATMError::TransportError(format!(
                    "Websocket address {}: no valid address found",
                    url
                )));
            }
            addrs.remove(0)
        }
        Err(err) => {
            error!("Websocket address {}: invalid address: {}", url, err);
            return Err(ATMError::TransportError(format!(
                "Websocket address {}: invalid address: {}",
                url, err
            )));
        }
    };

    let stream = TcpStream::connect(address).await.map_err(|err| {
        ATMError::TransportError(format!("TcpStream::Connect({}) failed: {}", address, err))
    })?;
    let connector = TlsConnector::from(Arc::new(ClientConfig::with_platform_verifier()));
    let mut tls = BufReader::new(
        connector
            .connect(ServerName::DnsName(dns_name), stream)
            .await
            .map_err(|err| {
                ATMError::TransportError(format!("TlsConnector::connect({}) failed: {}", host, err))
            })?,
    );

    let (req, sec_key) = handshake::request(
        host,
        path,
        [("Authorization", ["Bearer ", authorization_token].concat())],
    );

    tls.write_all(req.as_bytes())
        .await
        .map_err(|err| ATMError::TransportError(format!("websocket handshake failed: {}", err)))?;

    let http = HttpRequest::parse(&mut tls).await?;

    if !http.prefix.starts_with("HTTP/1.1 101 Switching Protocols") {
        return Err(ATMError::TransportError(
            "expected upgrade connection".to_string(),
        ));
    }
    if http
        .get("sec-websocket-accept")
        .expect("couldn't get `sec-websocket-accept` from http response")
        .ne(&handshake::accept_key_from(sec_key))
    {
        return Err(ATMError::TransportError(
            "invalid websocket accept key".to_string(),
        ));
    }

    Ok(WebSocket::client(tls))
}
