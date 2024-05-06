use http::Uri;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use rustls::{ClientConfig, RootCertStore};
use std::{
    fs,
    io::{self},
    str::FromStr,
};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Set a process wide default crypto provider.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let tls = load_certs().unwrap();

    // Prepare the HTTPS connector
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();

    // Build the hyper client from the HTTPS connector.
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
    let url = Uri::from_str("https://localhost:7037/").map_err(|e| error(format!("{}", e)))?;

    // Prepare a chain of futures which sends a GET request, inspects
    // the returned headers, collects the whole body and prints it to
    // stdout.
    let fut = async move {
        let res = client
            .get(url)
            .await
            .map_err(|e| error(format!("Could not get: {:?}", e)))?;
        println!("Status:\n{}", res.status());
        println!("Headers:\n{:#?}", res.headers());

        let body = res
            .into_body()
            .collect()
            .await
            .map_err(|e| error(format!("Could not get body: {:?}", e)))?
            .to_bytes();
        println!("Body:\n{}", String::from_utf8_lossy(&body));

        Ok(())
    };

    fut.await
}

fn load_certs() -> io::Result<ClientConfig> {
    let f = fs::File::open("conf/keys/client.chain").map_err(|e| {
        error(format!(
            "failed to open {}: {}",
            "conf/keys/client.chain", e
        ))
    })?;
    let rd = &mut io::BufReader::new(f);
    let certs = rustls_pemfile::certs(rd).collect::<Result<Vec<_>, _>>()?;
    let mut roots = RootCertStore::empty();
    let a = roots.add_parsable_certificates(certs);
    println!("Added {:?} certs to the store", a);
    // TLS client config using the custom CA store for lookups
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}
