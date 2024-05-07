use std::env;

use axum::{routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use did_peer::DIDPeer;
use didcomm::Message;
use didcomm_mediator::{
    database,
    handlers::{application_routes, health_checker_handler},
    init,
    resolvers::affinidi_dids::AffinidiDIDResolver,
    SharedData,
};
use http::Method;
use ssi::did::DIDMethods;
use tokio::sync::mpsc;
use tower_http::{
    cors::CorsLayer,
    trace::{self, TraceLayer},
};
use tracing::{event, Level};
use tracing_subscriber::{filter, layer::SubscriberExt, reload, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // setup logging/tracing framework
    let filter = filter::LevelFilter::INFO; // This can be changed in the config file!
    let (filter, reload_handle) = reload::Layer::new(filter);
    let ansi = env::var("LOCAL").is_ok();
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_ansi(ansi))
        .init();

    if ansi {
        event!(
            Level::INFO,
            r#"        db          ad88     ad88  88               88           88  88     88b           d88                       88  88"#
        );
        event!(
            Level::INFO,
            r#"       d88b        d8"      d8"    ""               ""           88  ""     888b         d888                       88  ""                ,d"#
        );
        event!(
            Level::INFO,
            r#"      d8'`8b       88       88                                   88         88`8b       d8'88                       88                    88"#
        );
        event!(
            Level::INFO,
            r#"     d8'  `8b    MM88MMM  MM88MMM  88  8b,dPPYba,   88   ,adPPYb,88  88     88 `8b     d8' 88   ,adPPYba,   ,adPPYb,88  88  ,adPPYYba,  MM88MMM  ,adPPYba,   8b,dPPYba,"#
        );
        event!(
            Level::INFO,
            r#"    d8YaaaaY8b     88       88     88  88P'   `"8a  88  a8"    `Y88  88     88  `8b   d8'  88  a8P_____88  a8"    `Y88  88  ""     `Y8    88    a8"     "8a  88P'   "Y8"#
        );
        event!(
            Level::INFO,
            r#"   d8""""""""8b    88       88     88  88       88  88  8b       88  88     88   `8b d8'   88  8PP"""""""  8b       88  88  ,adPPPPP88    88    8b       d8  88"#
        );
        event!(
            Level::INFO,
            r#"  d8'        `8b   88       88     88  88       88  88  "8a,   ,d88  88     88    `888'    88  "8b,   ,aa  "8a,   ,d88  88  88,    ,88    88,   "8a,   ,a8"  88"#
        );
        event!(
            Level::INFO,
            r#" d8'          `8b  88       88     88  88       88  88   `"8bbdP"Y8  88     88     `8'     88   `"Ybbd8"'   `"8bbdP"Y8  88  `"8bbdP"Y8    "Y888  `"YbbdP"'   88"#
        );
        event!(Level::INFO, "");
    }

    event!(
        Level::INFO,
        "[Loading Affinidi Secure Messaging Mediator configuration]"
    );

    let config = init(Some(reload_handle))
        .await
        .expect("Couldn't initialize mediator!");

    let mut did_method_resolver = DIDMethods::default();
    did_method_resolver.insert(Box::new(DIDPeer));
    let did_resolver = AffinidiDIDResolver::new(vec![config.mediator_did_doc.clone()]);

    // Start setting up the database durability and handling
    // We run all database operations in a seperate thread and use Channels to communicate
    let (db_tx, db_rx) = mpsc::channel::<Message>(1);

    // Create the shared application State
    let shared_state = SharedData {
        config: config.clone(),
        service_start_timestamp: chrono::Utc::now(),
        send_channel: db_tx,
        did_resolver,
    };

    let db_shared_state = shared_state.clone();

    // Start the database thread
    let database_manager = tokio::spawn(async move { database::run(db_shared_state, db_rx).await });

    // build our application with a single route
    let app: Router = application_routes(&shared_state);

    // Add middleware to all routes
    let app = Router::new()
        .merge(app)
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_headers([http::header::CONTENT_TYPE])
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::DELETE,
                    Method::PATCH,
                ]),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        // Add the healthcheck route after the tracing so we don't fill up logs with healthchecks
        .route(
            "/atm/healthchecker",
            get(health_checker_handler).with_state(shared_state),
        );

    if config.use_ssl {
        event!(Level::INFO, "Using SSL/TLS for secure communication.");
        // configure certificate and private key used by https
        let ssl_config =
            RustlsConfig::from_pem_file(config.ssl_certificate_file, config.ssl_key_file)
                .await
                .expect("bad certificate/key");
        axum_server::bind_rustls(config.listen_address.parse().unwrap(), ssl_config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    } else {
        event!(Level::WARN, "**** WARNING: Running without SSL/TLS ****");
        axum_server::bind(config.listen_address.parse().unwrap())
            .serve(app.into_make_service())
            .await
            .unwrap();
    }

    // Doesn't really do anything, will block and stop the app from exiting if the server functions fail
    event!(
        Level::ERROR,
        "Services have failed, we are stuck on database_manager.await!"
    );
    database_manager.await.unwrap();
}
