use crate::{
    database::DatabaseHandler,
    handlers::{application_routes, health_checker_handler},
    init,
    tasks::statistics::statistics,
    tasks::websocket_streaming::StreamingTask,
    SharedData,
};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use axum::{routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use http::Method;
use std::{env, net::SocketAddr};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::{self, TraceLayer};
use tracing::{event, Level};
use tracing_subscriber::{filter, layer::SubscriberExt, reload, util::SubscriberInitExt};

pub async fn start() {
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

    // Start setting up the database durability and handling
    let database = match DatabaseHandler::new(&config).await {
        Ok(db) => db,
        Err(err) => {
            event!(Level::ERROR, "Error opening database: {}", err);
            event!(Level::ERROR, "Exiting...");
            std::process::exit(1);
        }
    };

    // Start the statistics thread
    let _stats_database = database.clone(); // Clone the database handler for the statistics thread
    tokio::spawn(async move {
        statistics(_stats_database)
            .await
            .expect("Error starting statistics thread");
    });

    // Start the streaming thread if enabled
    let (streaming_task, _) = if config.streaming_enabled {
        let _database = database.clone(); // Clone the database handler for the subscriber thread
        let uuid = config.streaming_uuid.clone();
        let (_task, _handle) = StreamingTask::new(_database.clone(), &uuid)
            .await
            .expect("Error starting streaming task");
        (Some(_task), Some(_handle))
    } else {
        (None, None)
    };

    // Create the DID Resolver
    let did_resolver = DIDCacheClient::new(config.did_resolver_config.clone())
        .await
        .unwrap();

    // Create the shared application State
    let shared_state = SharedData {
        config: config.clone(),
        service_start_timestamp: chrono::Utc::now(),
        did_resolver,
        database,
        streaming_task,
    };

    // build our application routes
    let app: Router = application_routes(&config.api_prefix, &shared_state);

    // Add middleware to all routes
    let app = Router::new()
        .merge(app)
        .layer(
            config
                .cors_allow_origin
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
        .layer(RequestBodyLimitLayer::new(config.http_size_limit as usize))
        // Add the healthcheck route after the tracing so we don't fill up logs with healthchecks
        .route(
            format!("{}healthchecker", &config.api_prefix).as_str(),
            get(health_checker_handler).with_state(shared_state),
        );

    if config.use_ssl {
        event!(
            Level::INFO,
            "This mediator is using SSL/TLS for secure communication."
        );
        // configure certificate and private key used by https
        // TODO: Build a proper TLS Config
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ssl_config =
            RustlsConfig::from_pem_file(config.ssl_certificate_file, config.ssl_key_file)
                .await
                .expect("bad certificate/key");

        axum_server::bind_rustls(config.listen_address.parse().unwrap(), ssl_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    } else {
        event!(Level::WARN, "**** WARNING: Running without SSL/TLS ****");
        axum_server::bind(config.listen_address.parse().unwrap())
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    }
}
