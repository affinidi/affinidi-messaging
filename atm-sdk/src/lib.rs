use config::Config;
use didcomm::did::DIDDoc;
use didcomm::did::DIDResolver as DidcommDIDResolver;
use didcomm::secrets::Secret;
use errors::ATMError;
use reqwest::Client;
use resolvers::did_resolver::AffinidiDIDResolver;
use resolvers::secrets_resolver::AffinidiSecrets;
use ssi::did::{DIDMethod, DIDMethods};
use ssi::did_resolve::DIDResolver as SSIDIDResolver;
use tracing::debug;
use tracing::span;

pub mod config;
pub mod conversions;
pub mod errors;
pub mod messages;
mod resolvers;

pub struct ATM<'c> {
    pub(crate) config: Config,
    did_methods_resolver: DIDMethods<'c>,
    did_resolver: AffinidiDIDResolver,
    secrets_resolver: AffinidiSecrets,
    client: Client,
}

/// Affinidi Trusted Messaging SDK
/// This is the top level struct for the SSK
///
/// Example:
/// ```
/// use atm_sdk::ATM;
///
/// let config = Config::builder().build();
/// let mut atm = ATM::new(config);
///
/// // Add the DID:Peer method
/// atm.add_did_method(Box::new(DIDPeer));
///
/// let response = atm.ping("did:example:123", true);
/// ```
impl<'c> ATM<'c> {
    /// Creates a new instance of the SDK with a given configuration
    /// You need to add at least the DID Method for the SDK DID to work
    pub async fn new(
        config: Config,
        did_methods: Vec<Box<dyn DIDMethod>>,
    ) -> Result<ATM<'c>, ATMError> {
        // Set a process wide default crypto provider.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let mut client = reqwest::ClientBuilder::new()
            .use_rustls_tls()
            .https_only(true)
            .user_agent("Affinidi Trusted Messaging");

        for cert in config.get_ssl_certificates() {
            client = client.add_root_certificate(cert.to_owned());
        }

        let client = match client.build() {
            Ok(client) => client,
            Err(e) => {
                return Err(ATMError::HTTPSError(format!(
                    "Couldn't create HTTPS Client. Reason: {}",
                    e
                )))
            }
        };

        let mut atm = ATM {
            config: config.clone(),
            did_methods_resolver: DIDMethods::default(),
            did_resolver: AffinidiDIDResolver::new(vec![]),
            secrets_resolver: AffinidiSecrets::new(vec![]),
            client,
        };

        for method in did_methods {
            atm.add_did_method(method);
        }
        // Add our own DID to the DID_RESOLVER
        atm.add_did(&config.my_did).await?;

        Ok(atm)
    }

    /// Adds a DID Method that the resolvers can work with
    /// NOTE: DIDMethod is a trait from the `ssi` crate
    /// NOTE: As a result we add them after the initial creation of the ATM
    ///       So that we get around silly Rust borrowing rules on dyn traits
    ///
    /// Example:
    /// ```
    /// atm.add_did_method(Box::new(DIDPeer));
    /// ```
    pub fn add_did_method(&mut self, did_method: Box<dyn DIDMethod>) -> &Self {
        self.did_methods_resolver.insert(did_method);
        self
    }

    /// Adds a DID to the resolver
    /// This resolves the DID to the DID Document, and adds it to the list of known DIDs
    /// Returns the DIDDoc itself if successful, or an SDK Error
    pub async fn add_did(&mut self, did: &str) -> Result<DIDDoc, ATMError> {
        let _span = span!(tracing::Level::DEBUG, "add_did", did = did).entered();
        debug!("Adding DID to resolver");
        let (res_meta, doc_opt, _) = self
            .did_methods_resolver
            .resolve(did, &Default::default())
            .await;

        let doc = if let Some(doc) = doc_opt {
            doc
        } else {
            debug!("Couldn't resolve DID, returning error");
            return Err(ATMError::DIDError(format!(
                "Could not resolve DID ({}). Reason: {}",
                did,
                res_meta.error.unwrap_or("Unknown".to_string())
            )));
        };

        let doc = conversions::convert_did_format(&doc).await?;
        self.did_resolver.insert(&doc);
        debug!("Successfully added DID to resolver");

        Ok(doc)
    }

    /// Adds required secrets to the secrets resolver
    /// You need to add the private keys of the DIDs you want to sign and encrypt messages with
    pub fn add_secret(&mut self, secret: Secret) {
        self.secrets_resolver.insert(secret);
    }
}
