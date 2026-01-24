//! VLESS inbound listener
//!
//! This module provides the main VLESS inbound listener that accepts connections
//! from VLESS clients. It supports plain TCP, TLS, and REALITY modes, with optional
//! fallback for non-VLESS connections.
//!
//! # Architecture
//!
//! ```text
//! Client Connection
//!        |
//!        v
//! +------------------+
//! | TCP Accept       |
//! +------------------+
//!        |
//!        v
//! +------------------+
//! | REALITY/TLS      | (optional)
//! | Handshake        |
//! +------------------+
//!        |
//!        v (if valid)
//! +------------------+
//! | VLESS Handler    |
//! | - Read header    |
//! | - Validate UUID  |
//! | - Send response  |
//! +------------------+
//!        |
//!        v
//! +------------------+
//! | Authenticated    |
//! | VlessConnection  |
//! +------------------+
//!
//! If REALITY validation fails, connection is
//! transparently proxied to fallback destination.
//! ```
//!
//! # Example
//!
//! ```no_run
//! use rust_router::vless_inbound::{VlessInboundListener, VlessInboundConfig, VlessUser};
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = VlessInboundConfig::new("0.0.0.0:443".parse()?)
//!     .with_user(VlessUser::new(
//!         "550e8400-e29b-41d4-a716-446655440000",
//!         Some("admin"),
//!     ));
//!
//! let listener = VlessInboundListener::new(config).await?;
//!
//! loop {
//!     let conn = listener.accept().await?;
//!     tokio::spawn(async move {
//!         // Handle the authenticated connection
//!         println!("Connection from {} to {}",
//!             conn.client_addr(),
//!             conn.destination());
//!     });
//! }
//! # }
//! ```

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{debug, error, info, trace, warn};

use super::config::VlessInboundConfig;
use super::error::{VlessInboundError, VlessInboundResult};
use super::handler::{VlessConnection, VlessConnectionHandler};
use crate::reality::{
    RealityAcceptResult, RealityHandshakeResult, RealityServer, RealityServerStream,
};

#[cfg(feature = "transport-tls")]
use {
    super::config::InboundTlsConfig,
    rustls::pki_types::{CertificateDer, PrivateKeyDer},
    rustls::ServerConfig,
    std::fs::File,
    std::io::{BufReader, Seek},
    std::sync::OnceLock,
    tokio_rustls::TlsAcceptor,
};

/// Unified stream type for VLESS inbound connections
///
/// This enum allows `accept_auto()` to return a single type regardless of
/// whether the connection uses plain TCP or REALITY-encrypted transport.
pub enum VlessInboundStream {
    /// Plain TCP stream
    Tcp(TcpStream),
    /// REALITY-encrypted stream (TLS 1.3 with REALITY authentication)
    Reality(RealityServerStream<TcpStream>),
}

impl AsyncRead for VlessInboundStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            VlessInboundStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            VlessInboundStream::Reality(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for VlessInboundStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            VlessInboundStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            VlessInboundStream::Reality(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            VlessInboundStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            VlessInboundStream::Reality(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            VlessInboundStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            VlessInboundStream::Reality(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl std::fmt::Debug for VlessInboundStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VlessInboundStream::Tcp(_) => write!(f, "VlessInboundStream::Tcp"),
            VlessInboundStream::Reality(_) => write!(f, "VlessInboundStream::Reality"),
        }
    }
}

/// VLESS inbound listener
///
/// This listener accepts incoming connections from VLESS clients, performs
/// authentication, and returns authenticated connections for forwarding.
///
/// # Transport Modes
///
/// The listener supports three transport modes:
///
/// 1. **Plain TCP**: No encryption, VLESS header sent in plaintext (not recommended)
/// 2. **TLS**: Standard TLS 1.2/1.3 encryption using rustls
/// 3. **REALITY**: TLS 1.3 camouflage with transparent fallback
///
/// When REALITY is enabled, the listener validates incoming ClientHello messages
/// against the configured authentication parameters. Valid connections proceed
/// to VLESS protocol handling, while invalid connections are transparently
/// proxied to the fallback destination.
pub struct VlessInboundListener {
    /// TCP listener
    tcp_listener: TcpListener,

    /// TLS acceptor (if TLS is enabled)
    #[cfg(feature = "transport-tls")]
    tls_acceptor: Option<TlsAcceptor>,

    /// REALITY server (if REALITY is enabled)
    reality_server: Option<RealityServer>,

    /// Connection handler
    handler: Arc<VlessConnectionHandler>,

    /// Configuration
    config: VlessInboundConfig,

    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,

    /// Whether the listener is active
    active: bool,
}

impl VlessInboundListener {
    /// Create a new VLESS inbound listener
    ///
    /// # Arguments
    ///
    /// * `config` - Listener configuration
    ///
    /// # Errors
    ///
    /// Returns `VlessInboundError` if:
    /// - Configuration validation fails
    /// - Binding to the listen address fails
    /// - TLS configuration fails
    pub async fn new(config: VlessInboundConfig) -> VlessInboundResult<Self> {
        // Validate configuration
        config.validate()?;

        info!(
            listen = %config.listen,
            tls = config.has_tls(),
            reality = config.has_reality(),
            users = config.users.len(),
            fallback = ?config.fallback,
            "Creating VLESS inbound listener"
        );

        // Bind TCP listener
        let tcp_listener = TcpListener::bind(config.listen)
            .await
            .map_err(|e| VlessInboundError::bind_failed(config.listen, e.to_string()))?;

        // Create REALITY server if configured
        let reality_server = if config.has_reality() {
            let server = config.build_reality_server()?;
            info!(
                dest = %server.config().dest,
                short_ids = server.config().short_ids.len(),
                server_names = ?server.config().server_names,
                "REALITY server enabled"
            );
            Some(server)
        } else {
            None
        };

        // Create TLS acceptor if configured (only when REALITY is not enabled)
        #[cfg(feature = "transport-tls")]
        let tls_acceptor = if config.has_tls() {
            // has_tls() already checks that REALITY is not enabled
            Some(Self::create_tls_acceptor(config.tls.as_ref().unwrap())?)
        } else {
            None
        };

        // Build account manager and handler
        let account_manager = config.build_account_manager()?;
        let handler = Arc::new(VlessConnectionHandler::new(
            account_manager,
            config.users.clone(),
        ));

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel(1);

        info!(
            listen = %config.listen,
            "VLESS inbound listener ready"
        );

        Ok(Self {
            tcp_listener,
            #[cfg(feature = "transport-tls")]
            tls_acceptor,
            reality_server,
            handler,
            config,
            shutdown_tx,
            active: true,
        })
    }

    /// Create a TLS acceptor from configuration
    #[cfg(feature = "transport-tls")]
    fn create_tls_acceptor(tls_config: &InboundTlsConfig) -> VlessInboundResult<TlsAcceptor> {
        // Initialize crypto provider (only once)
        static CRYPTO_INIT: OnceLock<()> = OnceLock::new();
        CRYPTO_INIT.get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        // Load certificates
        let cert_file = File::open(&tls_config.cert_path).map_err(|e| {
            VlessInboundError::certificate_load(&tls_config.cert_path, e.to_string())
        })?;

        let mut cert_reader = BufReader::new(cert_file);
        let mut certs: Vec<CertificateDer<'static>> = Vec::new();
        for cert_result in rustls_pemfile::certs(&mut cert_reader) {
            match cert_result {
                Ok(cert) => certs.push(cert),
                Err(e) => {
                    return Err(VlessInboundError::certificate_load(
                        &tls_config.cert_path,
                        format!("failed to parse certificate: {}", e),
                    ));
                }
            }
        }

        if certs.is_empty() {
            return Err(VlessInboundError::certificate_load(
                &tls_config.cert_path,
                "no certificates found",
            ));
        }

        // Load private key
        let key_file = File::open(&tls_config.key_path).map_err(|e| {
            VlessInboundError::private_key_load(&tls_config.key_path, e.to_string())
        })?;

        let mut key_reader = BufReader::new(key_file);
        let key = Self::load_private_key(&mut key_reader, &tls_config.key_path)?;

        // Build server config
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| VlessInboundError::tls_config(e.to_string()))?;

        // Set ALPN protocols if specified
        if !tls_config.alpn.is_empty() {
            server_config.alpn_protocols = tls_config
                .alpn
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect();
        }

        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }

    /// Load a private key from PEM file
    #[cfg(feature = "transport-tls")]
    fn load_private_key(
        reader: &mut BufReader<File>,
        path: &str,
    ) -> VlessInboundResult<PrivateKeyDer<'static>> {

        // Try PKCS#8 first
        for key_result in rustls_pemfile::pkcs8_private_keys(reader) {
            if let Ok(key) = key_result {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
        }

        // Rewind and try RSA
        if reader.get_mut().seek(std::io::SeekFrom::Start(0)).is_ok() {
            for key_result in rustls_pemfile::rsa_private_keys(reader) {
                if let Ok(key) = key_result {
                    return Ok(PrivateKeyDer::Pkcs1(key));
                }
            }
        }

        // Rewind and try EC
        if reader.get_mut().seek(std::io::SeekFrom::Start(0)).is_ok() {
            for key_result in rustls_pemfile::ec_private_keys(reader) {
                if let Ok(key) = key_result {
                    return Ok(PrivateKeyDer::Sec1(key));
                }
            }
        }

        Err(VlessInboundError::private_key_load(
            path,
            "no valid private key found",
        ))
    }

    /// Accept a new VLESS connection
    ///
    /// This method waits for a new connection, performs TLS handshake (if enabled),
    /// validates the VLESS header, and returns an authenticated connection.
    ///
    /// # Errors
    ///
    /// Returns `VlessInboundError` if:
    /// - Listener is not active
    /// - TCP accept fails
    /// - TLS handshake fails
    /// - VLESS authentication fails
    pub async fn accept(&self) -> VlessInboundResult<VlessConnection<TcpStream>> {
        if !self.active {
            return Err(VlessInboundError::NotActive);
        }

        loop {
            // Accept TCP connection
            let (tcp_stream, client_addr) = self
                .tcp_listener
                .accept()
                .await
                .map_err(|e| VlessInboundError::accept(e.to_string()))?;

            trace!(client = %client_addr, "Accepted TCP connection");

            // Handle the connection
            match self.handle_connection(tcp_stream, client_addr).await {
                Ok(Some(conn)) => return Ok(conn),
                Ok(None) => {
                    // Connection was handled (e.g., forwarded to fallback)
                    continue;
                }
                Err(e) => {
                    if e.is_recoverable() {
                        warn!(client = %client_addr, error = %e, "Recoverable error, continuing");
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Accept a new VLESS connection with TLS
    ///
    /// This is similar to `accept()` but returns the TLS stream type.
    #[cfg(feature = "transport-tls")]
    pub async fn accept_tls(
        &self,
    ) -> VlessInboundResult<VlessConnection<tokio_rustls::server::TlsStream<TcpStream>>> {
        if !self.active {
            return Err(VlessInboundError::NotActive);
        }

        let tls_acceptor = self
            .tls_acceptor
            .as_ref()
            .ok_or_else(|| VlessInboundError::tls_config("TLS not configured"))?;

        loop {
            // Accept TCP connection
            let (tcp_stream, client_addr) = self
                .tcp_listener
                .accept()
                .await
                .map_err(|e| VlessInboundError::accept(e.to_string()))?;

            trace!(client = %client_addr, "Accepted TCP connection");

            // Perform TLS handshake
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    warn!(client = %client_addr, error = %e, "TLS handshake failed");
                    continue;
                }
            };

            debug!(client = %client_addr, "TLS handshake completed");

            // Handle VLESS authentication
            match self.handler.handle(tls_stream, client_addr).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    if e.is_recoverable() {
                        warn!(client = %client_addr, error = %e, "Recoverable error, continuing");
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Handle a single TCP connection (without TLS for now)
    async fn handle_connection(
        &self,
        tcp_stream: TcpStream,
        client_addr: SocketAddr,
    ) -> VlessInboundResult<Option<VlessConnection<TcpStream>>> {
        // Handle VLESS authentication directly (no TLS)
        // For TLS, use accept_tls() instead
        // For REALITY, use accept_reality() instead
        match self.handler.handle(tcp_stream, client_addr).await {
            Ok(conn) => Ok(Some(conn)),
            Err(VlessInboundError::AuthenticationFailed) if self.config.fallback.is_some() => {
                // Forward to fallback (would need to buffer the initial bytes)
                debug!(
                    client = %client_addr,
                    fallback = ?self.config.fallback,
                    "Would forward to fallback (not implemented)"
                );
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Accept a new VLESS connection with REALITY
    ///
    /// This method accepts connections with REALITY protocol validation.
    /// Valid REALITY clients proceed with VLESS authentication, while
    /// invalid clients are transparently proxied to the fallback destination.
    ///
    /// # Returns
    ///
    /// Returns `Some(VlessConnection)` for authenticated VLESS clients,
    /// or `None` if the connection was proxied to fallback (REALITY validation failed).
    ///
    /// # Errors
    ///
    /// Returns error if REALITY is not configured, bind/accept fails, or
    /// VLESS authentication fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::vless_inbound::{
    ///     VlessInboundListener, VlessInboundConfig, VlessUser, InboundRealityConfig
    /// };
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = VlessInboundConfig::new("0.0.0.0:443".parse()?)
    ///     .with_user(VlessUser::new(
    ///         "550e8400-e29b-41d4-a716-446655440000",
    ///         Some("admin"),
    ///     ))
    ///     .with_reality(
    ///         InboundRealityConfig::new(
    ///             "base64_private_key",
    ///             "www.google.com:443"
    ///         )
    ///         .with_short_id("1234567890abcdef")
    ///         .with_server_name("www.google.com")
    ///     );
    ///
    /// let listener = VlessInboundListener::new(config).await?;
    ///
    /// loop {
    ///     match listener.accept_reality().await? {
    ///         Some(conn) => {
    ///             println!("Authenticated connection to {}", conn.destination());
    ///         }
    ///         None => {
    ///             // Connection was proxied to fallback
    ///         }
    ///     }
    /// }
    /// # }
    /// ```
    pub async fn accept_reality(
        &self,
    ) -> VlessInboundResult<Option<VlessConnection<RealityServerStream<TcpStream>>>> {
        if !self.active {
            return Err(VlessInboundError::NotActive);
        }

        let reality_server = self
            .reality_server
            .as_ref()
            .ok_or_else(|| VlessInboundError::invalid_config("REALITY not configured"))?;

        loop {
            // Accept TCP connection
            let (tcp_stream, client_addr) = self
                .tcp_listener
                .accept()
                .await
                .map_err(|e| VlessInboundError::accept(e.to_string()))?;

            trace!(client = %client_addr, "Accepted TCP connection (REALITY mode)");

            // Perform REALITY validation with complete TLS 1.3 handshake
            match reality_server.accept_with_handshake(tcp_stream).await {
                Ok(RealityHandshakeResult::Authenticated { stream, short_id }) => {
                    debug!(
                        client = %client_addr,
                        short_id = ?short_id,
                        "REALITY authentication and TLS handshake successful"
                    );

                    // Now handle VLESS authentication on the encrypted stream
                    match self.handler.handle(stream, client_addr).await {
                        Ok(conn) => return Ok(Some(conn)),
                        Err(e) => {
                            if e.is_recoverable() {
                                warn!(
                                    client = %client_addr,
                                    error = %e,
                                    "Recoverable VLESS error after REALITY, continuing"
                                );
                                continue;
                            }
                            return Err(e);
                        }
                    }
                }
                Ok(RealityHandshakeResult::Fallback) => {
                    // Connection was proxied to fallback
                    debug!(
                        client = %client_addr,
                        "REALITY authentication failed, proxied to fallback"
                    );
                    // Continue accepting new connections
                    continue;
                }
                Err(e) => {
                    warn!(
                        client = %client_addr,
                        error = %e,
                        "REALITY accept/handshake error"
                    );
                    // Continue accepting new connections
                    continue;
                }
            }
        }
    }

    /// Accept a connection using the configured transport mode
    ///
    /// This method automatically selects the appropriate accept method based on
    /// the configuration:
    /// - REALITY mode: Uses REALITY protocol validation with TLS 1.3 handshake
    /// - TLS mode: Uses standard TLS handshake
    /// - Plain mode: Direct VLESS protocol
    ///
    /// # Returns
    ///
    /// Returns `Some(VlessConnection)` for authenticated clients, or `None` if
    /// the connection was handled (e.g., proxied to fallback in REALITY mode).
    ///
    /// The returned stream is a unified `VlessInboundStream` that can be either
    /// plain TCP or REALITY-encrypted, allowing callers to handle both cases uniformly.
    pub async fn accept_auto(&self) -> VlessInboundResult<Option<VlessConnection<VlessInboundStream>>> {
        if !self.active {
            return Err(VlessInboundError::NotActive);
        }

        if let Some(reality_server) = &self.reality_server {
            // REALITY mode: Complete TLS 1.3 handshake then VLESS auth
            loop {
                // Accept TCP connection
                let (tcp_stream, client_addr) = self
                    .tcp_listener
                    .accept()
                    .await
                    .map_err(|e| VlessInboundError::accept(e.to_string()))?;

                trace!(client = %client_addr, "Accepted TCP connection (REALITY mode)");

                // Perform REALITY validation with complete TLS 1.3 handshake
                match reality_server.accept_with_handshake(tcp_stream).await {
                    Ok(RealityHandshakeResult::Authenticated { stream, short_id }) => {
                        debug!(
                            client = %client_addr,
                            short_id = ?short_id,
                            "REALITY authentication and TLS handshake successful"
                        );

                        // Wrap in unified stream type
                        let unified_stream = VlessInboundStream::Reality(stream);

                        // Handle VLESS authentication on the encrypted stream
                        match self.handler.handle(unified_stream, client_addr).await {
                            Ok(conn) => return Ok(Some(conn)),
                            Err(e) => {
                                if e.is_recoverable() {
                                    warn!(
                                        client = %client_addr,
                                        error = %e,
                                        "Recoverable VLESS error after REALITY, continuing"
                                    );
                                    continue;
                                }
                                return Err(e);
                            }
                        }
                    }
                    Ok(RealityHandshakeResult::Fallback) => {
                        debug!(
                            client = %client_addr,
                            "REALITY authentication failed, proxied to fallback"
                        );
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            client = %client_addr,
                            error = %e,
                            "REALITY accept/handshake error"
                        );
                        continue;
                    }
                }
            }
        } else {
            // Plain TCP mode
            let (tcp_stream, client_addr) = self
                .tcp_listener
                .accept()
                .await
                .map_err(|e| VlessInboundError::accept(e.to_string()))?;

            trace!(client = %client_addr, "Accepted TCP connection");

            // Wrap in unified stream type
            let unified_stream = VlessInboundStream::Tcp(tcp_stream);

            // Handle VLESS authentication
            self.handler.handle(unified_stream, client_addr).await.map(Some)
        }
    }

    /// Check if REALITY is enabled
    #[must_use]
    pub fn has_reality(&self) -> bool {
        self.reality_server.is_some()
    }

    /// Run the listener with a connection handler callback
    ///
    /// This method runs the listener in a loop, accepting connections and
    /// calling the provided handler for each authenticated connection.
    ///
    /// # Arguments
    ///
    /// * `handler` - Callback function for authenticated connections
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_router::vless_inbound::{VlessInboundListener, VlessInboundConfig, VlessUser};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = VlessInboundConfig::new("0.0.0.0:443".parse()?)
    /// #     .with_user(VlessUser::new("550e8400-e29b-41d4-a716-446655440000", Some("admin")));
    /// let listener = VlessInboundListener::new(config).await?;
    ///
    /// listener.run(|conn| async move {
    ///     println!("Connection to {}", conn.destination());
    ///     Ok(())
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run<F, Fut>(&self, handler: F) -> VlessInboundResult<()>
    where
        F: Fn(VlessConnection<TcpStream>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = VlessInboundResult<()>> + Send,
    {
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = self.accept() => {
                    match result {
                        Ok(conn) => {
                            if let Err(e) = handler(conn).await {
                                error!(error = %e, "Connection handler error");
                            }
                        }
                        Err(e) if e.is_recoverable() => {
                            warn!(error = %e, "Recoverable error in accept loop");
                        }
                        Err(e) => {
                            error!(error = %e, "Fatal error in accept loop");
                            return Err(e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("VLESS listener shutdown signal received");
                    return Ok(());
                }
            }
        }
    }

    /// Graceful shutdown
    ///
    /// Signals the listener to stop accepting new connections.
    pub fn shutdown(&self) {
        info!(listen = %self.config.listen, "Shutting down VLESS listener");
        let _ = self.shutdown_tx.send(());
    }

    /// Get the listen address
    #[must_use]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen
    }

    /// Get the local address (may differ from listen if bound to 0.0.0.0)
    pub fn local_addr(&self) -> VlessInboundResult<SocketAddr> {
        self.tcp_listener
            .local_addr()
            .map_err(|e| VlessInboundError::Io(e))
    }

    /// Check if TLS is enabled
    #[must_use]
    pub fn has_tls(&self) -> bool {
        #[cfg(feature = "transport-tls")]
        {
            self.tls_acceptor.is_some()
        }
        #[cfg(not(feature = "transport-tls"))]
        {
            false
        }
    }

    /// Check if the listener is active
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the number of registered users
    #[must_use]
    pub fn user_count(&self) -> usize {
        self.handler.user_count()
    }

    /// Check if UDP support is enabled
    #[must_use]
    pub fn is_udp_enabled(&self) -> bool {
        self.config.is_udp_enabled()
    }

    /// Subscribe to shutdown signal
    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }
}

impl std::fmt::Debug for VlessInboundListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessInboundListener")
            .field("listen", &self.config.listen)
            .field("active", &self.active)
            .field("has_tls", &self.has_tls())
            .field("user_count", &self.handler.user_count())
            .field("fallback", &self.config.fallback)
            .finish()
    }
}

/// Statistics for the VLESS inbound listener
#[derive(Debug, Clone, Default)]
pub struct VlessInboundStats {
    /// Total connections accepted
    pub connections_accepted: u64,

    /// Total connections authenticated
    pub connections_authenticated: u64,

    /// Total authentication failures
    pub auth_failures: u64,

    /// Total TLS handshake failures
    pub tls_failures: u64,

    /// Total protocol errors
    pub protocol_errors: u64,

    /// Currently active connections
    pub active_connections: u64,
}

impl VlessInboundStats {
    /// Create new empty stats
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless_inbound::VlessUser;

    #[tokio::test]
    async fn test_listener_creation() {
        // Use a random port to avoid conflicts
        let config = VlessInboundConfig::new("127.0.0.1:0".parse().unwrap()).with_user(
            VlessUser::new("550e8400-e29b-41d4-a716-446655440000", Some("test")),
        );

        let listener = VlessInboundListener::new(config).await;
        assert!(listener.is_ok());

        let listener = listener.unwrap();
        assert!(listener.is_active());
        assert_eq!(listener.user_count(), 1);
        assert!(!listener.has_tls());
    }

    #[tokio::test]
    async fn test_listener_no_users() {
        let config = VlessInboundConfig::new("127.0.0.1:0".parse().unwrap());

        let result = VlessInboundListener::new(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_listener_invalid_uuid() {
        let config = VlessInboundConfig::new("127.0.0.1:0".parse().unwrap())
            .with_user(VlessUser::new("not-a-valid-uuid", Some("test")));

        let result = VlessInboundListener::new(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_listener_local_addr() {
        let config = VlessInboundConfig::new("127.0.0.1:0".parse().unwrap()).with_user(
            VlessUser::new("550e8400-e29b-41d4-a716-446655440000", Some("test")),
        );

        let listener = VlessInboundListener::new(config).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        assert!(local_addr.port() > 0);
    }

    #[tokio::test]
    async fn test_listener_shutdown() {
        let config = VlessInboundConfig::new("127.0.0.1:0".parse().unwrap()).with_user(
            VlessUser::new("550e8400-e29b-41d4-a716-446655440000", Some("test")),
        );

        let listener = VlessInboundListener::new(config).await.unwrap();
        let mut shutdown_rx = listener.subscribe_shutdown();

        // Shutdown should broadcast
        listener.shutdown();

        // Should receive shutdown signal
        assert!(shutdown_rx.recv().await.is_ok());
    }

    #[test]
    fn test_vless_inbound_stats() {
        let stats = VlessInboundStats::new();
        assert_eq!(stats.connections_accepted, 0);
        assert_eq!(stats.active_connections, 0);
    }

    #[test]
    fn test_listener_debug() {
        // Just verify Debug doesn't panic
        let config = VlessInboundConfig::new("127.0.0.1:443".parse().unwrap())
            .with_user(VlessUser::new(
                "550e8400-e29b-41d4-a716-446655440000",
                Some("test"),
            ))
            .with_fallback("127.0.0.1:80".parse().unwrap());

        // Can't create listener without binding, but we can test the config
        let debug = format!("{:?}", config);
        assert!(debug.contains("VlessInboundConfig"));
    }
}
