//! IPC Server
//!
//! This module provides a Unix socket server for IPC communication.

use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use super::handler::IpcHandler;
use super::protocol::{
    decode_message, encode_message, ErrorCode, IpcCommand, IpcResponse, LENGTH_PREFIX_SIZE,
    MAX_MESSAGE_SIZE,
};
use crate::config::IpcConfig;
use crate::error::IpcError;

/// IPC server for handling control commands
pub struct IpcServer {
    /// Configuration
    config: IpcConfig,

    /// Command handler
    handler: Arc<IpcHandler>,

    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
}

impl IpcServer {
    /// Create a new IPC server
    pub fn new(config: IpcConfig, handler: Arc<IpcHandler>) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            config,
            handler,
            shutdown_tx,
        }
    }

    /// Run the IPC server
    ///
    /// This starts listening on the Unix socket and handles incoming connections.
    pub async fn run(&self) -> Result<(), IpcError> {
        if !self.config.enabled {
            info!("IPC server disabled");
            return Ok(());
        }

        let socket_path = &self.config.socket_path;

        // Remove existing socket file if it exists
        if socket_path.exists() {
            std::fs::remove_file(socket_path).map_err(|e| IpcError::SocketCreation {
                path: socket_path.display().to_string(),
                reason: format!("Failed to remove existing socket: {}", e),
            })?;
        }

        // Create parent directory if needed
        if let Some(parent) = socket_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| IpcError::SocketCreation {
                    path: socket_path.display().to_string(),
                    reason: format!("Failed to create parent directory: {}", e),
                })?;
            }
        }

        // Create Unix listener
        let listener = UnixListener::bind(socket_path).map_err(|e| IpcError::BindError {
            path: socket_path.display().to_string(),
            reason: e.to_string(),
        })?;

        // Set socket permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(self.config.socket_mode);
            std::fs::set_permissions(socket_path, permissions).map_err(|e| {
                IpcError::SocketCreation {
                    path: socket_path.display().to_string(),
                    reason: format!("Failed to set permissions: {}", e),
                }
            })?;
        }

        info!("IPC server listening on {:?}", socket_path);

        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            let handler = Arc::clone(&self.handler);
                            let max_size = self.config.max_message_size;

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, handler, max_size).await {
                                    debug!("IPC connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("IPC accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("IPC server shutting down");
                    break;
                }
            }
        }

        // Cleanup socket file
        if socket_path.exists() {
            let _ = std::fs::remove_file(socket_path);
        }

        Ok(())
    }

    /// Get a shutdown signal sender
    pub fn shutdown_sender(&self) -> broadcast::Sender<()> {
        self.shutdown_tx.clone()
    }

    /// Initiate shutdown
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// Handle a single IPC connection
async fn handle_connection(
    mut stream: UnixStream,
    handler: Arc<IpcHandler>,
    max_message_size: usize,
) -> Result<(), IpcError> {
    debug!("New IPC connection");

    loop {
        // Read length prefix
        let mut len_buf = [0u8; LENGTH_PREFIX_SIZE];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("IPC client disconnected");
                return Ok(());
            }
            Err(e) => return Err(IpcError::from(e)),
        }

        let msg_len = u32::from_be_bytes(len_buf) as usize;

        // Validate message size
        if msg_len > max_message_size {
            warn!(
                "IPC message too large: {} bytes (max {})",
                msg_len, max_message_size
            );
            let response = IpcResponse::error(
                ErrorCode::InvalidParameters,
                format!("Message too large: {} bytes", msg_len),
            );
            send_response(&mut stream, &response).await?;
            continue;
        }

        // Read message body
        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).await?;

        // Parse command
        let command: IpcCommand = match decode_message(&msg_buf) {
            Ok(cmd) => cmd,
            Err(e) => {
                warn!("Invalid IPC command: {}", e);
                let response = IpcResponse::error(
                    ErrorCode::InvalidCommand,
                    format!("Invalid command format: {}", e),
                );
                send_response(&mut stream, &response).await?;
                continue;
            }
        };

        debug!("Received IPC command: {:?}", command);

        // Check for shutdown command (special handling)
        let is_shutdown = matches!(command, IpcCommand::Shutdown { .. });

        // Handle command
        let response = handler.handle(command).await;

        // Send response
        send_response(&mut stream, &response).await?;

        // If this was a shutdown command, break out of the loop
        if is_shutdown {
            debug!("Shutdown command received, closing connection");
            break;
        }
    }

    Ok(())
}

/// Send a response to the client
async fn send_response(stream: &mut UnixStream, response: &IpcResponse) -> Result<(), IpcError> {
    let encoded = encode_message(response).map_err(|e| IpcError::serialization(e.to_string()))?;

    stream.write_all(&encoded).await?;
    stream.flush().await?;

    Ok(())
}

/// IPC client for connecting to the server
pub struct IpcClient {
    socket_path: std::path::PathBuf,
}

impl IpcClient {
    /// Create a new IPC client
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Send a command and receive a response
    pub async fn send(&self, command: IpcCommand) -> Result<IpcResponse, IpcError> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| IpcError::ConnectionError(e.to_string()))?;

        // Encode and send command
        let encoded =
            encode_message(&command).map_err(|e| IpcError::serialization(e.to_string()))?;
        stream.write_all(&encoded).await?;
        stream.flush().await?;

        // Read response
        let mut len_buf = [0u8; LENGTH_PREFIX_SIZE];
        stream.read_exact(&mut len_buf).await?;
        let msg_len = u32::from_be_bytes(len_buf) as usize;

        if msg_len > MAX_MESSAGE_SIZE {
            return Err(IpcError::protocol(format!(
                "Response too large: {} bytes",
                msg_len
            )));
        }

        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).await?;

        let response: IpcResponse =
            decode_message(&msg_buf).map_err(|e| IpcError::protocol(e.to_string()))?;

        Ok(response)
    }

    /// Send a ping command
    pub async fn ping(&self) -> Result<bool, IpcError> {
        let response = self.send(IpcCommand::Ping).await?;
        Ok(matches!(response, IpcResponse::Pong))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConnectionConfig;
    use crate::connection::ConnectionManager;
    use crate::outbound::OutboundManager;
    use std::time::Duration;
    use tempfile::tempdir;

    fn create_test_handler() -> Arc<IpcHandler> {
        let outbound_manager = Arc::new(OutboundManager::new());
        let conn_config = ConnectionConfig::default();
        let connection_manager = Arc::new(ConnectionManager::new(
            &conn_config,
            Arc::clone(&outbound_manager),
            "direct".into(),
            Duration::from_millis(300),
        ));

        Arc::new(IpcHandler::new(connection_manager, outbound_manager))
    }

    #[tokio::test]
    async fn test_client_server() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");

        let config = IpcConfig {
            socket_path: socket_path.clone(),
            socket_mode: 0o660,
            enabled: true,
            max_message_size: 1024 * 1024,
        };

        let handler = create_test_handler();
        let server = IpcServer::new(config, handler);
        let shutdown_tx = server.shutdown_sender();

        // Start server in background
        let server_handle = tokio::spawn(async move {
            server.run().await
        });

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Create client and send ping
        let client = IpcClient::new(&socket_path);
        let pong = client.ping().await.unwrap();
        assert!(pong);

        // Send status command
        let response = client.send(IpcCommand::Status).await.unwrap();
        assert!(matches!(response, IpcResponse::Status(_)));

        // Shutdown
        let _ = shutdown_tx.send(());
        tokio::time::sleep(Duration::from_millis(100)).await;

        server_handle.abort();
    }
}
