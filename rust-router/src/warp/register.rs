// WARP registration implementation

use super::config::{constants::*, RegisterRequest, RegisterResponse, WarpRegistration};
use super::error::{Result, WarpError};
use base64::prelude::*;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::time::Duration;
use tracing::{debug, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

/// HTTP request timeout (30 seconds)
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// WARP+ license key format (expected pattern)
const WARP_PLUS_LICENSE_PATTERN: &str = r"^[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}$";

/// Generate x25519 keypair for WireGuard
pub fn generate_keypair() -> Result<(String, String)> {
    debug!("Generating x25519 keypair");

    let private_key = StaticSecret::random_from_rng(rand::thread_rng());
    let public_key = PublicKey::from(&private_key);

    let private_b64 = BASE64_STANDARD.encode(private_key.to_bytes());
    let public_b64 = BASE64_STANDARD.encode(public_key.as_bytes());

    Ok((private_b64, public_b64))
}

/// Register a new WARP device with Cloudflare
pub async fn register_device(tag: String, warp_plus_license: Option<String>) -> Result<WarpRegistration> {
    info!("Registering WARP device with tag: {}", tag);

    // Step 1: Generate keypair
    let (private_key, public_key) = generate_keypair()?;

    // Step 2: Generate install_id
    let install_id = hex::encode(rand::random::<[u8; 16]>());
    debug!("Generated install_id: {}", install_id);

    // Step 3: Build request
    let register_req = RegisterRequest {
        key: public_key.clone(),
        install_id,
        ..Default::default()
    };

    // Step 4: Make API request
    let response = make_api_request(register_req).await?;

    // Step 5: Validate response
    validate_response(&response)?;

    // Step 6: Extract WireGuard config
    let config = extract_config(&response, &private_key)?;

    // Step 7: Optionally upgrade to WARP+
    if let Some(license) = warp_plus_license {
        // H2 Fix: Validate WARP+ license key format
        validate_warp_plus_license(&license)?;

        info!("Upgrading to WARP+ with license");
        if let Err(e) = upgrade_to_plus(&config.account_id, &config.license_key, &license).await {
            warn!("WARP+ upgrade failed: {}, continuing with free account", e);
        } else {
            info!("Successfully upgraded to WARP+");
        }
    }

    info!("WARP registration successful: {}", tag);
    Ok(WarpRegistration {
        tag,
        ..config
    })
}

/// Validate WARP+ license key format
fn validate_warp_plus_license(license: &str) -> Result<()> {
    // Check basic length (expected format: XXXXXXXX-XXXXXXXX-XXXXXXXX)
    if license.len() < 26 || license.len() > 30 {
        return Err(WarpError::InvalidResponse(
            "WARP+ license key has invalid length".to_string(),
        ));
    }

    // Check for dashes at expected positions
    let parts: Vec<&str> = license.split('-').collect();
    if parts.len() != 3 {
        return Err(WarpError::InvalidResponse(
            "WARP+ license key must have format XXXXXXXX-XXXXXXXX-XXXXXXXX".to_string(),
        ));
    }

    // Validate each part is alphanumeric
    for (i, part) in parts.iter().enumerate() {
        if part.len() < 8 {
            return Err(WarpError::InvalidResponse(format!(
                "WARP+ license key part {} is too short",
                i + 1
            )));
        }
        if !part.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(WarpError::InvalidResponse(format!(
                "WARP+ license key part {} contains invalid characters",
                i + 1
            )));
        }
    }

    Ok(())
}

/// Make HTTP API request to Cloudflare
async fn make_api_request(req: RegisterRequest) -> Result<RegisterResponse> {
    debug!("Making API request to Cloudflare");

    // Install rustls crypto provider if not already installed
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Build HTTPS client
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|e| WarpError::Tls(e.to_string()))?
        .https_only()
        .enable_http1()
        .build();

    let client = Client::builder(TokioExecutor::new()).build(https);

    // Serialize request body
    let body_json = serde_json::to_string(&req)?;

    // Build HTTP request
    let uri = format!("{}/{}/reg", API_BASE, API_VERSION);
    let http_req = Request::builder()
        .method("POST")
        .uri(&uri)
        .header("CF-Client-Version", CF_CLIENT_VERSION)
        .header("Content-Type", "application/json")
        .header("User-Agent", USER_AGENT)
        .body(Full::new(Bytes::from(body_json)))?;

    debug!("Sending request to: {}", uri);

    // C2 Fix: Make request with timeout
    let resp = tokio::time::timeout(HTTP_TIMEOUT, client.request(http_req))
        .await
        .map_err(|_| WarpError::NetworkError("Request timeout".to_string()))?
        .map_err(|e| WarpError::ApiRequest(e.to_string()))?;

    let (parts, body) = resp.into_parts();

    // Check status code
    if !parts.status.is_success() {
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| WarpError::ApiRequest(e.to_string()))?
            .to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);

        // Check for rate limiting
        if parts.status.as_u16() == 429 {
            let retry_after = parts
                .headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60);
            return Err(WarpError::RateLimited(retry_after));
        }

        return Err(WarpError::InvalidResponse(format!(
            "HTTP {}: {}",
            parts.status, body_str
        )));
    }

    // Parse response
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| WarpError::ApiRequest(e.to_string()))?
        .to_bytes();

    let response: RegisterResponse = serde_json::from_slice(&body_bytes)?;

    debug!("Registration successful, account_id: {}", response.id);
    Ok(response)
}

/// Validate API response
fn validate_response(resp: &RegisterResponse) -> Result<()> {
    debug!("Validating API response");

    if resp.id.is_empty() {
        return Err(WarpError::InvalidResponse("Missing account ID".to_string()));
    }

    if resp.config.peers.is_empty() {
        return Err(WarpError::InvalidResponse("No peers in config".to_string()));
    }

    // Validate peer public key format (must be 32 bytes base64)
    let peer_key = BASE64_STANDARD.decode(&resp.config.peers[0].public_key)?;
    if peer_key.len() != 32 {
        return Err(WarpError::InvalidResponse(format!(
            "Invalid peer key length: expected 32 bytes, got {}",
            peer_key.len()
        )));
    }

    // Validate endpoint format
    if !resp.config.peers[0].endpoint.host.contains(':') {
        return Err(WarpError::InvalidEndpoint(format!(
            "Endpoint missing port: {}",
            resp.config.peers[0].endpoint.host
        )));
    }

    Ok(())
}

/// Extract WireGuard config from API response
fn extract_config(resp: &RegisterResponse, private_key: &str) -> Result<WarpRegistration> {
    debug!("Extracting WireGuard configuration");

    // Decode client_id to get reserved bytes
    let client_id_bytes = BASE64_STANDARD.decode(&resp.config.client_id)?;
    if client_id_bytes.len() < 3 {
        return Err(WarpError::InvalidReservedBytes(client_id_bytes.len()));
    }
    let reserved = [client_id_bytes[0], client_id_bytes[1], client_id_bytes[2]];

    let peer = &resp.config.peers[0];

    Ok(WarpRegistration {
        tag: String::new(), // Will be set by caller
        account_id: resp.id.clone(),
        license_key: resp.account.license.clone(),
        private_key: private_key.to_string(),
        peer_public_key: peer.public_key.clone(),
        endpoint: peer.endpoint.host.clone(),
        reserved,
        ipv4_address: resp.config.interface.addresses.v4.clone(),
        ipv6_address: resp.config.interface.addresses.v6.clone(),
        account_type: resp.account.account_type.clone(),
    })
}

/// Upgrade account to WARP+
async fn upgrade_to_plus(account_id: &str, license_key: &str, warp_plus_license: &str) -> Result<()> {
    debug!("Upgrading account {} to WARP+", account_id);

    // Install rustls crypto provider if not already installed
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Build HTTPS client
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|e| WarpError::Tls(e.to_string()))?
        .https_only()
        .enable_http1()
        .build();

    let client = Client::builder(TokioExecutor::new()).build(https);

    // Build request body
    let body_json = serde_json::json!({
        "license": warp_plus_license
    })
    .to_string();

    // Build HTTP request
    let uri = format!("{}/{}/reg/{}", API_BASE, API_VERSION, account_id);
    let http_req = Request::builder()
        .method("PATCH")
        .uri(&uri)
        .header("Authorization", format!("Bearer {}", license_key))
        .header("Content-Type", "application/json")
        .header("User-Agent", USER_AGENT)
        .body(Full::new(Bytes::from(body_json)))?;

    debug!("Sending WARP+ upgrade request to: {}", uri);

    // C2 Fix: Make request with timeout
    let resp = tokio::time::timeout(HTTP_TIMEOUT, client.request(http_req))
        .await
        .map_err(|_| WarpError::NetworkError("WARP+ upgrade timeout".to_string()))?
        .map_err(|e| WarpError::ApiRequest(e.to_string()))?;

    let (parts, body) = resp.into_parts();

    if !parts.status.is_success() {
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| WarpError::ApiRequest(e.to_string()))?
            .to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        return Err(WarpError::InvalidResponse(format!(
            "WARP+ upgrade failed: HTTP {}: {}",
            parts.status, body_str
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (private, public) = generate_keypair().unwrap();

        // Verify base64 format (44 characters for 32 bytes)
        assert_eq!(private.len(), 44);
        assert_eq!(public.len(), 44);

        // Verify can decode
        let private_bytes = BASE64_STANDARD.decode(&private).unwrap();
        let public_bytes = BASE64_STANDARD.decode(&public).unwrap();

        assert_eq!(private_bytes.len(), 32);
        assert_eq!(public_bytes.len(), 32);
    }

    #[test]
    fn test_error_recoverability() {
        assert!(WarpError::RateLimited(60).is_recoverable());
        assert!(WarpError::NetworkError("test".to_string()).is_recoverable());
        assert!(!WarpError::InvalidResponse("test".to_string()).is_recoverable());
    }

    #[test]
    fn test_retry_delay() {
        let err = WarpError::RateLimited(120);
        assert_eq!(err.retry_delay(), Some(120));

        let err = WarpError::InvalidResponse("test".to_string());
        assert_eq!(err.retry_delay(), None);
    }

    #[test]
    fn test_warp_plus_license_validation() {
        // Valid license keys
        assert!(validate_warp_plus_license("12345678-ABCD1234-xyz98765").is_ok());
        assert!(validate_warp_plus_license("aB3De5Gh-1J2kL4mN-6P7qR8sT").is_ok());

        // Invalid: too short
        assert!(validate_warp_plus_license("1234567-ABCD1234-xyz98765").is_err());

        // Invalid: missing dashes
        assert!(validate_warp_plus_license("12345678ABCD1234xyz98765").is_err());

        // Invalid: too few parts
        assert!(validate_warp_plus_license("12345678-ABCD1234").is_err());

        // Invalid: special characters
        assert!(validate_warp_plus_license("12345678-ABCD!234-xyz98765").is_err());

        // Invalid: empty
        assert!(validate_warp_plus_license("").is_err());
    }
}
