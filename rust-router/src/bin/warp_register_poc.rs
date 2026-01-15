// WARP Registration PoC
// Tests Cloudflare WARP API registration without warp-cli dependency

use base64::prelude::*;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Serialize)]
struct RegisterRequest {
    key: String,
    install_id: String,
    fcm_token: String,
    tos: String,
    #[serde(rename = "type")]
    device_type: String,
    model: String,
    locale: String,
}

#[derive(Deserialize, Debug)]
struct RegisterResponse {
    id: String,
    account: Account,
    config: WarpConfig,
}

#[derive(Deserialize, Debug)]
struct Account {
    id: String,
    account_type: String,
    created: String,
    license: String,
}

#[derive(Deserialize, Debug)]
struct WarpConfig {
    client_id: String,
    interface: Interface,
    peers: Vec<Peer>,
}

#[derive(Deserialize, Debug)]
struct Interface {
    addresses: Addresses,
}

#[derive(Deserialize, Debug)]
struct Addresses {
    v4: String,
    v6: String,
}

#[derive(Deserialize, Debug)]
struct Peer {
    public_key: String,
    endpoint: Endpoint,
}

#[derive(Deserialize, Debug)]
struct Endpoint {
    host: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install rustls crypto provider (required for rustls 0.23+)
    let _ = rustls::crypto::ring::default_provider().install_default();

    println!("=== WARP Registration PoC ===\n");

    // Step 1: Generate x25519 keypair
    println!("1. Generating x25519 keypair...");
    let private_key = StaticSecret::random_from_rng(rand::thread_rng());
    let public_key = PublicKey::from(&private_key);

    let private_b64 = BASE64_STANDARD.encode(private_key.to_bytes());
    let public_b64 = BASE64_STANDARD.encode(public_key.as_bytes());

    println!("   Private key: {}...", &private_b64[..16]);
    println!("   Public key:  {}...", &public_b64[..16]);

    // Step 2: Register with Cloudflare API
    println!("\n2. Registering with Cloudflare API...");
    let install_id = hex::encode(rand::random::<[u8; 16]>());
    println!("   Install ID: {}", install_id);

    let register_req = RegisterRequest {
        key: public_b64,
        install_id,
        fcm_token: String::new(),
        tos: "2021-01-01T00:00:00.000Z".to_string(),
        device_type: "Android".to_string(),
        model: "PC".to_string(),
        locale: "en_US".to_string(),
    };

    // Build HTTPS client
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()?
        .https_only()
        .enable_http1()
        .build();

    let client = Client::builder(TokioExecutor::new()).build(https);

    // Make API request
    let body_json = serde_json::to_string(&register_req)?;
    let req = Request::builder()
        .method("POST")
        .uri("https://api.cloudflareclient.com/v0a2158/reg")
        .header("CF-Client-Version", "a-6.30")
        .header("Content-Type", "application/json")
        .header("User-Agent", "rust-router/0.1.0")
        .body(Full::new(Bytes::from(body_json)))?;

    let resp = client.request(req).await?;
    println!("   Response status: {}", resp.status());

    let (parts, body) = resp.into_parts();

    if !parts.status.is_success() {
        let body_bytes = body.collect().await?.to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        eprintln!("   Error response: {}", body_str);
        return Err("Registration failed".into());
    }

    // Step 3: Parse response
    println!("\n3. Parsing response...");
    let body_bytes = body.collect().await?.to_bytes();
    let register_resp: RegisterResponse = serde_json::from_slice(&body_bytes)?;

    println!("   Account ID: {}", register_resp.id);
    println!("   Account type: {}", register_resp.account.account_type);
    println!("   License key: {}...", &register_resp.account.license[..16]);

    // Step 4: Extract WireGuard config
    println!("\n4. Extracting WireGuard configuration...");
    let client_id_bytes = BASE64_STANDARD.decode(&register_resp.config.client_id)?;
    let reserved = [client_id_bytes[0], client_id_bytes[1], client_id_bytes[2]];

    let peer = &register_resp.config.peers[0];

    println!("   Interface addresses:");
    println!("     IPv4: {}", register_resp.config.interface.addresses.v4);
    println!("     IPv6: {}", register_resp.config.interface.addresses.v6);
    println!("   Peer public key: {}...", &peer.public_key[..16]);
    println!("   Endpoint: {}", peer.endpoint.host);
    println!("   Reserved bytes: {:?}", reserved);

    // Step 5: Generate WireGuard configuration
    println!("\n5. WireGuard Configuration:");
    println!("   [Interface]");
    println!("   PrivateKey = {}", private_b64);
    println!(
        "   Address = {}, {}",
        register_resp.config.interface.addresses.v4, register_resp.config.interface.addresses.v6
    );
    println!();
    println!("   [Peer]");
    println!("   PublicKey = {}", peer.public_key);
    println!("   Endpoint = {}", peer.endpoint.host);
    println!("   AllowedIPs = 0.0.0.0/0, ::/0");

    println!("\n=== Success! ===");
    Ok(())
}
