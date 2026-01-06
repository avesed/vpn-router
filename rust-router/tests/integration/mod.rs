//! Integration tests for rust-router
//!
//! This module contains integration tests for verifying the behavior of various
//! rust-router components in realistic scenarios.
//!
//! # Test Organization
//!
//! - `socks5_integration`: SOCKS5 outbound integration tests with mock server
//! - `wireguard_integration`: WireGuard interface utilities and parity tests
//! - `failover_integration`: Health check, IPC, and graceful shutdown tests
//! - `dscp_chain`: DSCP chain routing verification and parity tests
//!
//! # Running Tests
//!
//! ```bash
//! # Run all integration tests
//! cargo test --test integration
//!
//! # Run specific test module
//! cargo test --test integration socks5
//!
//! # Run tests that require network (marked with #[ignore])
//! cargo test --test integration -- --ignored
//! ```
//!
//! # Test Requirements
//!
//! - Most tests use mock servers and don't require network access
//! - Tests marked with `#[ignore]` require specific setup (CAP_NET_ADMIN, real interfaces)
//! - DSCP chain tests verify parity with Python implementation

pub mod dscp_chain;
pub mod failover_integration;
pub mod socks5_integration;
pub mod wireguard_integration;
