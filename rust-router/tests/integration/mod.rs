//! Integration tests for rust-router
//!
//! This module contains integration tests for verifying the behavior of various
//! rust-router components in realistic scenarios.
//!
//! # Test Organization
//!
//! - `ab_comparison`: A/B comparison framework for rust-router vs sing-box
//! - `socks5_integration`: SOCKS5 outbound integration tests with mock server
//! - `wireguard_integration`: WireGuard interface utilities and parity tests
//! - `failover_integration`: Health check, IPC, and graceful shutdown tests
//! - `dscp_chain`: DSCP chain routing verification and parity tests
//! - `stability`: Stress tests and concurrency verification
//! - `memory_stability`: Memory leak detection and budget verification
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
//! # Run A/B comparison tests
//! cargo test --test integration ab_comparison -- --nocapture
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
//! - A/B comparison tests use simulated data by default, real tests require both routers running

pub mod ab_comparison;
pub mod chaos;
pub mod dscp_chain;
pub mod e2e;
pub mod failover_integration;
pub mod memory_stability;
pub mod security;
pub mod socks5_integration;
pub mod stability;
pub mod wireguard_integration;
