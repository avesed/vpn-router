//! Integration test suite entry point
//!
//! This file serves as the entry point for integration tests.
//! All test modules are organized under `tests/integration/`.
//!
//! # Running Integration Tests
//!
//! ```bash
//! # Run all integration tests
//! cargo test --test integration_tests
//!
//! # Run specific test module
//! cargo test --test integration_tests socks5
//!
//! # Run tests that require network (marked with #[ignore])
//! cargo test --test integration_tests -- --ignored
//! ```

mod integration;
