//! ControlPlaneHandler vs IngressProcessor Equivalence Tests
//!
//! This module verifies that `ControlPlaneHandler` produces identical routing
//! decisions as `IngressProcessor` for equivalent inputs.
//!
//! # Background
//!
//! The `controlplane` module is a new implementation that refactors routing
//! logic from `IngressProcessor` into a reusable component implementing
//! `netbridge::ConnectionHandler`. These tests ensure behavioral equivalence.
//!
//! # Test Categories
//!
//! - `chain_routing`: DSCP chain routing decisions
//! - `rule_matching`: Domain/GeoIP/Port rule matching and block handling
//!
//! # Running Tests
//!
//! ```bash
//! # Run all controlplane equivalence tests
//! cargo test --test integration_tests controlplane_equivalence
//!
//! # Run specific test module
//! cargo test --test integration_tests controlplane_equivalence::chain_routing
//! ```

mod chain_routing;
mod fixtures;
mod rule_matching;
