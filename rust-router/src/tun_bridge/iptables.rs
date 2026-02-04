//! iptables management for TUN + TPROXY bridge
//!
//! This module re-exports `IptablesManager` from its canonical location in
//! `netbridge::kernel::iptables_core`. This preserves backward compatibility
//! for code that imports from `tun_bridge::IptablesManager`.
//!
//! New code should import directly from `netbridge::kernel::iptables_core` or
//! `netbridge::kernel::IptablesManager`.

pub use crate::netbridge::kernel::iptables_core::IptablesManager;
