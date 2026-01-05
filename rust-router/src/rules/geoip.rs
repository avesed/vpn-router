//! `GeoIP` matcher for IP-based routing rules
//!
//! This module provides efficient IP address matching for routing decisions.
//! It supports two match types:
//!
//! - **Direct CIDR matching**: Match specific IP ranges (e.g., `192.168.0.0/16`)
//! - **`GeoIP` country matching**: Match by country code (e.g., `geoip:CN`)
//!
//! # Architecture
//!
//! The matcher supports lazy loading of country CIDR data. Country data is loaded
//! on first access from JSON files in the geoip directory, reducing startup time
//! and memory usage when not all countries are needed.
//!
//! # Example
//!
//! ```no_run
//! use rust_router::rules::geoip::GeoIpMatcher;
//! use std::net::IpAddr;
//!
//! let matcher = GeoIpMatcher::builder()
//!     .geoip_dir("/config/geoip")
//!     .load_catalog("/config/geoip-catalog.json")
//!     .unwrap()
//!     .add_cidr("192.168.0.0/16", "direct")
//!     .unwrap()
//!     .add_cidr("10.0.0.0/8", "direct")
//!     .unwrap()
//!     .add_country("cn", "cn-proxy")
//!     .unwrap()
//!     .add_country("us", "us-proxy")
//!     .unwrap()
//!     .build()
//!     .unwrap();
//!
//! let ip: IpAddr = "192.168.1.100".parse().unwrap();
//! assert_eq!(matcher.match_ip(ip), Some("direct"));
//! ```

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use ipnet::IpNet;
use serde::Deserialize;

use crate::error::RuleError;

/// Information about a country in the `GeoIP` catalog
#[derive(Debug, Clone)]
pub struct CountryInfo {
    /// Two-letter country code (lowercase)
    pub code: String,
    /// Country name
    pub name: String,
    /// Display name for UI
    pub display_name: String,
    /// Number of IPv4 CIDR ranges
    pub ipv4_count: usize,
    /// Number of IPv6 CIDR ranges
    pub ipv6_count: usize,
    /// Recommended exit for this country
    pub recommended_exit: Option<String>,
}

/// `GeoIP` catalog parsed from `geoip-catalog.json`
#[derive(Debug, Clone, Deserialize)]
struct GeoIpCatalog {
    /// Catalog version
    #[allow(dead_code)]
    version: u32,
    /// Total number of countries
    #[allow(dead_code)]
    total_countries: usize,
    /// Total IPv4 ranges across all countries
    #[allow(dead_code)]
    total_ipv4_ranges: usize,
    /// Total IPv6 ranges across all countries
    #[allow(dead_code)]
    total_ipv6_ranges: usize,
    /// List of countries
    countries: Vec<CatalogCountry>,
}

/// Country entry in the catalog
#[derive(Debug, Clone, Deserialize)]
struct CatalogCountry {
    code: String,
    name: String,
    display_name: String,
    ipv4_count: usize,
    ipv6_count: usize,
    #[serde(default)]
    recommended_exit: Option<String>,
}

/// Country data parsed from individual country JSON files
#[derive(Debug, Deserialize)]
struct CountryData {
    #[allow(dead_code)]
    code: String,
    #[allow(dead_code)]
    name: String,
    ipv4_ranges: Vec<String>,
    ipv6_ranges: Vec<String>,
}

/// `GeoIP` matcher supporting CIDR and country-based IP matching
///
/// The matcher processes IPs in priority order:
/// 1. Direct CIDR rules (highest priority, checked in order added)
/// 2. `GeoIP` country rules (checked in order added)
///
/// This ordering ensures that specific IP ranges can override country rules.
pub struct GeoIpMatcher {
    /// Direct CIDR rules: (network, outbound)
    /// Checked in order, first match wins
    cidr_rules: Vec<(IpNet, String)>,

    /// Country code -> outbound mapping
    /// Countries are checked in the order they were added
    country_rules: Vec<(String, String)>,

    /// Lazy-loaded country CIDR data: `country_code` -> `Vec<IpNet>`
    /// Uses `RwLock` for interior mutability during lazy loading
    country_cidrs: RwLock<HashMap<String, Vec<IpNet>>>,

    /// Path to geoip directory for lazy loading
    geoip_dir: Option<PathBuf>,

    /// Catalog of available countries (from geoip-catalog.json)
    available_countries: HashMap<String, CountryInfo>,
}

impl std::fmt::Debug for GeoIpMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let loaded_countries = self
            .country_cidrs
            .read()
            .map(|c| c.len())
            .unwrap_or(0);

        f.debug_struct("GeoIpMatcher")
            .field("cidr_rules", &self.cidr_rules.len())
            .field("country_rules", &self.country_rules.len())
            .field("loaded_countries", &loaded_countries)
            .field("available_countries", &self.available_countries.len())
            .field("geoip_dir", &self.geoip_dir)
            .finish()
    }
}

impl GeoIpMatcher {
    /// Create a new builder for constructing a `GeoIpMatcher`
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::rules::geoip::GeoIpMatcher;
    ///
    /// let matcher = GeoIpMatcher::builder()
    ///     .add_cidr("192.168.0.0/16", "direct")
    ///     .unwrap()
    ///     .build()
    ///     .unwrap();
    /// ```
    #[must_use]
    pub fn builder() -> GeoIpMatcherBuilder {
        GeoIpMatcherBuilder::new()
    }

    /// Create an empty `GeoIP` matcher
    ///
    /// An empty matcher will return `None` for all IP lookups.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            cidr_rules: Vec::new(),
            country_rules: Vec::new(),
            country_cidrs: RwLock::new(HashMap::new()),
            geoip_dir: None,
            available_countries: HashMap::new(),
        }
    }

    /// Match an IP address against all rules
    ///
    /// Returns the outbound tag of the first matching rule, or `None` if
    /// no rules match.
    ///
    /// # Priority Order
    ///
    /// 1. Direct CIDR rules (highest priority, checked in order added)
    /// 2. `GeoIP` country rules (checked in order added)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::geoip::GeoIpMatcher;
    /// use std::net::IpAddr;
    ///
    /// let matcher = GeoIpMatcher::builder()
    ///     .add_cidr("192.168.0.0/16", "local")
    ///     .unwrap()
    ///     .add_cidr("10.0.0.0/8", "private")
    ///     .unwrap()
    ///     .build()
    ///     .unwrap();
    ///
    /// let ip: IpAddr = "192.168.1.100".parse().unwrap();
    /// assert_eq!(matcher.match_ip(ip), Some("local"));
    ///
    /// let ip: IpAddr = "8.8.8.8".parse().unwrap();
    /// assert_eq!(matcher.match_ip(ip), None);
    /// ```
    #[must_use]
    pub fn match_ip(&self, ip: IpAddr) -> Option<&str> {
        // Priority 1: Direct CIDR rules
        for (network, outbound) in &self.cidr_rules {
            if network.contains(&ip) {
                return Some(outbound.as_str());
            }
        }

        // Priority 2: GeoIP country rules
        for (country_code, outbound) in &self.country_rules {
            if self.is_ip_in_country_internal(ip, country_code) {
                return Some(outbound.as_str());
            }
        }

        None
    }

    /// Check if an IP address belongs to a specific country
    ///
    /// This method will lazy-load the country data if not already loaded.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to check
    /// * `country_code` - Two-letter country code (case-insensitive)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::rules::geoip::GeoIpMatcher;
    /// use std::net::IpAddr;
    ///
    /// let matcher = GeoIpMatcher::builder()
    ///     .geoip_dir("/config/geoip")
    ///     .load_catalog("/config/geoip-catalog.json")
    ///     .unwrap()
    ///     .build()
    ///     .unwrap();
    ///
    /// let ip: IpAddr = "8.8.8.8".parse().unwrap();
    /// let is_us = matcher.is_ip_in_country(ip, "us");
    /// ```
    pub fn is_ip_in_country(&self, ip: IpAddr, country_code: &str) -> bool {
        let code_lower = country_code.to_ascii_lowercase();
        self.is_ip_in_country_internal(ip, &code_lower)
    }

    /// Internal country check with normalized country code
    fn is_ip_in_country_internal(&self, ip: IpAddr, country_code: &str) -> bool {
        // Try to load country data if not already loaded
        if let Err(e) = self.load_country_data(country_code) {
            tracing::warn!("Failed to load country data for {}: {}", country_code, e);
            return false;
        }

        // Check if IP is in any of the country's CIDRs
        let cache = match self.country_cidrs.read() {
            Ok(cache) => cache,
            Err(e) => {
                tracing::error!("Failed to acquire read lock: {}", e);
                return false;
            }
        };

        if let Some(cidrs) = cache.get(country_code) {
            for cidr in cidrs {
                if cidr.contains(&ip) {
                    return true;
                }
            }
        }

        false
    }

    /// Load country CIDR data on demand (lazy loading)
    ///
    /// Uses double-checked locking pattern for thread safety.
    fn load_country_data(&self, country_code: &str) -> Result<(), RuleError> {
        // Fast path: check if already loaded (read lock)
        {
            let cache = self.country_cidrs.read().map_err(|e| {
                RuleError::GeoIpLoadError(country_code.to_string(), format!("lock poisoned: {e}"))
            })?;
            if cache.contains_key(country_code) {
                return Ok(());
            }
        }

        // Slow path: need to load (write lock)
        let mut cache = self.country_cidrs.write().map_err(|e| {
            RuleError::GeoIpLoadError(country_code.to_string(), format!("lock poisoned: {e}"))
        })?;

        // Double-check after acquiring write lock
        if cache.contains_key(country_code) {
            return Ok(());
        }

        // Check if geoip directory is configured
        let geoip_dir = self
            .geoip_dir
            .as_ref()
            .ok_or(RuleError::GeoIpNotConfigured)?;

        // Check if country is in catalog
        if !self.available_countries.is_empty() && !self.available_countries.contains_key(country_code) {
            return Err(RuleError::UnknownCountry(country_code.to_string()));
        }

        // Load from file
        let file_path = geoip_dir.join(format!("{country_code}.json"));
        let data = fs::read_to_string(&file_path).map_err(|e| {
            RuleError::GeoIpLoadError(country_code.to_string(), e.to_string())
        })?;

        // Parse JSON
        let country_data: CountryData = serde_json::from_str(&data).map_err(|e| {
            RuleError::GeoIpParseError(country_code.to_string(), e.to_string())
        })?;

        // Parse CIDRs
        let mut cidrs = Vec::with_capacity(
            country_data.ipv4_ranges.len() + country_data.ipv6_ranges.len(),
        );

        for cidr_str in country_data
            .ipv4_ranges
            .iter()
            .chain(country_data.ipv6_ranges.iter())
        {
            match cidr_str.parse::<IpNet>() {
                Ok(cidr) => cidrs.push(cidr),
                Err(e) => {
                    tracing::warn!(
                        "Skipping invalid CIDR '{}' in country {}: {}",
                        cidr_str,
                        country_code,
                        e
                    );
                }
            }
        }

        cache.insert(country_code.to_string(), cidrs);
        Ok(())
    }

    /// Preload country data for specific countries
    ///
    /// This is an optional optimization to load frequently-used countries
    /// at startup rather than on first access.
    ///
    /// # Arguments
    ///
    /// * `codes` - Slice of country codes to preload
    ///
    /// # Errors
    ///
    /// Returns `RuleError` if any country fails to load.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::rules::geoip::GeoIpMatcher;
    ///
    /// let matcher = GeoIpMatcher::builder()
    ///     .geoip_dir("/config/geoip")
    ///     .load_catalog("/config/geoip-catalog.json")
    ///     .unwrap()
    ///     .build()
    ///     .unwrap();
    ///
    /// // Preload commonly used countries
    /// matcher.preload_countries(&["us", "cn", "gb"]).unwrap();
    /// ```
    pub fn preload_countries(&self, codes: &[&str]) -> Result<(), RuleError> {
        for code in codes {
            let code_lower = code.to_ascii_lowercase();
            self.load_country_data(&code_lower)?;
        }
        Ok(())
    }

    /// Get list of available countries from the catalog
    ///
    /// Returns an empty vector if no catalog was loaded.
    #[must_use]
    pub fn available_countries(&self) -> Vec<&CountryInfo> {
        self.available_countries.values().collect()
    }

    /// Get information about a specific country
    ///
    /// # Arguments
    ///
    /// * `code` - Two-letter country code (case-insensitive)
    #[must_use]
    pub fn get_country_info(&self, code: &str) -> Option<&CountryInfo> {
        let code_lower = code.to_ascii_lowercase();
        self.available_countries.get(&code_lower)
    }

    /// Check if the matcher has any rules
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cidr_rules.is_empty() && self.country_rules.is_empty()
    }

    /// Get the total number of rules (CIDR + country)
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.cidr_rules.len() + self.country_rules.len()
    }

    /// Get the number of direct CIDR rules
    #[must_use]
    pub fn cidr_count(&self) -> usize {
        self.cidr_rules.len()
    }

    /// Get the number of country rules
    #[must_use]
    pub fn country_count(&self) -> usize {
        self.country_rules.len()
    }

    /// Get the number of currently loaded countries
    #[must_use]
    pub fn loaded_country_count(&self) -> usize {
        self.country_cidrs
            .read()
            .map(|c| c.len())
            .unwrap_or(0)
    }

    /// Get the number of available countries in the catalog
    #[must_use]
    pub fn catalog_country_count(&self) -> usize {
        self.available_countries.len()
    }
}

/// Builder for constructing a `GeoIpMatcher`
///
/// The builder collects all rules and compiles them into an efficient
/// matcher when `build()` is called.
///
/// # Example
///
/// ```no_run
/// use rust_router::rules::geoip::GeoIpMatcherBuilder;
///
/// let matcher = GeoIpMatcherBuilder::new()
///     .geoip_dir("/config/geoip")
///     .load_catalog("/config/geoip-catalog.json")
///     .unwrap()
///     .add_cidr("192.168.0.0/16", "direct")
///     .unwrap()
///     .add_country("cn", "proxy")
///     .unwrap()
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Default)]
pub struct GeoIpMatcherBuilder {
    cidr_rules: Vec<(IpNet, String)>,
    country_rules: Vec<(String, String)>,
    geoip_dir: Option<PathBuf>,
    catalog: HashMap<String, CountryInfo>,
}

impl GeoIpMatcherBuilder {
    /// Create a new empty builder
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the geoip directory for lazy loading country data
    ///
    /// The directory should contain per-country JSON files (e.g., `us.json`, `cn.json`).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::rules::geoip::GeoIpMatcherBuilder;
    ///
    /// let builder = GeoIpMatcherBuilder::new()
    ///     .geoip_dir("/config/geoip");
    /// ```
    #[must_use]
    pub fn geoip_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.geoip_dir = Some(path.into());
        self
    }

    /// Load the `GeoIP` catalog from a JSON file
    ///
    /// The catalog provides metadata about available countries without
    /// loading all the CIDR data.
    ///
    /// # Errors
    ///
    /// Returns `RuleError::GeoIpLoadError` if the file cannot be read.
    /// Returns `RuleError::GeoIpParseError` if the file is not valid JSON.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::rules::geoip::GeoIpMatcherBuilder;
    ///
    /// let builder = GeoIpMatcherBuilder::new()
    ///     .load_catalog("/config/geoip-catalog.json")
    ///     .unwrap();
    /// ```
    pub fn load_catalog(mut self, path: impl AsRef<Path>) -> Result<Self, RuleError> {
        let path = path.as_ref();
        let data = fs::read_to_string(path).map_err(|e| {
            RuleError::GeoIpLoadError("catalog".to_string(), e.to_string())
        })?;

        let catalog: GeoIpCatalog = serde_json::from_str(&data).map_err(|e| {
            RuleError::GeoIpParseError("catalog".to_string(), e.to_string())
        })?;

        for country in catalog.countries {
            let code_lower = country.code.to_ascii_lowercase();
            self.catalog.insert(
                code_lower.clone(),
                CountryInfo {
                    code: code_lower,
                    name: country.name,
                    display_name: country.display_name,
                    ipv4_count: country.ipv4_count,
                    ipv6_count: country.ipv6_count,
                    recommended_exit: country.recommended_exit,
                },
            );
        }

        Ok(self)
    }

    /// Add a direct CIDR rule
    ///
    /// CIDR rules have higher priority than country rules and are checked
    /// in the order they are added.
    ///
    /// # Arguments
    ///
    /// * `cidr` - CIDR notation (e.g., `192.168.0.0/16`, `10.0.0.0/8`, `2001:db8::/32`)
    /// * `outbound` - Outbound tag for matching IPs
    ///
    /// # Errors
    ///
    /// Returns `RuleError::InvalidCidr` if the CIDR notation is invalid.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::geoip::GeoIpMatcherBuilder;
    ///
    /// let builder = GeoIpMatcherBuilder::new()
    ///     .add_cidr("192.168.0.0/16", "direct")
    ///     .unwrap()
    ///     .add_cidr("10.0.0.0/8", "direct")
    ///     .unwrap();
    /// ```
    pub fn add_cidr(
        mut self,
        cidr: &str,
        outbound: impl Into<String>,
    ) -> Result<Self, RuleError> {
        let network: IpNet = cidr
            .parse()
            .map_err(|_| RuleError::InvalidCidr(cidr.to_string()))?;
        self.cidr_rules.push((network, outbound.into()));
        Ok(self)
    }

    /// Add a CIDR rule using a mutable reference
    ///
    /// This is useful when adding rules in a loop.
    ///
    /// # Errors
    ///
    /// Returns `RuleError::InvalidCidr` if the CIDR notation is invalid.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::geoip::GeoIpMatcherBuilder;
    ///
    /// let mut builder = GeoIpMatcherBuilder::new();
    /// builder.add_cidr_mut("192.168.0.0/16", "direct").unwrap();
    /// builder.add_cidr_mut("10.0.0.0/8", "direct").unwrap();
    /// ```
    pub fn add_cidr_mut(
        &mut self,
        cidr: &str,
        outbound: impl Into<String>,
    ) -> Result<&mut Self, RuleError> {
        let network: IpNet = cidr
            .parse()
            .map_err(|_| RuleError::InvalidCidr(cidr.to_string()))?;
        self.cidr_rules.push((network, outbound.into()));
        Ok(self)
    }

    /// Add a `GeoIP` country rule
    ///
    /// Country rules are checked after CIDR rules, in the order they are added.
    ///
    /// # Arguments
    ///
    /// * `country_code` - Two-letter country code (case-insensitive)
    /// * `outbound` - Outbound tag for matching IPs
    ///
    /// # Errors
    ///
    /// Returns `RuleError::UnknownCountry` if a catalog was loaded and the
    /// country code is not in the catalog.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::rules::geoip::GeoIpMatcherBuilder;
    ///
    /// let builder = GeoIpMatcherBuilder::new()
    ///     .load_catalog("/config/geoip-catalog.json")
    ///     .unwrap()
    ///     .add_country("cn", "cn-proxy")
    ///     .unwrap()
    ///     .add_country("us", "us-proxy")
    ///     .unwrap();
    /// ```
    pub fn add_country(
        mut self,
        country_code: &str,
        outbound: impl Into<String>,
    ) -> Result<Self, RuleError> {
        let code_lower = country_code.to_ascii_lowercase();

        // Validate against catalog if loaded
        if !self.catalog.is_empty() && !self.catalog.contains_key(&code_lower) {
            return Err(RuleError::UnknownCountry(country_code.to_string()));
        }

        self.country_rules.push((code_lower, outbound.into()));
        Ok(self)
    }

    /// Add a country rule using a mutable reference
    ///
    /// This is useful when adding rules in a loop.
    ///
    /// # Errors
    ///
    /// Returns `RuleError::UnknownCountry` if a catalog was loaded and the
    /// country code is not in the catalog.
    pub fn add_country_mut(
        &mut self,
        country_code: &str,
        outbound: impl Into<String>,
    ) -> Result<&mut Self, RuleError> {
        let code_lower = country_code.to_ascii_lowercase();

        // Validate against catalog if loaded
        if !self.catalog.is_empty() && !self.catalog.contains_key(&code_lower) {
            return Err(RuleError::UnknownCountry(country_code.to_string()));
        }

        self.country_rules.push((code_lower, outbound.into()));
        Ok(self)
    }

    /// Build the `GeoIpMatcher` from collected rules
    ///
    /// # Errors
    ///
    /// Returns `RuleError` if validation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::geoip::GeoIpMatcherBuilder;
    ///
    /// let matcher = GeoIpMatcherBuilder::new()
    ///     .add_cidr("192.168.0.0/16", "direct")
    ///     .unwrap()
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn build(self) -> Result<GeoIpMatcher, RuleError> {
        Ok(GeoIpMatcher {
            cidr_rules: self.cidr_rules,
            country_rules: self.country_rules,
            country_cidrs: RwLock::new(HashMap::new()),
            geoip_dir: self.geoip_dir,
            available_countries: self.catalog,
        })
    }

    /// Check if the builder has any rules
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cidr_rules.is_empty() && self.country_rules.is_empty()
    }

    /// Get the total number of rules added
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.cidr_rules.len() + self.country_rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    // Helper function to create test GeoIP files
    fn create_test_geoip_data() -> TempDir {
        let dir = TempDir::new().unwrap();

        // Create catalog
        let catalog = r#"{
            "version": 1,
            "total_countries": 3,
            "total_ipv4_ranges": 10,
            "total_ipv6_ranges": 2,
            "countries": [
                {"code": "us", "name": "United States", "display_name": "United States", "ipv4_count": 3, "ipv6_count": 1, "recommended_exit": "direct"},
                {"code": "cn", "name": "China", "display_name": "China", "ipv4_count": 3, "ipv6_count": 1, "recommended_exit": "proxy"},
                {"code": "de", "name": "Germany", "display_name": "Germany", "ipv4_count": 2, "ipv6_count": 0, "recommended_exit": "direct"}
            ]
        }"#;
        let catalog_path = dir.path().join("geoip-catalog.json");
        let mut file = fs::File::create(&catalog_path).unwrap();
        file.write_all(catalog.as_bytes()).unwrap();

        // Create US data
        let us_data = r#"{"code": "us", "name": "United States", "ipv4_ranges": ["8.0.0.0/8", "12.0.0.0/8", "15.0.0.0/8"], "ipv6_ranges": ["2001:4860::/32"]}"#;
        let us_path = dir.path().join("us.json");
        let mut file = fs::File::create(&us_path).unwrap();
        file.write_all(us_data.as_bytes()).unwrap();

        // Create CN data
        let cn_data = r#"{"code": "cn", "name": "China", "ipv4_ranges": ["1.0.0.0/8", "14.0.0.0/8", "27.0.0.0/8"], "ipv6_ranges": ["240e::/16"]}"#;
        let cn_path = dir.path().join("cn.json");
        let mut file = fs::File::create(&cn_path).unwrap();
        file.write_all(cn_data.as_bytes()).unwrap();

        // Create DE data
        let de_data = r#"{"code": "de", "name": "Germany", "ipv4_ranges": ["5.0.0.0/8", "31.0.0.0/8"], "ipv6_ranges": []}"#;
        let de_path = dir.path().join("de.json");
        let mut file = fs::File::create(&de_path).unwrap();
        file.write_all(de_data.as_bytes()).unwrap();

        dir
    }

    // ==================== Direct CIDR Tests ====================

    #[test]
    fn test_cidr_match_ipv4() {
        let matcher = GeoIpMatcher::builder()
            .add_cidr("192.168.0.0/16", "local")
            .unwrap()
            .add_cidr("10.0.0.0/8", "private")
            .unwrap()
            .build()
            .unwrap();

        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("local"));

        let ip: IpAddr = "192.168.255.255".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("local"));

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("private"));

        let ip: IpAddr = "10.255.255.255".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("private"));
    }

    #[test]
    fn test_cidr_match_ipv6() {
        let matcher = GeoIpMatcher::builder()
            .add_cidr("2001:db8::/32", "ipv6-local")
            .unwrap()
            .add_cidr("fe80::/10", "link-local")
            .unwrap()
            .build()
            .unwrap();

        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("ipv6-local"));

        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("link-local"));

        let ip: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), None);
    }

    #[test]
    fn test_cidr_match_no_match() {
        let matcher = GeoIpMatcher::builder()
            .add_cidr("192.168.0.0/16", "local")
            .unwrap()
            .build()
            .unwrap();

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), None);

        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), None);
    }

    #[test]
    fn test_cidr_match_order() {
        // More specific CIDR should be added first if we want it to match first
        let matcher = GeoIpMatcher::builder()
            .add_cidr("192.168.1.0/24", "specific")
            .unwrap()
            .add_cidr("192.168.0.0/16", "general")
            .unwrap()
            .build()
            .unwrap();

        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("specific"));

        let ip: IpAddr = "192.168.2.100".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("general"));
    }

    #[test]
    fn test_cidr_match_single_host() {
        let matcher = GeoIpMatcher::builder()
            .add_cidr("8.8.8.8/32", "google-dns")
            .unwrap()
            .build()
            .unwrap();

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("google-dns"));

        let ip: IpAddr = "8.8.8.9".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), None);
    }

    #[test]
    fn test_cidr_invalid() {
        let result = GeoIpMatcher::builder().add_cidr("not-a-cidr", "direct");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RuleError::InvalidCidr(_)));

        let result = GeoIpMatcher::builder().add_cidr("192.168.1.1/33", "direct");
        assert!(result.is_err());

        let result = GeoIpMatcher::builder().add_cidr("256.0.0.0/8", "direct");
        assert!(result.is_err());
    }

    // ==================== Country Match Tests ====================

    #[test]
    fn test_country_match() {
        let dir = create_test_geoip_data();

        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap()
            .add_country("us", "us-proxy")
            .unwrap()
            .add_country("cn", "cn-proxy")
            .unwrap()
            .build()
            .unwrap();

        // US IP (8.x.x.x)
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("us-proxy"));

        // CN IP (1.x.x.x)
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("cn-proxy"));

        // Unknown IP
        let ip: IpAddr = "100.0.0.1".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), None);
    }

    #[test]
    fn test_country_match_case_insensitive() {
        let dir = create_test_geoip_data();

        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap()
            .add_country("US", "us-proxy")
            .unwrap()
            .add_country("Cn", "cn-proxy")
            .unwrap()
            .build()
            .unwrap();

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("us-proxy"));
    }

    #[test]
    fn test_is_ip_in_country() {
        let dir = create_test_geoip_data();

        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap()
            .build()
            .unwrap();

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(matcher.is_ip_in_country(ip, "us"));
        assert!(matcher.is_ip_in_country(ip, "US"));
        assert!(!matcher.is_ip_in_country(ip, "cn"));

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(matcher.is_ip_in_country(ip, "cn"));
        assert!(!matcher.is_ip_in_country(ip, "us"));
    }

    #[test]
    fn test_unknown_country() {
        let dir = create_test_geoip_data();

        let result = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap()
            .add_country("xx", "unknown-proxy");

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RuleError::UnknownCountry(_)));
    }

    #[test]
    fn test_country_without_catalog() {
        let dir = create_test_geoip_data();

        // Without catalog, any country code is accepted
        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .add_country("us", "us-proxy")
            .unwrap()
            .add_country("cn", "cn-proxy")
            .unwrap()
            .build()
            .unwrap();

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("us-proxy"));
    }

    // ==================== Priority Tests ====================

    #[test]
    fn test_cidr_priority_over_country() {
        let dir = create_test_geoip_data();

        // Add CIDR rule for specific IP that would otherwise match US
        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap()
            .add_cidr("8.8.8.8/32", "google-dns")
            .unwrap()
            .add_country("us", "us-proxy")
            .unwrap()
            .build()
            .unwrap();

        // Specific CIDR should win
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("google-dns"));

        // Other US IPs should still match country
        let ip: IpAddr = "8.8.4.4".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("us-proxy"));
    }

    #[test]
    fn test_country_order() {
        let dir = create_test_geoip_data();

        // First country rule wins
        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap()
            .add_country("us", "first-proxy")
            .unwrap()
            .add_country("us", "second-proxy")
            .unwrap()
            .build()
            .unwrap();

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("first-proxy"));
    }

    // ==================== Lazy Loading Tests ====================

    #[test]
    fn test_lazy_loading() {
        let dir = create_test_geoip_data();

        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap()
            .add_country("us", "us-proxy")
            .unwrap()
            .add_country("cn", "cn-proxy")
            .unwrap()
            .build()
            .unwrap();

        // No countries loaded initially
        assert_eq!(matcher.loaded_country_count(), 0);

        // Match US IP - should load US data
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let _ = matcher.match_ip(ip);
        assert_eq!(matcher.loaded_country_count(), 1);

        // Match CN IP - should load CN data
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let _ = matcher.match_ip(ip);
        assert_eq!(matcher.loaded_country_count(), 2);
    }

    #[test]
    fn test_preload_countries() {
        let dir = create_test_geoip_data();

        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap()
            .build()
            .unwrap();

        // Preload specific countries
        matcher.preload_countries(&["us", "cn"]).unwrap();
        assert_eq!(matcher.loaded_country_count(), 2);

        // Preload unknown country should fail
        let result = matcher.preload_countries(&["xx"]);
        assert!(result.is_err());
    }

    // ==================== Catalog Tests ====================

    #[test]
    fn test_catalog_loading() {
        let dir = create_test_geoip_data();

        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(matcher.catalog_country_count(), 3);

        let us_info = matcher.get_country_info("us").unwrap();
        assert_eq!(us_info.name, "United States");
        assert_eq!(us_info.ipv4_count, 3);
        assert_eq!(us_info.recommended_exit, Some("direct".to_string()));

        let cn_info = matcher.get_country_info("CN").unwrap();
        assert_eq!(cn_info.name, "China");
        assert_eq!(cn_info.recommended_exit, Some("proxy".to_string()));
    }

    #[test]
    fn test_available_countries() {
        let dir = create_test_geoip_data();

        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap()
            .build()
            .unwrap();

        let countries = matcher.available_countries();
        assert_eq!(countries.len(), 3);

        let codes: Vec<&str> = countries.iter().map(|c| c.code.as_str()).collect();
        assert!(codes.contains(&"us"));
        assert!(codes.contains(&"cn"));
        assert!(codes.contains(&"de"));
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_matcher() {
        let matcher = GeoIpMatcher::empty();

        assert!(matcher.is_empty());
        assert_eq!(matcher.rule_count(), 0);

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), None);
    }

    #[test]
    fn test_localhost() {
        let matcher = GeoIpMatcher::builder()
            .add_cidr("127.0.0.0/8", "localhost")
            .unwrap()
            .build()
            .unwrap();

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("localhost"));
    }

    #[test]
    fn test_private_ranges() {
        let matcher = GeoIpMatcher::builder()
            .add_cidr("10.0.0.0/8", "private-a")
            .unwrap()
            .add_cidr("172.16.0.0/12", "private-b")
            .unwrap()
            .add_cidr("192.168.0.0/16", "private-c")
            .unwrap()
            .build()
            .unwrap();

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("private-a"));

        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("private-b"));

        let ip: IpAddr = "172.31.255.255".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("private-b"));

        let ip: IpAddr = "172.32.0.1".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), None);

        let ip: IpAddr = "192.168.0.1".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("private-c"));
    }

    #[test]
    fn test_geoip_not_configured() {
        let matcher = GeoIpMatcher::builder()
            .add_country("us", "us-proxy")
            .unwrap()
            .build()
            .unwrap();

        // Without geoip_dir, country matching should fail gracefully
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), None);
    }

    #[test]
    fn test_missing_country_file() {
        let dir = create_test_geoip_data();

        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            // Don't load catalog - allow any country code
            .add_country("fr", "fr-proxy")  // France file doesn't exist
            .unwrap()
            .build()
            .unwrap();

        // Should fail gracefully when file doesn't exist
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), None);
    }

    // ==================== Builder Tests ====================

    #[test]
    fn test_builder_is_empty() {
        let builder = GeoIpMatcherBuilder::new();
        assert!(builder.is_empty());
        assert_eq!(builder.rule_count(), 0);
    }

    #[test]
    fn test_builder_rule_count() {
        let builder = GeoIpMatcherBuilder::new()
            .add_cidr("192.168.0.0/16", "direct")
            .unwrap()
            .add_cidr("10.0.0.0/8", "direct")
            .unwrap();

        assert!(!builder.is_empty());
        assert_eq!(builder.rule_count(), 2);
    }

    #[test]
    fn test_builder_add_cidr_mut() {
        let mut builder = GeoIpMatcherBuilder::new();
        builder.add_cidr_mut("192.168.0.0/16", "direct").unwrap();
        builder.add_cidr_mut("10.0.0.0/8", "private").unwrap();

        assert_eq!(builder.rule_count(), 2);

        let matcher = builder.build().unwrap();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("direct"));
    }

    #[test]
    fn test_builder_add_country_mut() {
        let dir = create_test_geoip_data();

        let mut builder = GeoIpMatcherBuilder::new()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap();

        builder.add_country_mut("us", "us-proxy").unwrap();
        builder.add_country_mut("cn", "cn-proxy").unwrap();

        let matcher = builder.build().unwrap();
        assert_eq!(matcher.country_count(), 2);
    }

    // ==================== Count Tests ====================

    #[test]
    fn test_matcher_counts() {
        let dir = create_test_geoip_data();

        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap()
            .add_cidr("192.168.0.0/16", "direct")
            .unwrap()
            .add_cidr("10.0.0.0/8", "direct")
            .unwrap()
            .add_country("us", "us-proxy")
            .unwrap()
            .add_country("cn", "cn-proxy")
            .unwrap()
            .add_country("de", "de-proxy")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(matcher.cidr_count(), 2);
        assert_eq!(matcher.country_count(), 3);
        assert_eq!(matcher.rule_count(), 5);
        assert_eq!(matcher.catalog_country_count(), 3);
        assert!(!matcher.is_empty());
    }

    // ==================== Debug Trait Test ====================

    #[test]
    fn test_debug_impl() {
        let matcher = GeoIpMatcher::builder()
            .add_cidr("192.168.0.0/16", "direct")
            .unwrap()
            .build()
            .unwrap();

        let debug_str = format!("{:?}", matcher);
        assert!(debug_str.contains("GeoIpMatcher"));
        assert!(debug_str.contains("cidr_rules"));
    }

    #[test]
    fn test_builder_debug_impl() {
        let builder = GeoIpMatcherBuilder::new()
            .add_cidr("192.168.0.0/16", "direct")
            .unwrap();

        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("GeoIpMatcherBuilder"));
    }

    // ==================== IPv6 Country Tests ====================

    #[test]
    fn test_ipv6_country_match() {
        let dir = create_test_geoip_data();

        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap()
            .add_country("us", "us-proxy")
            .unwrap()
            .build()
            .unwrap();

        // US IPv6 range: 2001:4860::/32
        let ip: IpAddr = "2001:4860::1".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), Some("us-proxy"));

        // Non-US IPv6
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(matcher.match_ip(ip), None);
    }

    // ==================== Performance Test ====================

    #[test]
    fn test_performance_many_cidr_rules() {
        let mut builder = GeoIpMatcher::builder();

        // Add 250 CIDR rules
        for i in 0..250 {
            builder
                .add_cidr_mut(&format!("{i}.0.0.0/8"), "outbound")
                .unwrap();
        }

        let matcher = builder.build().unwrap();
        assert_eq!(matcher.cidr_count(), 250);

        // Benchmark lookups
        let start = std::time::Instant::now();
        for i in 0..10000 {
            let ip: IpAddr = format!("{}.1.1.1", i % 256).parse().unwrap();
            let _ = matcher.match_ip(ip);
        }
        let elapsed = start.elapsed();

        // Should complete in reasonable time
        assert!(
            elapsed.as_secs() < 1,
            "10K lookups took too long: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_performance_country_lookup() {
        let dir = create_test_geoip_data();

        let matcher = GeoIpMatcher::builder()
            .geoip_dir(dir.path())
            .load_catalog(dir.path().join("geoip-catalog.json"))
            .unwrap()
            .add_country("us", "us-proxy")
            .unwrap()
            .add_country("cn", "cn-proxy")
            .unwrap()
            .add_country("de", "de-proxy")
            .unwrap()
            .build()
            .unwrap();

        // Preload to avoid file I/O in benchmark
        matcher.preload_countries(&["us", "cn", "de"]).unwrap();

        let start = std::time::Instant::now();
        for _ in 0..10000 {
            let ip: IpAddr = "8.8.8.8".parse().unwrap();
            let _ = matcher.match_ip(ip);
            let ip: IpAddr = "1.2.3.4".parse().unwrap();
            let _ = matcher.match_ip(ip);
            let ip: IpAddr = "5.5.5.5".parse().unwrap();
            let _ = matcher.match_ip(ip);
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_secs() < 2,
            "30K country lookups took too long: {:?}",
            elapsed
        );
    }
}
