//! VLESS account management
//!
//! This module provides UUID-based user account management for VLESS protocol.
//! Each account is identified by a 16-byte RFC 4122 UUID which serves as
//! the authentication credential.
//!
//! # Security Model
//!
//! VLESS uses UUID as the sole authentication mechanism. The UUID is transmitted
//! in plaintext in the request header, so transport-layer encryption (TLS/REALITY)
//! is essential for security.
//!
//! # Example
//!
//! ```
//! use rust_router::vless::{VlessAccount, VlessAccountManager};
//!
//! // Create an account manager
//! let mut manager = VlessAccountManager::new();
//!
//! // Add a user
//! let account = VlessAccount::new("admin@example.com");
//! manager.add_account(account.clone());
//!
//! // Authenticate a connection
//! let uuid_bytes = account.id_bytes();
//! assert!(manager.validate_uuid(&uuid_bytes).is_some());
//! ```

use std::collections::HashMap;
use std::fmt;

use uuid::Uuid;

use super::error::VlessError;

/// A VLESS user account
///
/// Each account has a UUID for authentication and an optional email
/// for identification/logging purposes.
#[derive(Clone)]
pub struct VlessAccount {
    /// UUID for authentication (16 bytes)
    id: Uuid,

    /// Optional email for user identification
    email: Option<String>,
}

impl VlessAccount {
    /// Create a new account with a random UUID
    ///
    /// # Arguments
    ///
    /// * `email` - Optional email address for user identification
    #[must_use]
    pub fn new(email: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            email: Some(email.into()),
        }
    }

    /// Create an account with a specific UUID
    ///
    /// # Arguments
    ///
    /// * `id` - The UUID to use for this account
    /// * `email` - Optional email address for user identification
    #[must_use]
    pub fn with_uuid(id: Uuid, email: Option<String>) -> Self {
        Self { id, email }
    }

    /// Create an account from a UUID string
    ///
    /// # Arguments
    ///
    /// * `uuid_str` - UUID in standard format (e.g., "550e8400-e29b-41d4-a716-446655440000")
    /// * `email` - Optional email address
    ///
    /// # Errors
    ///
    /// Returns `VlessError::InvalidUuid` if the string is not a valid UUID.
    pub fn from_uuid_str(uuid_str: &str, email: Option<String>) -> Result<Self, VlessError> {
        let id = Uuid::parse_str(uuid_str)
            .map_err(|e| VlessError::InvalidUuid(format!("{uuid_str}: {e}")))?;
        Ok(Self { id, email })
    }

    /// Create an account from raw UUID bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - 16-byte UUID
    /// * `email` - Optional email address
    ///
    /// # Errors
    ///
    /// Returns `VlessError::InvalidUuid` if the bytes are not valid.
    pub fn from_bytes(bytes: &[u8], email: Option<String>) -> Result<Self, VlessError> {
        if bytes.len() != 16 {
            return Err(VlessError::InvalidUuid(format!(
                "expected 16 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 16];
        arr.copy_from_slice(bytes);
        let id = Uuid::from_bytes(arr);

        Ok(Self { id, email })
    }

    /// Get the UUID
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// Get the UUID as raw bytes (16 bytes)
    #[must_use]
    pub fn id_bytes(&self) -> [u8; 16] {
        *self.id.as_bytes()
    }

    /// Get the email address (if set)
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Get the UUID as a hyphenated string
    #[must_use]
    pub fn id_string(&self) -> String {
        self.id.hyphenated().to_string()
    }
}

impl fmt::Debug for VlessAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessAccount")
            .field("id", &self.id_string())
            .field("email", &self.email)
            .finish()
    }
}

impl fmt::Display for VlessAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.email {
            Some(email) => write!(f, "VlessAccount({}, {})", self.id_string(), email),
            None => write!(f, "VlessAccount({})", self.id_string()),
        }
    }
}

impl PartialEq for VlessAccount {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for VlessAccount {}

impl std::hash::Hash for VlessAccount {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// VLESS account manager
///
/// Manages a collection of VLESS accounts and provides efficient
/// UUID-based lookup for authentication.
#[derive(Debug, Default)]
pub struct VlessAccountManager {
    /// Accounts indexed by UUID bytes
    accounts: HashMap<[u8; 16], VlessAccount>,
}

impl VlessAccountManager {
    /// Create an empty account manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }

    /// Create an account manager with initial capacity
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            accounts: HashMap::with_capacity(capacity),
        }
    }

    /// Add an account to the manager
    ///
    /// If an account with the same UUID already exists, it will be replaced.
    pub fn add_account(&mut self, account: VlessAccount) {
        self.accounts.insert(account.id_bytes(), account);
    }

    /// Remove an account by UUID
    ///
    /// Returns the removed account if it existed.
    pub fn remove_account(&mut self, id: &Uuid) -> Option<VlessAccount> {
        self.accounts.remove(id.as_bytes())
    }

    /// Remove an account by UUID bytes
    ///
    /// Returns the removed account if it existed.
    pub fn remove_by_bytes(&mut self, bytes: &[u8; 16]) -> Option<VlessAccount> {
        self.accounts.remove(bytes)
    }

    /// Validate a UUID and return the associated account
    ///
    /// This is the primary authentication method. It takes the raw UUID
    /// bytes from a VLESS request header and returns the account if valid.
    ///
    /// # Arguments
    ///
    /// * `uuid_bytes` - 16-byte UUID from the VLESS request header
    ///
    /// # Returns
    ///
    /// The account if the UUID is valid, or `None` if not found.
    #[must_use]
    pub fn validate_uuid(&self, uuid_bytes: &[u8; 16]) -> Option<&VlessAccount> {
        self.accounts.get(uuid_bytes)
    }

    /// Get an account by UUID
    #[must_use]
    pub fn get(&self, id: &Uuid) -> Option<&VlessAccount> {
        self.accounts.get(id.as_bytes())
    }

    /// Check if a UUID is registered
    #[must_use]
    pub fn contains(&self, id: &Uuid) -> bool {
        self.accounts.contains_key(id.as_bytes())
    }

    /// Check if UUID bytes are registered
    #[must_use]
    pub fn contains_bytes(&self, bytes: &[u8; 16]) -> bool {
        self.accounts.contains_key(bytes)
    }

    /// Get the number of registered accounts
    #[must_use]
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// Check if the manager has no accounts
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Iterate over all accounts
    pub fn iter(&self) -> impl Iterator<Item = &VlessAccount> {
        self.accounts.values()
    }

    /// Clear all accounts
    pub fn clear(&mut self) {
        self.accounts.clear();
    }
}

impl FromIterator<VlessAccount> for VlessAccountManager {
    fn from_iter<T: IntoIterator<Item = VlessAccount>>(iter: T) -> Self {
        let iter = iter.into_iter();
        let (lower, upper) = iter.size_hint();
        let capacity = upper.unwrap_or(lower);
        let mut manager = Self::with_capacity(capacity);
        for account in iter {
            manager.add_account(account);
        }
        manager
    }
}

impl Extend<VlessAccount> for VlessAccountManager {
    fn extend<T: IntoIterator<Item = VlessAccount>>(&mut self, iter: T) {
        for account in iter {
            self.add_account(account);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_creation() {
        let account = VlessAccount::new("test@example.com");
        assert!(account.email().is_some());
        assert_eq!(account.email().unwrap(), "test@example.com");
        assert_eq!(account.id_bytes().len(), 16);
    }

    #[test]
    fn test_account_with_uuid() {
        let uuid = Uuid::new_v4();
        let account = VlessAccount::with_uuid(uuid, Some("admin".to_string()));
        assert_eq!(account.id(), uuid);
        assert_eq!(account.email(), Some("admin"));
    }

    #[test]
    fn test_account_from_uuid_str() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let account = VlessAccount::from_uuid_str(uuid_str, None).unwrap();
        assert_eq!(account.id_string(), uuid_str);
        assert!(account.email().is_none());
    }

    #[test]
    fn test_account_from_invalid_uuid_str() {
        let result = VlessAccount::from_uuid_str("not-a-uuid", None);
        assert!(result.is_err());
        match result {
            Err(VlessError::InvalidUuid(msg)) => {
                assert!(msg.contains("not-a-uuid"));
            }
            _ => panic!("Expected InvalidUuid error"),
        }
    }

    #[test]
    fn test_account_from_bytes() {
        let bytes = [0u8; 16];
        let account = VlessAccount::from_bytes(&bytes, Some("zero".to_string())).unwrap();
        assert_eq!(account.id_bytes(), bytes);
    }

    #[test]
    fn test_account_from_invalid_bytes() {
        let bytes = [0u8; 15]; // Wrong length
        let result = VlessAccount::from_bytes(&bytes, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_account_display() {
        let account = VlessAccount::new("user@example.com");
        let display = account.to_string();
        assert!(display.contains("VlessAccount"));
        assert!(display.contains("user@example.com"));
    }

    #[test]
    fn test_account_debug() {
        let account = VlessAccount::new("debug@test.com");
        let debug = format!("{:?}", account);
        assert!(debug.contains("VlessAccount"));
        assert!(debug.contains("debug@test.com"));
    }

    #[test]
    fn test_account_equality() {
        let uuid = Uuid::new_v4();
        let account1 = VlessAccount::with_uuid(uuid, Some("email1".to_string()));
        let account2 = VlessAccount::with_uuid(uuid, Some("email2".to_string()));
        let account3 = VlessAccount::new("email3");

        // Same UUID = equal (email is not considered)
        assert_eq!(account1, account2);
        // Different UUID = not equal
        assert_ne!(account1, account3);
    }

    #[test]
    fn test_account_hash() {
        use std::collections::HashSet;

        let uuid = Uuid::new_v4();
        let account1 = VlessAccount::with_uuid(uuid, None);
        let account2 = VlessAccount::with_uuid(uuid, Some("email".to_string()));

        let mut set = HashSet::new();
        set.insert(account1);
        // Same UUID should not be inserted again
        assert!(!set.insert(account2));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_manager_creation() {
        let manager = VlessAccountManager::new();
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_manager_add_account() {
        let mut manager = VlessAccountManager::new();
        let account = VlessAccount::new("test@example.com");
        let uuid = account.id();

        manager.add_account(account);
        assert_eq!(manager.len(), 1);
        assert!(manager.contains(&uuid));
    }

    #[test]
    fn test_manager_validate_uuid() {
        let mut manager = VlessAccountManager::new();
        let account = VlessAccount::new("auth@example.com");
        let uuid_bytes = account.id_bytes();

        manager.add_account(account);

        // Valid UUID
        let result = manager.validate_uuid(&uuid_bytes);
        assert!(result.is_some());
        assert_eq!(result.unwrap().email(), Some("auth@example.com"));

        // Invalid UUID
        let invalid = [0xFFu8; 16];
        assert!(manager.validate_uuid(&invalid).is_none());
    }

    #[test]
    fn test_manager_remove_account() {
        let mut manager = VlessAccountManager::new();
        let account = VlessAccount::new("remove@example.com");
        let uuid = account.id();

        manager.add_account(account);
        assert_eq!(manager.len(), 1);

        let removed = manager.remove_account(&uuid);
        assert!(removed.is_some());
        assert_eq!(manager.len(), 0);
        assert!(!manager.contains(&uuid));
    }

    #[test]
    fn test_manager_remove_by_bytes() {
        let mut manager = VlessAccountManager::new();
        let account = VlessAccount::new("bytes@example.com");
        let bytes = account.id_bytes();

        manager.add_account(account);
        assert!(manager.contains_bytes(&bytes));

        let removed = manager.remove_by_bytes(&bytes);
        assert!(removed.is_some());
        assert!(!manager.contains_bytes(&bytes));
    }

    #[test]
    fn test_manager_replace_account() {
        let mut manager = VlessAccountManager::new();
        let uuid = Uuid::new_v4();

        let account1 = VlessAccount::with_uuid(uuid, Some("first".to_string()));
        let account2 = VlessAccount::with_uuid(uuid, Some("second".to_string()));

        manager.add_account(account1);
        assert_eq!(manager.get(&uuid).unwrap().email(), Some("first"));

        manager.add_account(account2);
        assert_eq!(manager.len(), 1); // Still only one account
        assert_eq!(manager.get(&uuid).unwrap().email(), Some("second"));
    }

    #[test]
    fn test_manager_iter() {
        let mut manager = VlessAccountManager::new();
        manager.add_account(VlessAccount::new("one@example.com"));
        manager.add_account(VlessAccount::new("two@example.com"));
        manager.add_account(VlessAccount::new("three@example.com"));

        let emails: Vec<_> = manager.iter().filter_map(|a| a.email()).collect();
        assert_eq!(emails.len(), 3);
    }

    #[test]
    fn test_manager_clear() {
        let mut manager = VlessAccountManager::new();
        manager.add_account(VlessAccount::new("clear@example.com"));
        manager.add_account(VlessAccount::new("also@example.com"));
        assert_eq!(manager.len(), 2);

        manager.clear();
        assert!(manager.is_empty());
    }

    #[test]
    fn test_manager_from_iter() {
        let accounts = vec![
            VlessAccount::new("iter1@example.com"),
            VlessAccount::new("iter2@example.com"),
        ];

        let manager: VlessAccountManager = accounts.into_iter().collect();
        assert_eq!(manager.len(), 2);
    }

    #[test]
    fn test_manager_extend() {
        let mut manager = VlessAccountManager::new();
        manager.add_account(VlessAccount::new("base@example.com"));

        let more_accounts = vec![
            VlessAccount::new("ext1@example.com"),
            VlessAccount::new("ext2@example.com"),
        ];

        manager.extend(more_accounts);
        assert_eq!(manager.len(), 3);
    }

    #[test]
    fn test_manager_with_capacity() {
        let manager = VlessAccountManager::with_capacity(100);
        assert!(manager.is_empty());
        // Capacity is internal, just verify it doesn't panic
    }
}
