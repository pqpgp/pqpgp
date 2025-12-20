//! RPC server state types.

use crate::forum::persistence::PersistentForumState;
use crate::identity::RelayIdentity;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

// =============================================================================
// State Types
// =============================================================================

/// A registered user on the relay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisteredUser {
    pub name: String,
    pub fingerprint: String,
    pub prekey_bundle: String,
    pub registered_at: u64,
    pub last_seen: u64,
}

/// A message queued for delivery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueuedMessage {
    pub sender_fingerprint: String,
    pub encrypted_data: String,
    pub timestamp: u64,
    pub message_id: String,
}

/// Messaging relay state.
#[derive(Default)]
pub struct RelayState {
    pub users: HashMap<String, RegisteredUser>,
    pub messages: HashMap<String, VecDeque<QueuedMessage>>,
}

impl RelayState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Thread-safe relay state.
pub type SharedRelayState = Arc<RwLock<RelayState>>;

/// Thread-safe forum state.
pub type SharedForumState = Arc<RwLock<PersistentForumState>>;

/// Shared relay identity.
pub type SharedRelayIdentity = Arc<RelayIdentity>;

/// Combined application state.
#[derive(Clone)]
pub struct AppState {
    pub relay: SharedRelayState,
    pub forum: SharedForumState,
    pub identity: SharedRelayIdentity,
}

// =============================================================================
// RwLock Helpers
// =============================================================================

pub fn acquire_relay_read(state: &RwLock<RelayState>) -> RwLockReadGuard<'_, RelayState> {
    state.read().unwrap_or_else(|p| p.into_inner())
}

pub fn acquire_relay_write(state: &RwLock<RelayState>) -> RwLockWriteGuard<'_, RelayState> {
    state.write().unwrap_or_else(|p| p.into_inner())
}

pub fn acquire_forum_read(
    state: &RwLock<PersistentForumState>,
) -> RwLockReadGuard<'_, PersistentForumState> {
    state.read().unwrap_or_else(|p| p.into_inner())
}

pub fn acquire_forum_write(
    state: &RwLock<PersistentForumState>,
) -> RwLockWriteGuard<'_, PersistentForumState> {
    state.write().unwrap_or_else(|p| p.into_inner())
}
