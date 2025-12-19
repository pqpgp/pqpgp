//! Forum-related RPC handlers.

use super::{parse_params, to_json};
use crate::rpc::state::{acquire_forum_read, acquire_forum_write, SharedForumState};
use base64::Engine;
use pqpgp::forum::constants::{MAX_EXPORT_PAGE_SIZE, MAX_FETCH_BATCH_SIZE, MAX_NODES_PER_FORUM};
use pqpgp::forum::dag_ops::nodes_in_topological_order;
use pqpgp::forum::permissions::ForumPermissions;
use pqpgp::forum::rpc_client::{
    ExportParams, ExportResult, FetchParams, FetchResult, ForumInfo, NodeData, SubmitParams,
    SubmitResult, SyncParams, SyncResult,
};
use pqpgp::forum::sync::{DEFAULT_SYNC_BATCH_SIZE, MAX_SYNC_BATCH_SIZE};
use pqpgp::forum::types::current_timestamp_millis;
use pqpgp::forum::{
    validate_content_limits, validate_node, ContentHash, DagNode, ForumGenesis, ValidationContext,
};
use pqpgp::rpc::RpcError;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tracing::info;

pub fn handle_list(state: &SharedForumState) -> Result<Value, RpcError> {
    let relay = acquire_forum_read(state);

    let forums: Vec<ForumInfo> = relay
        .forums()
        .iter()
        .map(|(hash, forum)| ForumInfo {
            hash: hash.to_hex(),
            name: forum.name.clone(),
            description: forum.description.clone(),
            node_count: forum.node_count(),
            created_at: forum.created_at,
        })
        .collect();

    info!("forum.list: {} forums", forums.len());
    to_json(forums)
}

pub fn handle_sync(state: &SharedForumState, params: Value) -> Result<Value, RpcError> {
    let params: SyncParams = parse_params(params)?;

    let forum_hash = ContentHash::from_hex(&params.forum_hash)
        .map_err(|_| RpcError::invalid_params("Invalid forum hash"))?;

    // Parse cursor hash if provided
    let cursor_hash = params
        .cursor_hash
        .as_ref()
        .map(|h| ContentHash::from_hex(h))
        .transpose()
        .map_err(|_| RpcError::invalid_params("Invalid cursor hash"))?;

    // Apply batch size limits
    let batch_size = params
        .batch_size
        .unwrap_or(DEFAULT_SYNC_BATCH_SIZE)
        .min(MAX_SYNC_BATCH_SIZE);

    let relay = acquire_forum_read(state);

    let forum = relay
        .get_forum(&forum_hash)
        .ok_or_else(|| RpcError::not_found("Forum not found"))?;

    // Get nodes after cursor using timestamp index
    let (nodes, has_more) =
        forum.get_nodes_after_cursor(params.cursor_timestamp, cursor_hash.as_ref(), batch_size);

    // Serialize nodes for response
    let mut node_data = Vec::with_capacity(nodes.len());
    let mut next_cursor_timestamp = params.cursor_timestamp;
    let mut next_cursor_hash = None;

    for node in &nodes {
        if let Ok(data) = node.to_bytes() {
            node_data.push(NodeData {
                hash: node.hash().to_hex(),
                data: base64::engine::general_purpose::STANDARD.encode(&data),
            });
            // Update cursor to last node
            next_cursor_timestamp = node.created_at();
            next_cursor_hash = Some(node.hash().to_hex());
        }
    }

    info!(
        "forum.sync: {} returned {} nodes (cursor_ts={}, has_more={})",
        forum_hash.short(),
        node_data.len(),
        params.cursor_timestamp,
        has_more
    );

    let result = SyncResult {
        forum_hash: params.forum_hash,
        nodes: node_data,
        next_cursor_timestamp,
        next_cursor_hash,
        has_more,
        total_nodes: Some(forum.node_count()),
    };

    to_json(result)
}

pub fn handle_fetch(state: &SharedForumState, params: Value) -> Result<Value, RpcError> {
    let params: FetchParams = parse_params(params)?;

    if params.hashes.len() > MAX_FETCH_BATCH_SIZE {
        return Err(RpcError::invalid_params(format!(
            "Too many hashes (max {})",
            MAX_FETCH_BATCH_SIZE
        )));
    }

    let unique_hashes: HashSet<ContentHash> = params
        .hashes
        .iter()
        .filter_map(|h| ContentHash::from_hex(h).ok())
        .collect();

    let relay = acquire_forum_read(state);

    // Search for nodes directly in each forum's HashMap.
    // This is O(h * f) where h = requested hashes and f = number of forums.
    // Much more efficient than building a global index O(total_nodes) per request.
    let mut nodes = Vec::with_capacity(unique_hashes.len());
    let mut not_found = Vec::new();

    for hash in unique_hashes {
        let mut found = false;

        // Search each forum for this hash
        // Typically a fetch request targets nodes from a single forum,
        // so we'll usually find it in the first forum we check.
        for forum in relay.forums().values() {
            if let Some(node) = forum.nodes.get(&hash) {
                if let Ok(data) = node.to_bytes() {
                    nodes.push(NodeData {
                        hash: hash.to_hex(),
                        data: base64::engine::general_purpose::STANDARD.encode(&data),
                    });
                    found = true;
                    break;
                }
            }
        }

        if !found {
            not_found.push(hash.to_hex());
        }
    }

    info!(
        "forum.fetch: {} found, {} not found",
        nodes.len(),
        not_found.len()
    );

    let result = FetchResult { nodes, not_found };
    to_json(result)
}

pub fn handle_submit(state: &SharedForumState, params: Value) -> Result<Value, RpcError> {
    let params: SubmitParams = parse_params(params)?;

    let node_bytes = base64::engine::general_purpose::STANDARD
        .decode(&params.node_data)
        .map_err(|e| RpcError::invalid_params(format!("Invalid base64: {}", e)))?;

    let node = DagNode::from_bytes(&node_bytes)
        .map_err(|e| RpcError::invalid_params(format!("Invalid node: {}", e)))?;

    let node_hash = *node.hash();

    // Check content limits
    if let Some(error) = validate_content_limits(&node) {
        return Err(RpcError::validation_failed(vec![error]));
    }

    // Handle ForumGenesis specially
    if let DagNode::ForumGenesis(ref genesis) = node {
        return handle_genesis_submit(state, genesis.clone());
    }

    let forum_hash = ContentHash::from_hex(&params.forum_hash)
        .map_err(|_| RpcError::invalid_params("Invalid forum hash"))?;

    let mut relay = acquire_forum_write(state);

    // Validate against forum state
    let validation_result = {
        let forum = relay
            .get_forum(&forum_hash)
            .ok_or_else(|| RpcError::not_found("Forum not found"))?;

        if forum.node_count() >= MAX_NODES_PER_FORUM {
            return Err(RpcError::resource_exhausted(format!(
                "Forum at capacity ({} nodes)",
                MAX_NODES_PER_FORUM
            )));
        }

        // Build minimal permissions map for validation
        let permissions: HashMap<ContentHash, ForumPermissions> = forum
            .permissions
            .as_ref()
            .map(|p| std::iter::once((forum_hash, p.clone())).collect())
            .unwrap_or_default();

        let ctx = ValidationContext::new(&forum.nodes, &permissions, current_timestamp_millis());
        validate_node(&node, &ctx)
    };

    match validation_result {
        Ok(result) if !result.is_valid => {
            return Err(RpcError::validation_failed(result.errors));
        }
        Err(e) => {
            return Err(RpcError::validation_failed(vec![e.to_string()]));
        }
        _ => {}
    }

    relay
        .add_node(&forum_hash, node.clone())
        .map_err(RpcError::internal_error)?;

    info!(
        "forum.submit: accepted {} ({:?})",
        node_hash.short(),
        node.node_type()
    );

    let result = SubmitResult {
        accepted: true,
        hash: node_hash.to_hex(),
    };
    to_json(result)
}

fn handle_genesis_submit(
    state: &SharedForumState,
    genesis: ForumGenesis,
) -> Result<Value, RpcError> {
    let empty_nodes = HashMap::new();
    let empty_perms = HashMap::new();
    let ctx = ValidationContext::new(&empty_nodes, &empty_perms, current_timestamp_millis());

    match validate_node(&DagNode::from(genesis.clone()), &ctx) {
        Ok(result) if !result.is_valid => {
            return Err(RpcError::validation_failed(result.errors));
        }
        Err(e) => {
            return Err(RpcError::validation_failed(vec![e.to_string()]));
        }
        _ => {}
    }

    let mut relay = acquire_forum_write(state);
    let hash = relay
        .create_forum(genesis.clone())
        .map_err(RpcError::internal_error)?;

    info!(
        "forum.submit: created forum '{}' ({})",
        genesis.name(),
        hash.short()
    );

    let result = SubmitResult {
        accepted: true,
        hash: hash.to_hex(),
    };
    to_json(result)
}

pub fn handle_export(state: &SharedForumState, params: Value) -> Result<Value, RpcError> {
    let params: ExportParams = parse_params(params)?;

    let forum_hash = ContentHash::from_hex(&params.forum_hash)
        .map_err(|_| RpcError::invalid_params("Invalid forum hash"))?;

    let relay = acquire_forum_read(state);

    let forum = relay
        .get_forum(&forum_hash)
        .ok_or_else(|| RpcError::not_found("Forum not found"))?;

    let page = params.page.unwrap_or(0);
    let page_size = params
        .page_size
        .unwrap_or(MAX_EXPORT_PAGE_SIZE)
        .min(MAX_EXPORT_PAGE_SIZE);

    let skip = page.saturating_mul(page_size);

    let all_nodes: Vec<&DagNode> = nodes_in_topological_order(&forum.nodes);
    let total_nodes = all_nodes.len();

    let mut nodes = Vec::new();
    for node in all_nodes.into_iter().skip(skip).take(page_size) {
        if let Ok(data) = node.to_bytes() {
            nodes.push(NodeData {
                hash: node.hash().to_hex(),
                data: base64::engine::general_purpose::STANDARD.encode(&data),
            });
        }
    }

    let has_more = skip + nodes.len() < total_nodes;

    info!(
        "forum.export: {} page {} ({} nodes, has_more={})",
        forum_hash.short(),
        page,
        nodes.len(),
        has_more
    );

    let result = ExportResult {
        forum_hash: params.forum_hash,
        nodes,
        total_nodes,
        has_more,
    };
    to_json(result)
}
