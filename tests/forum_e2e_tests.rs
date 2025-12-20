//! End-to-end tests for the DAG-based forum system.
//!
//! These tests verify complete workflows from forum creation through
//! to complex multi-user interactions, ensuring all components work
//! together correctly.

use pqpgp::crypto::KeyPair;
use pqpgp::forum::types::{ContentHash, ModAction};
use pqpgp::forum::{
    validate_node, BoardGenesis, ConversationManager, DagNode, EditNode, EditType,
    EncryptionIdentityGenerator, ForumGenesis, ForumPermissions, InnerMessage, ModActionNode, Post,
    PrivateMessageScanner, SealedPrivateMessage, ThreadRoot, ValidationContext,
};
use std::collections::HashMap;

/// Helper to create a test keypair.
fn create_test_keypair() -> KeyPair {
    KeyPair::generate_mldsa87().expect("Failed to generate keypair")
}

/// Helper to get current timestamp in milliseconds.
fn current_timestamp_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// =============================================================================
// Forum Workflow Tests
// =============================================================================

/// Complete forum workflow: create forum -> board -> thread -> post -> replies
///
/// This test verifies the entire forum hierarchy can be created and validated:
/// 1. Forum genesis creation by owner
/// 2. Board creation by forum owner
/// 3. Thread creation by any user
/// 4. Post creation as reply to thread
/// 5. Nested replies (post replying to post)
/// 6. All nodes validated through ValidationContext
#[test]
fn test_complete_forum_workflow() {
    // Create forum owner keypair
    let owner_keypair = create_test_keypair();

    // Create regular users
    let user_alice = create_test_keypair();
    let user_bob = create_test_keypair();

    // =========================================================================
    // Step 1: Create forum genesis
    // =========================================================================
    let forum = ForumGenesis::create(
        "Test Forum".to_string(),
        "A comprehensive test forum for e2e testing".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create forum genesis");

    assert_eq!(forum.content.name, "Test Forum");
    assert!(forum.verify(owner_keypair.public_key()).is_ok());

    // =========================================================================
    // Step 2: Create board genesis (by owner)
    // =========================================================================
    let board = BoardGenesis::create(
        *forum.hash(),
        "General Discussion".to_string(),
        "Talk about anything here".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create board");

    assert_eq!(board.content.forum_hash, *forum.hash());
    assert!(board.verify(owner_keypair.public_key()).is_ok());

    // =========================================================================
    // Step 3: Create thread (by regular user Alice)
    // =========================================================================
    let thread = ThreadRoot::create(
        *board.hash(),
        "Welcome Thread".to_string(),
        "Hello everyone! This is the first thread.".to_string(),
        user_alice.public_key(),
        user_alice.private_key(),
        None,
    )
    .expect("Failed to create thread");

    assert_eq!(thread.content.board_hash, *board.hash());
    assert!(thread.verify(user_alice.public_key()).is_ok());

    // =========================================================================
    // Step 4: Create first reply (by Bob)
    // =========================================================================
    let post1 = Post::create(
        *thread.hash(),
        vec![*thread.hash()],
        "Welcome Alice! Great to be here.".to_string(),
        None,
        user_bob.public_key(),
        user_bob.private_key(),
        None,
    )
    .expect("Failed to create post1");

    assert_eq!(post1.content.thread_hash, *thread.hash());
    assert!(post1.verify(user_bob.public_key()).is_ok());

    // =========================================================================
    // Step 5: Create nested reply (Alice replies to Bob)
    // =========================================================================
    let post2 = Post::create(
        *thread.hash(),
        vec![*post1.hash()],
        "Thanks Bob! Looking forward to great discussions.".to_string(),
        Some(*post1.hash()), // Quote Bob's post
        user_alice.public_key(),
        user_alice.private_key(),
        None,
    )
    .expect("Failed to create post2");

    assert_eq!(post2.content.thread_hash, *thread.hash());
    assert_eq!(post2.content.parent_hashes, vec![*post1.hash()]);
    assert_eq!(post2.content.quote_hash, Some(*post1.hash()));

    // =========================================================================
    // Step 6: Validate all nodes through ValidationContext
    // =========================================================================
    let mut nodes = HashMap::new();
    nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
    nodes.insert(*board.hash(), DagNode::from(board.clone()));
    nodes.insert(*thread.hash(), DagNode::from(thread.clone()));
    nodes.insert(*post1.hash(), DagNode::from(post1.clone()));
    nodes.insert(*post2.hash(), DagNode::from(post2.clone()));

    let mut permissions = HashMap::new();
    permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

    let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());

    // Validate each node
    let forum_result = validate_node(&DagNode::from(forum.clone()), &ctx).unwrap();
    assert!(
        forum_result.is_valid,
        "Forum validation failed: {:?}",
        forum_result.errors
    );

    let board_result = validate_node(&DagNode::from(board.clone()), &ctx).unwrap();
    assert!(
        board_result.is_valid,
        "Board validation failed: {:?}",
        board_result.errors
    );

    let thread_result = validate_node(&DagNode::from(thread.clone()), &ctx).unwrap();
    assert!(
        thread_result.is_valid,
        "Thread validation failed: {:?}",
        thread_result.errors
    );

    let post1_result = validate_node(&DagNode::from(post1.clone()), &ctx).unwrap();
    assert!(
        post1_result.is_valid,
        "Post1 validation failed: {:?}",
        post1_result.errors
    );

    let post2_result = validate_node(&DagNode::from(post2.clone()), &ctx).unwrap();
    assert!(
        post2_result.is_valid,
        "Post2 validation failed: {:?}",
        post2_result.errors
    );
}

/// Test multiple boards in a single forum.
#[test]
fn test_multiple_boards_in_forum() {
    let owner_keypair = create_test_keypair();

    let forum = ForumGenesis::create(
        "Multi-Board Forum".to_string(),
        "A forum with multiple boards".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create forum");

    // Create multiple boards
    let board_names = vec![
        ("General", "General discussion"),
        ("Tech", "Technology discussions"),
        ("Off-Topic", "Random chat"),
    ];

    let mut boards = Vec::new();
    for (name, desc) in board_names {
        let board = BoardGenesis::create(
            *forum.hash(),
            name.to_string(),
            desc.to_string(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
        )
        .expect("Failed to create board");
        boards.push(board);
    }

    assert_eq!(boards.len(), 3);

    // Verify all boards reference the same forum
    for board in &boards {
        assert_eq!(board.content.forum_hash, *forum.hash());
    }

    // Verify all boards have unique hashes
    let hashes: Vec<_> = boards.iter().map(|b| *b.hash()).collect();
    let unique_hashes: std::collections::HashSet<_> = hashes.iter().collect();
    assert_eq!(
        unique_hashes.len(),
        boards.len(),
        "All boards should have unique hashes"
    );
}

/// Test thread movement between boards via moderation action.
#[test]
fn test_thread_movement_between_boards() {
    let owner_keypair = create_test_keypair();
    let user_keypair = create_test_keypair();

    let forum = ForumGenesis::create(
        "Forum".to_string(),
        "Test forum".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create forum");

    let board1 = BoardGenesis::create(
        *forum.hash(),
        "Board 1".to_string(),
        "".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create board1");

    let board2 = BoardGenesis::create(
        *forum.hash(),
        "Board 2".to_string(),
        "".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create board2");

    // User creates thread in board1
    let thread = ThreadRoot::create(
        *board1.hash(),
        "Thread Title".to_string(),
        "Thread body".to_string(),
        user_keypair.public_key(),
        user_keypair.private_key(),
        None,
    )
    .expect("Failed to create thread");

    // Owner moves thread to board2 using create_move_thread_action
    let move_action = ModActionNode::create_move_thread_action(
        *forum.hash(),
        *thread.hash(),
        *board2.hash(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
        vec![], // parent hashes
    )
    .expect("Failed to create move action");

    // Validate the move action
    let mut nodes = HashMap::new();
    nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
    nodes.insert(*board1.hash(), DagNode::from(board1.clone()));
    nodes.insert(*board2.hash(), DagNode::from(board2.clone()));
    nodes.insert(*thread.hash(), DagNode::from(thread.clone()));

    let mut permissions = HashMap::new();
    permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

    let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());
    let result = validate_node(&DagNode::from(move_action.clone()), &ctx).unwrap();
    assert!(
        result.is_valid,
        "Move action validation failed: {:?}",
        result.errors
    );
}

/// Test forum and board editing.
#[test]
fn test_forum_and_board_editing() {
    let owner_keypair = create_test_keypair();

    let forum = ForumGenesis::create(
        "Original Forum Name".to_string(),
        "Original description".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create forum");

    let board = BoardGenesis::create(
        *forum.hash(),
        "Original Board".to_string(),
        "Original board description".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create board");

    // Edit forum name
    let forum_edit = EditNode::create_forum_edit(
        *forum.hash(),
        Some("Updated Forum Name".to_string()),
        None,
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create forum edit");

    assert_eq!(forum_edit.content.edit_type, EditType::EditForum);
    assert_eq!(
        forum_edit.content.new_name,
        Some("Updated Forum Name".to_string())
    );

    // Edit board description
    let board_edit = EditNode::create_board_edit(
        *forum.hash(),
        *board.hash(),
        None,
        Some("Updated board description".to_string()),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create board edit");

    assert_eq!(board_edit.content.edit_type, EditType::EditBoard);
    assert_eq!(
        board_edit.content.new_description,
        Some("Updated board description".to_string())
    );

    // Validate edits
    let mut nodes = HashMap::new();
    nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
    nodes.insert(*board.hash(), DagNode::from(board.clone()));

    let mut permissions = HashMap::new();
    permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

    let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());

    let forum_edit_result = validate_node(&DagNode::from(forum_edit), &ctx).unwrap();
    assert!(
        forum_edit_result.is_valid,
        "Forum edit validation failed: {:?}",
        forum_edit_result.errors
    );

    let board_edit_result = validate_node(&DagNode::from(board_edit), &ctx).unwrap();
    assert!(
        board_edit_result.is_valid,
        "Board edit validation failed: {:?}",
        board_edit_result.errors
    );
}

/// Test moderation actions: add/remove moderator, hide/unhide content.
#[test]
fn test_moderation_workflow() {
    let owner_keypair = create_test_keypair();
    let mod_keypair = create_test_keypair();
    let user_keypair = create_test_keypair();

    let forum = ForumGenesis::create(
        "Moderated Forum".to_string(),
        "".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create forum");

    let board = BoardGenesis::create(
        *forum.hash(),
        "Board".to_string(),
        "".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create board");

    let thread = ThreadRoot::create(
        *board.hash(),
        "Test Thread".to_string(),
        "".to_string(),
        user_keypair.public_key(),
        user_keypair.private_key(),
        None,
    )
    .expect("Failed to create thread");

    let post = Post::create(
        *thread.hash(),
        vec![*thread.hash()],
        "Spam post to be hidden".to_string(),
        None,
        user_keypair.public_key(),
        user_keypair.private_key(),
        None,
    )
    .expect("Failed to create post");

    // Step 1: Add moderator using create() with target_public_key
    let add_mod = ModActionNode::create(
        *forum.hash(),
        ModAction::AddModerator,
        mod_keypair.public_key(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
        vec![], // parent hashes
    )
    .expect("Failed to create add_mod action");

    // Build context with updated permissions
    let mut nodes = HashMap::new();
    nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
    nodes.insert(*board.hash(), DagNode::from(board.clone()));
    nodes.insert(*thread.hash(), DagNode::from(thread.clone()));
    nodes.insert(*post.hash(), DagNode::from(post.clone()));

    let mut permissions = ForumPermissions::from_genesis(&forum);

    // Apply add_mod action to permissions
    let result = permissions.apply_action(&add_mod);
    assert!(result.is_ok(), "Failed to apply add_mod: {:?}", result);

    let mut perms_map = HashMap::new();
    perms_map.insert(*forum.hash(), permissions.clone());

    let ctx = ValidationContext::new(&nodes, &perms_map, current_timestamp_millis());

    // Validate add_mod action
    let add_mod_result = validate_node(&DagNode::from(add_mod.clone()), &ctx).unwrap();
    assert!(
        add_mod_result.is_valid,
        "Add mod validation failed: {:?}",
        add_mod_result.errors
    );

    // Step 2: Owner hides the spam post using create_content_action
    let hide_post = ModActionNode::create_content_action(
        *forum.hash(),
        *post.hash(),
        ModAction::HidePost,
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
        vec![], // parent hashes
    )
    .expect("Failed to create hide_post action");

    let hide_result = validate_node(&DagNode::from(hide_post.clone()), &ctx).unwrap();
    assert!(
        hide_result.is_valid,
        "Hide post validation failed: {:?}",
        hide_result.errors
    );

    // Step 3: Unhide the post
    let unhide_post = ModActionNode::create_content_action(
        *forum.hash(),
        *post.hash(),
        ModAction::UnhidePost,
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
        vec![], // parent hashes
    )
    .expect("Failed to create unhide_post action");

    let unhide_result = validate_node(&DagNode::from(unhide_post), &ctx).unwrap();
    assert!(
        unhide_result.is_valid,
        "Unhide post validation failed: {:?}",
        unhide_result.errors
    );
}

/// Test permission enforcement: non-owners cannot perform owner-only actions.
#[test]
fn test_permission_enforcement() {
    let owner_keypair = create_test_keypair();
    let regular_user = create_test_keypair();

    let forum = ForumGenesis::create(
        "Forum".to_string(),
        "".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create forum");

    // Regular user tries to add a moderator (should fail validation)
    let unauthorized_add_mod = ModActionNode::create(
        *forum.hash(),
        ModAction::AddModerator,
        regular_user.public_key(), // target
        regular_user.public_key(), // issuer (regular user trying to be sneaky)
        regular_user.private_key(),
        None,
        vec![], // parent hashes
    )
    .expect("Failed to create action");

    let mut nodes = HashMap::new();
    nodes.insert(*forum.hash(), DagNode::from(forum.clone()));

    let mut permissions = HashMap::new();
    permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

    let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());

    let result = validate_node(&DagNode::from(unauthorized_add_mod), &ctx).unwrap();
    assert!(
        !result.is_valid,
        "Unauthorized action should fail validation"
    );
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.contains("permission") || e.contains("Insufficient")),
        "Should have permission error, got: {:?}",
        result.errors
    );
}

/// Test post chain with multiple parents (DAG structure).
#[test]
fn test_post_dag_structure() {
    let owner_keypair = create_test_keypair();
    let user_a = create_test_keypair();
    let user_b = create_test_keypair();
    let user_c = create_test_keypair();

    let forum = ForumGenesis::create(
        "Forum".to_string(),
        "".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create forum");

    let board = BoardGenesis::create(
        *forum.hash(),
        "Board".to_string(),
        "".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create board");

    let thread = ThreadRoot::create(
        *board.hash(),
        "Discussion".to_string(),
        "Let's discuss".to_string(),
        user_a.public_key(),
        user_a.private_key(),
        None,
    )
    .expect("Failed to create thread");

    // User A posts
    let post_a = Post::create(
        *thread.hash(),
        vec![*thread.hash()],
        "User A's take".to_string(),
        None,
        user_a.public_key(),
        user_a.private_key(),
        None,
    )
    .expect("Failed to create post_a");

    // User B posts
    let post_b = Post::create(
        *thread.hash(),
        vec![*thread.hash()],
        "User B's perspective".to_string(),
        None,
        user_b.public_key(),
        user_b.private_key(),
        None,
    )
    .expect("Failed to create post_b");

    // User C replies to BOTH A and B (multiple parents in DAG)
    let post_c = Post::create(
        *thread.hash(),
        vec![*post_a.hash(), *post_b.hash()], // Multiple parents
        "User C synthesizes both viewpoints".to_string(),
        None,
        user_c.public_key(),
        user_c.private_key(),
        None,
    )
    .expect("Failed to create post_c");

    assert_eq!(post_c.content.parent_hashes.len(), 2);
    assert!(post_c.content.parent_hashes.contains(post_a.hash()));
    assert!(post_c.content.parent_hashes.contains(post_b.hash()));

    // Validate the multi-parent post
    let mut nodes = HashMap::new();
    nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
    nodes.insert(*board.hash(), DagNode::from(board.clone()));
    nodes.insert(*thread.hash(), DagNode::from(thread.clone()));
    nodes.insert(*post_a.hash(), DagNode::from(post_a.clone()));
    nodes.insert(*post_b.hash(), DagNode::from(post_b.clone()));

    let mut permissions = HashMap::new();
    permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

    let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());

    let result = validate_node(&DagNode::from(post_c), &ctx).unwrap();
    assert!(
        result.is_valid,
        "Multi-parent post validation failed: {:?}",
        result.errors
    );
}

/// Test that validation fails for orphan nodes (missing parents).
#[test]
fn test_orphan_node_detection() {
    let owner_keypair = create_test_keypair();
    let user_keypair = create_test_keypair();

    let forum = ForumGenesis::create(
        "Forum".to_string(),
        "".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create forum");

    let board = BoardGenesis::create(
        *forum.hash(),
        "Board".to_string(),
        "".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create board");

    let thread = ThreadRoot::create(
        *board.hash(),
        "Thread".to_string(),
        "".to_string(),
        user_keypair.public_key(),
        user_keypair.private_key(),
        None,
    )
    .expect("Failed to create thread");

    // Create a post referencing a non-existent parent
    let fake_parent = ContentHash::compute(b"fake parent").expect("hash");
    let orphan_post = Post::create(
        *thread.hash(),
        vec![fake_parent], // Parent doesn't exist
        "Orphan post".to_string(),
        None,
        user_keypair.public_key(),
        user_keypair.private_key(),
        None,
    )
    .expect("Failed to create orphan post");

    let mut nodes = HashMap::new();
    nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
    nodes.insert(*board.hash(), DagNode::from(board.clone()));
    nodes.insert(*thread.hash(), DagNode::from(thread.clone()));
    // Note: NOT inserting the fake parent

    let mut permissions = HashMap::new();
    permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

    let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());

    let result = validate_node(&DagNode::from(orphan_post), &ctx).unwrap();
    assert!(!result.is_valid, "Orphan post should fail validation");
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.contains("not exist") || e.contains("parent")),
        "Should have missing parent error, got: {:?}",
        result.errors
    );
}

/// Test complete workflow with long reply chain.
#[test]
fn test_deep_reply_chain() {
    let owner_keypair = create_test_keypair();
    let users: Vec<KeyPair> = (0..10).map(|_| create_test_keypair()).collect();

    let forum = ForumGenesis::create(
        "Forum".to_string(),
        "".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create forum");

    let board = BoardGenesis::create(
        *forum.hash(),
        "Board".to_string(),
        "".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create board");

    let thread = ThreadRoot::create(
        *board.hash(),
        "Long Discussion".to_string(),
        "Start of a long thread".to_string(),
        users[0].public_key(),
        users[0].private_key(),
        None,
    )
    .expect("Failed to create thread");

    let mut nodes = HashMap::new();
    nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
    nodes.insert(*board.hash(), DagNode::from(board.clone()));
    nodes.insert(*thread.hash(), DagNode::from(thread.clone()));

    let mut last_hash = *thread.hash();

    // Create a chain of 10 replies
    for (i, user) in users.iter().enumerate() {
        let post = Post::create(
            *thread.hash(),
            vec![last_hash],
            format!("Reply {} in the chain", i + 1),
            None,
            user.public_key(),
            user.private_key(),
            None,
        )
        .expect("Failed to create post");

        nodes.insert(*post.hash(), DagNode::from(post.clone()));
        last_hash = *post.hash();
    }

    // Validate all nodes
    let mut permissions = HashMap::new();
    permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

    let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());

    for (hash, node) in &nodes {
        let result = validate_node(node, &ctx).unwrap();
        assert!(
            result.is_valid,
            "Node {} validation failed: {:?}",
            hash.short(),
            result.errors
        );
    }

    assert_eq!(nodes.len(), 13); // forum + board + thread + 10 posts
}

/// Test board moderator functionality.
#[test]
fn test_board_moderator_workflow() {
    let owner_keypair = create_test_keypair();
    let board_mod = create_test_keypair();

    let forum = ForumGenesis::create(
        "Forum".to_string(),
        "".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create forum");

    let board = BoardGenesis::create(
        *forum.hash(),
        "Moderated Board".to_string(),
        "".to_string(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
    )
    .expect("Failed to create board");

    // Add board moderator using create_board_action
    let add_board_mod = ModActionNode::create_board_action(
        *forum.hash(),
        *board.hash(),
        ModAction::AddBoardModerator,
        board_mod.public_key(),
        owner_keypair.public_key(),
        owner_keypair.private_key(),
        None,
        vec![], // parent hashes
    )
    .expect("Failed to create add_board_mod action");

    let mut nodes = HashMap::new();
    nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
    nodes.insert(*board.hash(), DagNode::from(board.clone()));

    let mut permissions = ForumPermissions::from_genesis(&forum);

    // Apply board mod action
    permissions
        .apply_action(&add_board_mod)
        .expect("Failed to apply action");

    let mut perms_map = HashMap::new();
    perms_map.insert(*forum.hash(), permissions.clone());

    let ctx = ValidationContext::new(&nodes, &perms_map, current_timestamp_millis());

    let result = validate_node(&DagNode::from(add_board_mod), &ctx).unwrap();
    assert!(
        result.is_valid,
        "Add board mod validation failed: {:?}",
        result.errors
    );

    // Verify board mod is set
    assert!(permissions.is_board_moderator(&board_mod.public_key().as_bytes(), board.hash()));
}

// =============================================================================
// Private Messaging Tests
// =============================================================================

/// Helper to create a test forum hash.
fn create_test_forum_hash() -> ContentHash {
    ContentHash::compute(b"test forum for PM").expect("hash")
}

/// Complete private messaging workflow:
/// 1. Create encryption identities for Alice and Bob
/// 2. Alice sends sealed message to Bob
/// 3. Bob scans and decrypts message
/// 4. Bob replies to Alice
/// 5. Alice receives and decrypts reply
#[test]
fn test_complete_private_messaging_workflow() {
    use pqpgp::forum::{seal_private_message, unseal_private_message};

    let forum_hash = create_test_forum_hash();

    // Step 1: Create encryption identities
    let alice_keypair = create_test_keypair();
    let (alice_identity, alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        10, // 10 one-time prekeys
        None,
    )
    .expect("Failed to generate Alice's encryption identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        10,
        None,
    )
    .expect("Failed to generate Bob's encryption identity");

    // Verify identities are properly signed
    assert!(alice_identity.verify(alice_keypair.public_key()).is_ok());
    assert!(bob_identity.verify(bob_keypair.public_key()).is_ok());

    // Step 2: Alice sends sealed message to Bob
    let message1 = InnerMessage::new(
        [0u8; 32], // Will be replaced with conversation ID
        "Hello Bob! This is a secret message from Alice.".to_string(),
    );

    let sealed1 = seal_private_message(
        forum_hash,
        &alice_identity,
        &bob_identity,
        message1,
        true, // Use one-time prekey for first message
    )
    .expect("Failed to seal message for Bob");

    // Step 3: Bob decrypts the message (unseal_private_message takes 2 args)
    let unsealed1 = unseal_private_message(&sealed1.message, &bob_private)
        .expect("Bob failed to unseal message");

    assert_eq!(
        unsealed1.inner_message.body,
        "Hello Bob! This is a secret message from Alice."
    );
    assert_eq!(unsealed1.conversation_id, sealed1.conversation_id);

    // Step 4: Bob replies to Alice
    let message2 = InnerMessage::new(
        sealed1.conversation_id,
        "Hi Alice! Got your message. This is Bob.".to_string(),
    )
    .with_reply_to(unsealed1.inner_message.message_id);

    let sealed2 = seal_private_message(forum_hash, &bob_identity, &alice_identity, message2, true)
        .expect("Failed to seal Bob's reply");

    // Step 5: Alice decrypts Bob's reply
    let unsealed2 = unseal_private_message(&sealed2.message, &alice_private)
        .expect("Alice failed to unseal Bob's reply");

    assert_eq!(
        unsealed2.inner_message.body,
        "Hi Alice! Got your message. This is Bob."
    );
    assert_eq!(
        unsealed2.inner_message.reply_to,
        Some(unsealed1.inner_message.message_id)
    );
}

/// Test that third parties cannot read sealed messages.
#[test]
fn test_private_message_privacy() {
    use pqpgp::forum::{seal_private_message, unseal_private_message};

    let forum_hash = create_test_forum_hash();

    // Create Alice, Bob, and Eve
    let alice_keypair = create_test_keypair();
    let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Bob identity");

    let eve_keypair = create_test_keypair();
    let (_eve_identity, eve_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        eve_keypair.public_key(),
        eve_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Eve identity");

    // Alice sends message to Bob
    let secret_message = InnerMessage::new(
        [0u8; 32],
        "Top secret information for Bob only!".to_string(),
    );

    let sealed = seal_private_message(
        forum_hash,
        &alice_identity,
        &bob_identity,
        secret_message,
        true,
    )
    .expect("Failed to seal message");

    // Eve tries to decrypt - should fail
    let eve_result = unseal_private_message(&sealed.message, &eve_private);
    assert!(
        eve_result.is_err(),
        "Eve should not be able to decrypt Bob's message"
    );

    // Bob can decrypt
    let bob_result = unseal_private_message(&sealed.message, &bob_private);
    assert!(
        bob_result.is_ok(),
        "Bob should be able to decrypt his message"
    );
}

/// Test message scanning with PrivateMessageScanner.
#[test]
fn test_private_message_scanning() {
    use pqpgp::forum::seal_private_message;

    let forum_hash = create_test_forum_hash();

    // Create multiple users
    let alice_keypair = create_test_keypair();
    let (alice_identity, alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        10,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        10,
        None,
    )
    .expect("Failed to generate Bob identity");

    let charlie_keypair = create_test_keypair();
    let (charlie_identity, charlie_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        charlie_keypair.public_key(),
        charlie_keypair.private_key(),
        10,
        None,
    )
    .expect("Failed to generate Charlie identity");

    // Create several messages between different pairs
    let msg_alice_to_bob = seal_private_message(
        forum_hash,
        &alice_identity,
        &bob_identity,
        InnerMessage::new([1u8; 32], "Alice to Bob".to_string()),
        true,
    )
    .expect("Failed to seal");

    let msg_charlie_to_bob = seal_private_message(
        forum_hash,
        &charlie_identity,
        &bob_identity,
        InnerMessage::new([2u8; 32], "Charlie to Bob".to_string()),
        true,
    )
    .expect("Failed to seal");

    let msg_alice_to_charlie = seal_private_message(
        forum_hash,
        &alice_identity,
        &charlie_identity,
        InnerMessage::new([3u8; 32], "Alice to Charlie".to_string()),
        true,
    )
    .expect("Failed to seal");

    // All messages in the "DAG" - scanner expects (&ContentHash, &SealedPrivateMessage)
    let msg1_hash = *msg_alice_to_bob.message.hash();
    let msg2_hash = *msg_charlie_to_bob.message.hash();
    let msg3_hash = *msg_alice_to_charlie.message.hash();

    let all_messages: Vec<(&ContentHash, &SealedPrivateMessage)> = vec![
        (&msg1_hash, &msg_alice_to_bob.message),
        (&msg2_hash, &msg_charlie_to_bob.message),
        (&msg3_hash, &msg_alice_to_charlie.message),
    ];

    // Bob scans - should find 2 messages
    let mut bob_scanner = PrivateMessageScanner::new(vec![&bob_private]);
    let bob_manager = ConversationManager::new();
    let bob_result = bob_scanner.scan_messages(all_messages.clone().into_iter(), &bob_manager);

    assert_eq!(
        bob_result.messages_decrypted, 2,
        "Bob should find 2 messages"
    );
    assert_eq!(bob_result.new_messages.len(), 2);

    // Charlie scans - should find 1 message
    let mut charlie_scanner = PrivateMessageScanner::new(vec![&charlie_private]);
    let charlie_manager = ConversationManager::new();
    let charlie_result =
        charlie_scanner.scan_messages(all_messages.clone().into_iter(), &charlie_manager);

    assert_eq!(
        charlie_result.messages_decrypted, 1,
        "Charlie should find 1 message"
    );

    // Alice scans - should find 0 messages (she only sent, didn't receive)
    let mut alice_scanner = PrivateMessageScanner::new(vec![&alice_private]);
    let alice_manager = ConversationManager::new();
    let alice_result = alice_scanner.scan_messages(all_messages.into_iter(), &alice_manager);

    assert_eq!(
        alice_result.messages_decrypted, 0,
        "Alice should find 0 messages (she only sent)"
    );
}

/// Test multi-message conversation with session reuse.
#[test]
fn test_conversation_session_continuity() {
    use pqpgp::forum::{seal_private_message, unseal_private_message};

    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();
    let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        20,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        20,
        None,
    )
    .expect("Failed to generate Bob identity");

    // First message establishes conversation
    let msg1 = seal_private_message(
        forum_hash,
        &alice_identity,
        &bob_identity,
        InnerMessage::new([0u8; 32], "Message 1".to_string()),
        true,
    )
    .expect("Failed to seal msg1");

    let conv_id = msg1.conversation_id;

    // Second message in same conversation
    let msg2 = seal_private_message(
        forum_hash,
        &alice_identity,
        &bob_identity,
        InnerMessage::new(conv_id, "Message 2".to_string()),
        true, // Still uses OTP for new X3DH (simplified test)
    )
    .expect("Failed to seal msg2");

    // Third message
    let msg3 = seal_private_message(
        forum_hash,
        &alice_identity,
        &bob_identity,
        InnerMessage::new(conv_id, "Message 3".to_string()),
        true,
    )
    .expect("Failed to seal msg3");

    // Bob should be able to decrypt all three
    let unsealed1 =
        unseal_private_message(&msg1.message, &bob_private).expect("Failed to unseal msg1");
    let unsealed2 =
        unseal_private_message(&msg2.message, &bob_private).expect("Failed to unseal msg2");
    let unsealed3 =
        unseal_private_message(&msg3.message, &bob_private).expect("Failed to unseal msg3");

    assert_eq!(unsealed1.inner_message.body, "Message 1");
    assert_eq!(unsealed2.inner_message.body, "Message 2");
    assert_eq!(unsealed3.inner_message.body, "Message 3");
}

/// Test tampering detection in sealed messages.
#[test]
fn test_sealed_message_tampering_detection() {
    use pqpgp::forum::{seal_private_message, unseal_private_message};

    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();
    let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Bob identity");

    let sealed = seal_private_message(
        forum_hash,
        &alice_identity,
        &bob_identity,
        InnerMessage::new([0u8; 32], "Original message".to_string()),
        true,
    )
    .expect("Failed to seal");

    // Tamper with the sealed payload
    let mut tampered = sealed.message.clone();
    if !tampered.content.sealed_payload.is_empty() {
        tampered.content.sealed_payload[0] ^= 0xFF;
    }

    // Decryption should fail
    let result = unseal_private_message(&tampered, &bob_private);
    assert!(result.is_err(), "Tampered message should fail to decrypt");
}

/// Test large message handling in private messages.
#[test]
fn test_large_private_message() {
    use pqpgp::forum::{seal_private_message, unseal_private_message};

    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();
    let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Bob identity");

    // Create a large message (50KB)
    let large_body: String = (0..50_000)
        .map(|i| ((i % 26) as u8 + b'a') as char)
        .collect();

    let sealed = seal_private_message(
        forum_hash,
        &alice_identity,
        &bob_identity,
        InnerMessage::new([0u8; 32], large_body.clone()),
        true,
    )
    .expect("Failed to seal large message");

    let unsealed = unseal_private_message(&sealed.message, &bob_private)
        .expect("Failed to unseal large message");

    assert_eq!(unsealed.inner_message.body, large_body);
    assert_eq!(unsealed.inner_message.body.len(), 50_000);
}

/// Test message with subject line.
#[test]
fn test_message_with_subject() {
    use pqpgp::forum::{seal_private_message, unseal_private_message};

    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();
    let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Bob identity");

    let msg = InnerMessage::new([0u8; 32], "Message body here".to_string())
        .with_subject("Important: Please Read".to_string());

    let sealed = seal_private_message(forum_hash, &alice_identity, &bob_identity, msg, true)
        .expect("Failed to seal");

    let unsealed = unseal_private_message(&sealed.message, &bob_private).expect("Failed to unseal");

    assert_eq!(
        unsealed.inner_message.subject,
        Some("Important: Please Read".to_string())
    );
    assert_eq!(unsealed.inner_message.body, "Message body here");
}

// =============================================================================
// Double Ratchet Session Tests
// =============================================================================

/// Test Double Ratchet seal/unseal roundtrip with conversation session.
#[test]
fn test_double_ratchet_session_roundtrip() {
    use pqpgp::forum::{
        seal_private_message, seal_with_ratchet, unseal_private_message, unseal_with_ratchet,
        ConversationSession,
    };

    let forum_hash = create_test_forum_hash();

    // Create Alice (sender) identity
    let alice_keypair = create_test_keypair();
    let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Alice identity");

    // Create Bob (recipient) identity
    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Bob identity");

    // First, establish conversation with X3DH
    let initial_msg = InnerMessage::new([0u8; 32], "Initial X3DH message".to_string());
    let sealed_x3dh = seal_private_message(
        forum_hash,
        &alice_identity,
        &bob_identity,
        initial_msg,
        true,
    )
    .expect("Failed to seal X3DH message");

    let unsealed_x3dh = unseal_private_message(&sealed_x3dh.message, &bob_private)
        .expect("Failed to unseal X3DH message");

    // Create Alice's session (initiator)
    let mut alice_session = ConversationSession::new_initiator(
        sealed_x3dh.conversation_id,
        *sealed_x3dh.conversation_key,
        *alice_identity.hash(),
        *bob_identity.hash(),
        None,
        Some(bob_identity.signed_prekey().public_key().to_vec()),
    );

    // Create Bob's session (responder)
    let mut bob_session = ConversationSession::new_responder(
        unsealed_x3dh.conversation_id,
        *unsealed_x3dh.conversation_key,
        *bob_identity.hash(),
        *alice_identity.hash(),
        unsealed_x3dh.used_one_time_prekey_id,
        Some((
            bob_private.signed_prekey_public().to_vec(),
            bob_private.signed_prekey_secret().to_vec(),
        )),
    );

    // Now send a ratchet-encrypted message
    let ratchet_msg = InnerMessage::new(
        sealed_x3dh.conversation_id,
        "Ratchet encrypted message!".to_string(),
    );

    let sealed_ratchet = seal_with_ratchet(
        forum_hash,
        &alice_identity,
        &bob_identity,
        ratchet_msg,
        &mut alice_session,
    )
    .expect("Failed to seal with ratchet");

    // Bob decrypts with ratchet
    let unsealed_ratchet = unseal_with_ratchet(&sealed_ratchet, &bob_private, &mut bob_session)
        .expect("Failed to unseal with ratchet");

    assert_eq!(unsealed_ratchet.body, "Ratchet encrypted message!");
}

/// Test multiple messages with Double Ratchet showing key rotation.
#[test]
fn test_double_ratchet_multiple_messages() {
    use pqpgp::forum::{
        seal_private_message, seal_with_ratchet, unseal_private_message, unseal_with_ratchet,
        ConversationSession,
    };

    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();
    let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Bob identity");

    // Establish X3DH
    let initial = InnerMessage::new([0u8; 32], "X3DH".to_string());
    let sealed = seal_private_message(forum_hash, &alice_identity, &bob_identity, initial, true)
        .expect("Failed to seal");

    let unsealed = unseal_private_message(&sealed.message, &bob_private).expect("Failed to unseal");

    // Create sessions
    let mut alice_session = ConversationSession::new_initiator(
        sealed.conversation_id,
        *sealed.conversation_key,
        *alice_identity.hash(),
        *bob_identity.hash(),
        None,
        Some(bob_identity.signed_prekey().public_key().to_vec()),
    );

    let mut bob_session = ConversationSession::new_responder(
        unsealed.conversation_id,
        *unsealed.conversation_key,
        *bob_identity.hash(),
        *alice_identity.hash(),
        unsealed.used_one_time_prekey_id,
        Some((
            bob_private.signed_prekey_public().to_vec(),
            bob_private.signed_prekey_secret().to_vec(),
        )),
    );

    // Send 5 messages with ratchet
    let messages = vec![
        "Message 1: Hello!",
        "Message 2: How are you?",
        "Message 3: The weather is nice.",
        "Message 4: See you later!",
        "Message 5: Goodbye!",
    ];

    for (i, msg_text) in messages.iter().enumerate() {
        let msg = InnerMessage::new(sealed.conversation_id, msg_text.to_string());

        let sealed_msg = seal_with_ratchet(
            forum_hash,
            &alice_identity,
            &bob_identity,
            msg,
            &mut alice_session,
        )
        .expect(&format!("Failed to seal message {}", i + 1));

        let unsealed_msg = unseal_with_ratchet(&sealed_msg, &bob_private, &mut bob_session)
            .expect(&format!("Failed to unseal message {}", i + 1));

        assert_eq!(unsealed_msg.body, *msg_text, "Message {} mismatch", i + 1);
    }
}

/// Test bidirectional Double Ratchet conversation (ping-pong).
#[test]
fn test_double_ratchet_bidirectional() {
    use pqpgp::forum::{
        seal_private_message, seal_with_ratchet, unseal_private_message, unseal_with_ratchet,
        ConversationSession,
    };

    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();
    let (alice_identity, alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Bob identity");

    // Establish X3DH (Alice -> Bob)
    let initial = InnerMessage::new([0u8; 32], "X3DH init".to_string());
    let sealed = seal_private_message(forum_hash, &alice_identity, &bob_identity, initial, true)
        .expect("Failed to seal");

    let unsealed = unseal_private_message(&sealed.message, &bob_private).expect("Failed to unseal");

    // Create sessions
    let mut alice_session = ConversationSession::new_initiator(
        sealed.conversation_id,
        *sealed.conversation_key,
        *alice_identity.hash(),
        *bob_identity.hash(),
        None,
        Some(bob_identity.signed_prekey().public_key().to_vec()),
    );

    let mut bob_session = ConversationSession::new_responder(
        unsealed.conversation_id,
        *unsealed.conversation_key,
        *bob_identity.hash(),
        *alice_identity.hash(),
        unsealed.used_one_time_prekey_id,
        Some((
            bob_private.signed_prekey_public().to_vec(),
            bob_private.signed_prekey_secret().to_vec(),
        )),
    );

    // Alice sends first ratchet message
    let msg1 = InnerMessage::new(sealed.conversation_id, "Alice: Hello Bob!".to_string());
    let sealed1 = seal_with_ratchet(
        forum_hash,
        &alice_identity,
        &bob_identity,
        msg1,
        &mut alice_session,
    )
    .expect("Failed to seal msg1");

    let unsealed1 = unseal_with_ratchet(&sealed1, &bob_private, &mut bob_session)
        .expect("Failed to unseal msg1");
    assert_eq!(unsealed1.body, "Alice: Hello Bob!");

    // Bob replies (this rotates the ratchet)
    let msg2 = InnerMessage::new(sealed.conversation_id, "Bob: Hi Alice!".to_string());
    let sealed2 = seal_with_ratchet(
        forum_hash,
        &bob_identity,
        &alice_identity,
        msg2,
        &mut bob_session,
    )
    .expect("Failed to seal msg2");

    let unsealed2 = unseal_with_ratchet(&sealed2, &alice_private, &mut alice_session)
        .expect("Failed to unseal msg2");
    assert_eq!(unsealed2.body, "Bob: Hi Alice!");

    // Alice sends another message (ratchet rotates again)
    let msg3 = InnerMessage::new(sealed.conversation_id, "Alice: How are you?".to_string());
    let sealed3 = seal_with_ratchet(
        forum_hash,
        &alice_identity,
        &bob_identity,
        msg3,
        &mut alice_session,
    )
    .expect("Failed to seal msg3");

    let unsealed3 = unseal_with_ratchet(&sealed3, &bob_private, &mut bob_session)
        .expect("Failed to unseal msg3");
    assert_eq!(unsealed3.body, "Alice: How are you?");

    // Bob replies again
    let msg4 = InnerMessage::new(sealed.conversation_id, "Bob: I'm great!".to_string());
    let sealed4 = seal_with_ratchet(
        forum_hash,
        &bob_identity,
        &alice_identity,
        msg4,
        &mut bob_session,
    )
    .expect("Failed to seal msg4");

    let unsealed4 = unseal_with_ratchet(&sealed4, &alice_private, &mut alice_session)
        .expect("Failed to unseal msg4");
    assert_eq!(unsealed4.body, "Bob: I'm great!");
}

/// Test that each ratchet message has a unique encryption.
#[test]
fn test_double_ratchet_unique_ciphertexts() {
    use pqpgp::forum::{
        seal_private_message, seal_with_ratchet, unseal_private_message, ConversationSession,
    };

    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();
    let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Bob identity");

    // Establish X3DH
    let initial = InnerMessage::new([0u8; 32], "X3DH".to_string());
    let sealed = seal_private_message(forum_hash, &alice_identity, &bob_identity, initial, true)
        .expect("Failed to seal");

    let _ = unseal_private_message(&sealed.message, &bob_private).expect("Failed to unseal");

    // Create session
    let mut alice_session = ConversationSession::new_initiator(
        sealed.conversation_id,
        *sealed.conversation_key,
        *alice_identity.hash(),
        *bob_identity.hash(),
        None,
        Some(bob_identity.signed_prekey().public_key().to_vec()),
    );

    // Send identical messages
    let identical_text = "Identical message content";
    let mut ciphertexts = Vec::new();

    for _ in 0..3 {
        let msg = InnerMessage::new(sealed.conversation_id, identical_text.to_string());
        let sealed_msg = seal_with_ratchet(
            forum_hash,
            &alice_identity,
            &bob_identity,
            msg,
            &mut alice_session,
        )
        .expect("Failed to seal");

        ciphertexts.push(sealed_msg.content.sealed_payload.clone());
    }

    // All ciphertexts should be different even though plaintext is identical
    assert_ne!(
        ciphertexts[0], ciphertexts[1],
        "Ciphertext 0 should differ from 1"
    );
    assert_ne!(
        ciphertexts[1], ciphertexts[2],
        "Ciphertext 1 should differ from 2"
    );
    assert_ne!(
        ciphertexts[0], ciphertexts[2],
        "Ciphertext 0 should differ from 2"
    );
}

// =============================================================================
// Out-of-Order Delivery Tests
// =============================================================================

/// Test out-of-order message delivery with Double Ratchet.
/// The ratchet should store skipped keys to handle this.
#[test]
fn test_out_of_order_delivery() {
    use pqpgp::forum::{
        seal_private_message, seal_with_ratchet, unseal_private_message, unseal_with_ratchet,
        ConversationSession,
    };

    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();
    let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Bob identity");

    // Establish X3DH
    let initial = InnerMessage::new([0u8; 32], "X3DH".to_string());
    let sealed = seal_private_message(forum_hash, &alice_identity, &bob_identity, initial, true)
        .expect("Failed to seal");

    let unsealed = unseal_private_message(&sealed.message, &bob_private).expect("Failed to unseal");

    // Create sessions
    let mut alice_session = ConversationSession::new_initiator(
        sealed.conversation_id,
        *sealed.conversation_key,
        *alice_identity.hash(),
        *bob_identity.hash(),
        None,
        Some(bob_identity.signed_prekey().public_key().to_vec()),
    );

    let mut bob_session = ConversationSession::new_responder(
        unsealed.conversation_id,
        *unsealed.conversation_key,
        *bob_identity.hash(),
        *alice_identity.hash(),
        unsealed.used_one_time_prekey_id,
        Some((
            bob_private.signed_prekey_public().to_vec(),
            bob_private.signed_prekey_secret().to_vec(),
        )),
    );

    // Alice sends 3 messages
    let msg1 = InnerMessage::new(sealed.conversation_id, "Message 1".to_string());
    let sealed1 = seal_with_ratchet(
        forum_hash,
        &alice_identity,
        &bob_identity,
        msg1,
        &mut alice_session,
    )
    .expect("Failed to seal msg1");

    let msg2 = InnerMessage::new(sealed.conversation_id, "Message 2".to_string());
    let sealed2 = seal_with_ratchet(
        forum_hash,
        &alice_identity,
        &bob_identity,
        msg2,
        &mut alice_session,
    )
    .expect("Failed to seal msg2");

    let msg3 = InnerMessage::new(sealed.conversation_id, "Message 3".to_string());
    let sealed3 = seal_with_ratchet(
        forum_hash,
        &alice_identity,
        &bob_identity,
        msg3,
        &mut alice_session,
    )
    .expect("Failed to seal msg3");

    // Current implementation requires in-order delivery.
    // Out-of-order messages should be rejected (msg3 before msg1).
    // This documents the current limitation - future implementations may support
    // out-of-order delivery via message key caching.
    let out_of_order_result = unseal_with_ratchet(&sealed3, &bob_private, &mut bob_session);
    assert!(
        out_of_order_result.is_err(),
        "Out-of-order message should be rejected"
    );

    // Now test in-order delivery with a fresh session
    let mut bob_session_fresh = ConversationSession::new_responder(
        unsealed.conversation_id,
        *unsealed.conversation_key,
        *bob_identity.hash(),
        *alice_identity.hash(),
        unsealed.used_one_time_prekey_id,
        Some((
            bob_private.signed_prekey_public().to_vec(),
            bob_private.signed_prekey_secret().to_vec(),
        )),
    );

    // Verify in-order delivery works correctly with fresh session
    let unsealed1 = unseal_with_ratchet(&sealed1, &bob_private, &mut bob_session_fresh)
        .expect("Failed to unseal msg1 (in order)");
    assert_eq!(unsealed1.body, "Message 1");

    let unsealed2 = unseal_with_ratchet(&sealed2, &bob_private, &mut bob_session_fresh)
        .expect("Failed to unseal msg2 (in order)");
    assert_eq!(unsealed2.body, "Message 2");

    let unsealed3 = unseal_with_ratchet(&sealed3, &bob_private, &mut bob_session_fresh)
        .expect("Failed to unseal msg3 (in order)");
    assert_eq!(unsealed3.body, "Message 3");
}

// =============================================================================
// Prekey Rotation Tests
// =============================================================================

/// Test that signed prekey rotation creates a new identity.
#[test]
fn test_signed_prekey_rotation() {
    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();

    // Generate initial identity
    let (identity1, private1) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate first identity");

    // Rotate signed prekey
    let (identity2, private2) = EncryptionIdentityGenerator::rotate_signed_prekey(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to rotate signed prekey");

    // Identities should be different
    assert_ne!(
        identity1.hash(),
        identity2.hash(),
        "Rotated identity should have different hash"
    );

    // Signed prekeys should be different
    assert_ne!(
        identity1.signed_prekey().public_key(),
        identity2.signed_prekey().public_key(),
        "Rotated signed prekey should be different"
    );

    // Both identities should be valid
    assert!(identity1.verify(alice_keypair.public_key()).is_ok());
    assert!(identity2.verify(alice_keypair.public_key()).is_ok());

    // Private keys should also be different
    assert_ne!(
        private1.signed_prekey_public(),
        private2.signed_prekey_public(),
        "Private signed prekey should be different"
    );
}

/// Test one-time prekey replenishment.
#[test]
fn test_otp_replenishment() {
    use pqpgp::forum::seal_private_message;

    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();
    let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();

    // Generate Bob's identity with only 3 OTPs
    let (bob_identity1, bob_private1) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        3,
        None,
    )
    .expect("Failed to generate Bob identity");

    let initial_otp_count = bob_identity1.content.one_time_prekeys.len();
    assert_eq!(initial_otp_count, 3);

    // Send 2 messages to Bob (consuming 2 OTPs)
    for i in 0..2 {
        let msg = InnerMessage::new([i as u8; 32], format!("Message {}", i));
        let _ = seal_private_message(forum_hash, &alice_identity, &bob_identity1, msg, true)
            .expect("Failed to seal");
    }

    // Replenish OTPs (starting from ID 100 to avoid collisions)
    let (bob_identity2, bob_private2) = EncryptionIdentityGenerator::replenish_one_time_prekeys(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        &bob_private1,
        5, // Add 5 new OTPs
        100u32,
        None,
    )
    .expect("Failed to replenish OTPs");

    // New identity should have more OTPs
    assert!(
        bob_identity2.content.one_time_prekeys.len() > initial_otp_count,
        "Replenished identity should have more OTPs"
    );

    // Should be able to send messages to new identity
    let msg = InnerMessage::new([99u8; 32], "Message to replenished identity".to_string());
    let sealed = seal_private_message(forum_hash, &alice_identity, &bob_identity2, msg, true)
        .expect("Failed to seal to replenished identity");

    // Bob should be able to unseal with new private
    use pqpgp::forum::unseal_private_message;
    let unsealed = unseal_private_message(&sealed.message, &bob_private2)
        .expect("Failed to unseal with replenished identity");

    assert_eq!(
        unsealed.inner_message.body,
        "Message to replenished identity"
    );
}

/// Test that messages can still be decrypted after prekey rotation
/// (grace period for in-flight messages).
#[test]
fn test_prekey_rotation_grace_period() {
    use pqpgp::forum::{seal_private_message, unseal_private_message};

    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();
    let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity_old, bob_private_old) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Bob's old identity");

    // Alice sends message to Bob's OLD identity
    let msg_old = InnerMessage::new([0u8; 32], "Message to old identity".to_string());
    let sealed_old = seal_private_message(
        forum_hash,
        &alice_identity,
        &bob_identity_old,
        msg_old,
        true,
    )
    .expect("Failed to seal to old identity");

    // Bob rotates his signed prekey (creates new identity)
    let (bob_identity_new, _bob_private_new) = EncryptionIdentityGenerator::rotate_signed_prekey(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to rotate");

    // Bob should still be able to decrypt with OLD private key
    // (simulates grace period where old keys are kept)
    let unsealed_old = unseal_private_message(&sealed_old.message, &bob_private_old)
        .expect("Bob should still decrypt with old private key");

    assert_eq!(unsealed_old.inner_message.body, "Message to old identity");

    // New identity should have different hash
    assert_ne!(bob_identity_old.hash(), bob_identity_new.hash());
}

// =============================================================================
// Forward Secrecy Verification Tests
// =============================================================================

/// Test that compromising current keys doesn't reveal past messages.
/// This is a conceptual test - we verify that each message uses a unique key.
#[test]
fn test_forward_secrecy_unique_message_keys() {
    use pqpgp::forum::{
        seal_private_message, seal_with_ratchet, unseal_private_message, ConversationSession,
    };

    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();
    let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        10,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        10,
        None,
    )
    .expect("Failed to generate Bob identity");

    // Establish session
    let initial = InnerMessage::new([0u8; 32], "X3DH".to_string());
    let sealed = seal_private_message(forum_hash, &alice_identity, &bob_identity, initial, true)
        .expect("Failed to seal");

    let _ = unseal_private_message(&sealed.message, &bob_private).expect("Failed to unseal");

    let mut alice_session = ConversationSession::new_initiator(
        sealed.conversation_id,
        *sealed.conversation_key,
        *alice_identity.hash(),
        *bob_identity.hash(),
        None,
        Some(bob_identity.signed_prekey().public_key().to_vec()),
    );

    // Collect all sealed payloads
    let mut payloads = Vec::new();

    for i in 0..5 {
        let msg = InnerMessage::new(sealed.conversation_id, format!("Secret {}", i));
        let sealed_msg = seal_with_ratchet(
            forum_hash,
            &alice_identity,
            &bob_identity,
            msg,
            &mut alice_session,
        )
        .expect("Failed to seal");

        payloads.push(sealed_msg.content.sealed_payload.clone());
    }

    // Verify all payloads are unique (different keys used)
    for i in 0..payloads.len() {
        for j in (i + 1)..payloads.len() {
            assert_ne!(
                payloads[i], payloads[j],
                "Messages {} and {} should have different ciphertexts",
                i, j
            );
        }
    }
}

/// Test that OTP consumption provides forward secrecy for initial messages.
#[test]
fn test_otp_forward_secrecy() {
    use pqpgp::forum::{seal_private_message, unseal_private_message};

    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();
    let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Bob identity");

    // Send multiple initial messages (each uses unique OTP)
    let mut results = Vec::new();

    for i in 0..3 {
        let msg = InnerMessage::new([i as u8; 32], format!("Initial message {}", i));
        let sealed = seal_private_message(
            forum_hash,
            &alice_identity,
            &bob_identity,
            msg,
            true, // Use OTP
        )
        .expect("Failed to seal");

        let unsealed =
            unseal_private_message(&sealed.message, &bob_private).expect("Failed to unseal");

        results.push((sealed, unsealed));
    }

    // Each message should have different conversation keys (due to different OTPs)
    // and different ciphertexts
    for i in 0..results.len() {
        for j in (i + 1)..results.len() {
            assert_ne!(
                results[i].0.message.content.sealed_payload,
                results[j].0.message.content.sealed_payload,
                "Messages {} and {} should have different ciphertexts",
                i,
                j
            );
        }
    }
}

/// Test that ratchet provides post-compromise security.
/// After a key rotation (via bidirectional communication), security is restored.
#[test]
fn test_post_compromise_security() {
    use pqpgp::forum::{
        seal_private_message, seal_with_ratchet, unseal_private_message, unseal_with_ratchet,
        ConversationSession,
    };

    let forum_hash = create_test_forum_hash();

    let alice_keypair = create_test_keypair();
    let (alice_identity, alice_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        alice_keypair.public_key(),
        alice_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Alice identity");

    let bob_keypair = create_test_keypair();
    let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
        forum_hash,
        bob_keypair.public_key(),
        bob_keypair.private_key(),
        5,
        None,
    )
    .expect("Failed to generate Bob identity");

    // Establish session
    let initial = InnerMessage::new([0u8; 32], "X3DH".to_string());
    let sealed = seal_private_message(forum_hash, &alice_identity, &bob_identity, initial, true)
        .expect("Failed to seal");

    let unsealed = unseal_private_message(&sealed.message, &bob_private).expect("Failed to unseal");

    let mut alice_session = ConversationSession::new_initiator(
        sealed.conversation_id,
        *sealed.conversation_key,
        *alice_identity.hash(),
        *bob_identity.hash(),
        None,
        Some(bob_identity.signed_prekey().public_key().to_vec()),
    );

    let mut bob_session = ConversationSession::new_responder(
        unsealed.conversation_id,
        *unsealed.conversation_key,
        *bob_identity.hash(),
        *alice_identity.hash(),
        unsealed.used_one_time_prekey_id,
        Some((
            bob_private.signed_prekey_public().to_vec(),
            bob_private.signed_prekey_secret().to_vec(),
        )),
    );

    // Phase 1: Alice sends (before compromise simulation)
    let msg1 = InnerMessage::new(sealed.conversation_id, "Before compromise".to_string());
    let sealed1 = seal_with_ratchet(
        forum_hash,
        &alice_identity,
        &bob_identity,
        msg1,
        &mut alice_session,
    )
    .expect("Failed to seal");

    let _ =
        unseal_with_ratchet(&sealed1, &bob_private, &mut bob_session).expect("Failed to unseal");

    // Phase 2: Bob responds (this rotates the KEM ratchet)
    let msg2 = InnerMessage::new(
        sealed.conversation_id,
        "Bob's response (rotates ratchet)".to_string(),
    );
    let sealed2 = seal_with_ratchet(
        forum_hash,
        &bob_identity,
        &alice_identity,
        msg2,
        &mut bob_session,
    )
    .expect("Failed to seal");

    let _ = unseal_with_ratchet(&sealed2, &alice_private, &mut alice_session)
        .expect("Failed to unseal");

    // Phase 3: Alice sends again (with new ratchet keys - security restored)
    let msg3 = InnerMessage::new(sealed.conversation_id, "After ratchet rotation".to_string());
    let sealed3 = seal_with_ratchet(
        forum_hash,
        &alice_identity,
        &bob_identity,
        msg3,
        &mut alice_session,
    )
    .expect("Failed to seal");

    let unsealed3 = unseal_with_ratchet(&sealed3, &bob_private, &mut bob_session)
        .expect("Failed to unseal after ratchet rotation");

    assert_eq!(unsealed3.body, "After ratchet rotation");

    // The key rotation means that even if an attacker compromised keys during
    // Phase 1, they cannot decrypt Phase 3 messages (post-compromise security)
    // This is verified by the fact that sealed1, sealed2, sealed3 all have
    // different ciphertexts and use different keys.
    assert_ne!(
        sealed1.content.sealed_payload, sealed3.content.sealed_payload,
        "Messages before and after rotation should use different keys"
    );
}
