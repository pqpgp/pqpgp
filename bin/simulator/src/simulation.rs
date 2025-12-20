//! Simulation logic for forum and messaging activities.

use crate::relay::SimulatorRelay;
use crate::user::SimulatedUser;
use pqpgp::forum::{BoardGenesis, ContentHash, DagNode, ForumGenesis, Post, ThreadRoot};
use tracing::{debug, info};

/// The main simulation state.
pub struct Simulation {
    /// Alice - first legitimate user.
    alice: SimulatedUser,
    /// Bob - second legitimate user.
    bob: SimulatedUser,
    /// Alice's relay.
    alice_relay: SimulatorRelay,
    /// Bob's relay.
    bob_relay: SimulatorRelay,

    // Forum state tracking
    /// The shared forum hash (created by Alice).
    forum_hash: Option<ContentHash>,
    /// Current board hashes.
    boards: Vec<ContentHash>,
    /// Current thread hashes.
    threads: Vec<ContentHash>,
}

impl Simulation {
    /// Creates a new simulation with the given users and relays.
    pub fn new(
        alice: SimulatedUser,
        bob: SimulatedUser,
        alice_relay: SimulatorRelay,
        bob_relay: SimulatorRelay,
    ) -> Self {
        Self {
            alice,
            bob,
            alice_relay,
            bob_relay,
            forum_hash: None,
            boards: Vec::new(),
            threads: Vec::new(),
        }
    }

    /// Returns a reference to Alice's relay.
    pub fn alice_relay(&self) -> &SimulatorRelay {
        &self.alice_relay
    }

    /// Returns a reference to Bob's relay.
    pub fn bob_relay(&self) -> &SimulatorRelay {
        &self.bob_relay
    }

    /// Returns the forum hash if created.
    pub fn forum_hash(&self) -> Option<&ContentHash> {
        self.forum_hash.as_ref()
    }

    /// Returns the first board hash if any boards exist.
    pub fn board_hash(&self) -> Option<&ContentHash> {
        self.boards.first()
    }

    /// Returns Alice's user info.
    pub fn alice(&self) -> &SimulatedUser {
        &self.alice
    }

    // =========================================================================
    // Forum Operations
    // =========================================================================

    /// Creates a shared forum (Alice is the creator/owner).
    pub async fn create_shared_forum(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let genesis = ForumGenesis::create(
            "PQPGP Test Forum".to_string(),
            "A forum for testing post-quantum cryptography discussions".to_string(),
            self.alice.keypair().public_key(),
            self.alice.keypair().private_key(),
            None,
        )?;

        let hash = *genesis.hash();
        info!("[Alice] Creating forum with hash: {}", hash.to_hex());

        // Submit to Alice's relay
        let result = self.alice_relay.create_forum(&genesis).await?;

        if result.accepted {
            self.forum_hash = Some(hash);
            info!("[Alice] Forum created successfully: {}", hash.short());
        } else {
            return Err("[Alice] Failed to create forum: not accepted".into());
        }

        Ok(())
    }

    /// Alice creates a board in the forum.
    pub async fn alice_create_board(
        &mut self,
        name: &str,
        description: &str,
    ) -> Result<ContentHash, Box<dyn std::error::Error + Send + Sync>> {
        let forum_hash = self.forum_hash.ok_or("[Alice] Forum not created yet")?;

        let board = BoardGenesis::create(
            forum_hash,
            name.to_string(),
            description.to_string(),
            self.alice.keypair().public_key(),
            self.alice.keypair().private_key(),
            None,
        )?;

        let hash = *board.hash();
        let node = DagNode::from(board);

        let result = self.alice_relay.submit_node(&forum_hash, &node).await?;

        if result.accepted {
            self.boards.push(hash);
            info!("[Alice] Board '{}' created: {}", name, hash.short());
            Ok(hash)
        } else {
            Err("[Alice] Failed to create board: not accepted".into())
        }
    }

    /// Alice creates a thread in a random available board.
    pub async fn alice_create_thread(
        &mut self,
        title: &str,
        body: &str,
    ) -> Result<ContentHash, Box<dyn std::error::Error + Send + Sync>> {
        let forum_hash = self.forum_hash.ok_or("[Alice] Forum not created yet")?;
        let board_hash = if self.boards.is_empty() {
            return Err("[Alice] No boards created yet".into());
        } else {
            // Pick a random board
            let idx = fastrand::usize(..self.boards.len());
            &self.boards[idx]
        };

        let thread = ThreadRoot::create(
            *board_hash,
            title.to_string(),
            body.to_string(),
            self.alice.keypair().public_key(),
            self.alice.keypair().private_key(),
            None,
        )?;

        let hash = *thread.hash();
        let node = DagNode::from(thread);

        let result = self.alice_relay.submit_node(&forum_hash, &node).await?;

        if result.accepted {
            self.threads.push(hash);
            info!("[Alice] Thread '{}' created: {}", title, hash.short());
            Ok(hash)
        } else {
            Err("[Alice] Failed to create thread: not accepted".into())
        }
    }

    /// Alice creates a post in a random thread.
    pub async fn alice_create_post(
        &mut self,
        body: &str,
    ) -> Result<ContentHash, Box<dyn std::error::Error + Send + Sync>> {
        let forum_hash = self.forum_hash.ok_or("[Alice] Forum not created yet")?;
        let thread_hash = if self.threads.is_empty() {
            return Err("[Alice] No threads created yet".into());
        } else {
            let idx = fastrand::usize(..self.threads.len());
            self.threads[idx]
        };

        // Use thread root as parent (simpler for random thread selection)
        let parent_hashes = vec![thread_hash];

        let post = Post::create(
            thread_hash,
            parent_hashes,
            body.to_string(),
            None,
            self.alice.keypair().public_key(),
            self.alice.keypair().private_key(),
            None,
        )?;

        let hash = *post.hash();
        let node = DagNode::from(post);

        let result = self.alice_relay.submit_node(&forum_hash, &node).await?;

        if result.accepted {
            debug!("[Alice] Posted: {}", hash.short());
            Ok(hash)
        } else {
            Err("[Alice] Failed to create post: not accepted".into())
        }
    }

    /// Bob creates a thread in a random available board.
    pub async fn bob_create_thread(
        &mut self,
        title: &str,
        body: &str,
    ) -> Result<ContentHash, Box<dyn std::error::Error + Send + Sync>> {
        let forum_hash = self.forum_hash.ok_or("[Bob] Forum not created yet")?;
        let board_hash = if self.boards.is_empty() {
            return Err("[Bob] No boards created yet".into());
        } else {
            // Pick a random board
            let idx = fastrand::usize(..self.boards.len());
            self.boards[idx]
        };

        let thread = ThreadRoot::create(
            board_hash,
            title.to_string(),
            body.to_string(),
            self.bob.keypair().public_key(),
            self.bob.keypair().private_key(),
            None,
        )?;

        let hash = *thread.hash();
        let node = DagNode::from(thread);

        // Submit to Alice's relay (forum origin) - will sync to Bob's relay
        let result = self.alice_relay.submit_node(&forum_hash, &node).await?;

        if result.accepted {
            self.threads.push(hash);
            info!("[Bob] Thread '{}' created: {}", title, hash.short());
            Ok(hash)
        } else {
            Err("[Bob] Failed to create thread: not accepted".into())
        }
    }

    /// Bob creates a post in a random thread.
    pub async fn bob_create_post(
        &mut self,
        body: &str,
    ) -> Result<ContentHash, Box<dyn std::error::Error + Send + Sync>> {
        let forum_hash = self.forum_hash.ok_or("[Bob] Forum not created yet")?;
        let thread_hash = if self.threads.is_empty() {
            return Err("[Bob] No threads created yet".into());
        } else {
            let idx = fastrand::usize(..self.threads.len());
            self.threads[idx]
        };

        // Use thread root as parent (simpler for random thread selection)
        let parent_hashes = vec![thread_hash];

        let post = Post::create(
            thread_hash,
            parent_hashes,
            body.to_string(),
            None,
            self.bob.keypair().public_key(),
            self.bob.keypair().private_key(),
            None,
        )?;

        let hash = *post.hash();
        let node = DagNode::from(post);

        // Submit to Alice's relay (forum origin) - will sync to Bob's relay
        let result = self.alice_relay.submit_node(&forum_hash, &node).await?;

        if result.accepted {
            debug!("[Bob] Posted: {}", hash.short());
            Ok(hash)
        } else {
            Err("[Bob] Failed to create post: not accepted".into())
        }
    }
}
