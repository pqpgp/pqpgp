//! PQPGP Forum and Messaging Simulator
//!
//! This simulator creates a realistic multi-user environment for testing:
//!
//! - **User 1 (Alice)**: Runs relay on port 4001, creates forums and content
//! - **User 2 (Bob)**: Runs relay on port 4002, participates in forums
//! - **Malicious User (Eve)**: Attempts various attacks against the system
//!
//! The relays sync with each other, allowing you to connect to either relay
//! to observe the synchronized forum state.
//!
//! ## Usage
//!
//! ```bash
//! # Run the simulator
//! pqpgp-simulator
//!
//! # Then connect to either relay:
//! # - Alice's relay: http://localhost:4001/rpc
//! # - Bob's relay: http://localhost:4002/rpc
//! ```

mod malicious;
mod relay;
mod simulation;
mod user;

use crate::relay::SimulatorRelay;
use crate::simulation::Simulation;
use crate::user::SimulatedUser;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, RwLock};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Ports for the simulated relays
const ALICE_RELAY_PORT: u16 = 4001;
const BOB_RELAY_PORT: u16 = 4002;

/// Sync interval for peer sync (seconds)
const SYNC_INTERVAL_SECS: u64 = 1;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize tracing with detailed output
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pqpgp_simulator=info,pqpgp=warn".into()),
        )
        .init();

    info!("===========================================");
    info!("  PQPGP Forum & Messaging Simulator");
    info!("===========================================");
    info!("");

    // Create temporary data directories for each relay
    let alice_data_dir = tempfile::tempdir()?;
    let bob_data_dir = tempfile::tempdir()?;

    info!("Creating simulated users...");

    // Create users with their keypairs
    let alice = SimulatedUser::new("Alice", ALICE_RELAY_PORT)?;
    let bob = SimulatedUser::new("Bob", BOB_RELAY_PORT)?;

    info!(
        "  Alice - Fingerprint: {}",
        hex::encode(alice.keypair().public_key().fingerprint())
    );
    info!(
        "  Bob   - Fingerprint: {}",
        hex::encode(bob.keypair().public_key().fingerprint())
    );
    info!("");

    // Start relays
    info!("Starting relays...");

    let alice_relay = SimulatorRelay::start(
        ALICE_RELAY_PORT,
        alice_data_dir.path(),
        vec![format!("http://127.0.0.1:{}", BOB_RELAY_PORT)],
        SYNC_INTERVAL_SECS,
    )
    .await?;

    let bob_relay = SimulatorRelay::start(
        BOB_RELAY_PORT,
        bob_data_dir.path(),
        vec![format!("http://127.0.0.1:{}", ALICE_RELAY_PORT)],
        SYNC_INTERVAL_SECS,
    )
    .await?;

    info!("  Alice's relay: http://127.0.0.1:{}/rpc", ALICE_RELAY_PORT);
    info!("  Bob's relay:   http://127.0.0.1:{}/rpc", BOB_RELAY_PORT);
    info!("");

    // Create shared simulation state
    let simulation = Arc::new(RwLock::new(Simulation::new(
        alice,
        bob,
        alice_relay,
        bob_relay,
    )));

    // Channel to signal when forum is ready
    let (forum_ready_tx, forum_ready_rx) = watch::channel(false);

    // Phase 1: Alice creates the forum (must happen first)
    {
        let mut sim = simulation.write().await;
        info!("[Setup] Alice creating forum...");
        sim.create_shared_forum().await?;
        info!("[Setup] Forum created successfully");
        let _ = forum_ready_tx.send(true);
    }

    // Now spawn all the parallel simulation tasks
    let sim_clone = simulation.clone();
    let alice_task = tokio::spawn(run_alice_simulation(sim_clone));

    let sim_clone = simulation.clone();
    let mut rx = forum_ready_rx.clone();
    let bob_task = tokio::spawn(async move {
        // Wait for forum to be ready
        while !*rx.borrow_and_update() {
            if rx.changed().await.is_err() {
                return;
            }
        }
        run_bob_simulation(sim_clone).await
    });

    let sim_clone = simulation.clone();
    let mut rx = forum_ready_rx.clone();
    let malicious_task = tokio::spawn(async move {
        // Wait for forum to be ready
        while !*rx.borrow_and_update() {
            if rx.changed().await.is_err() {
                return;
            }
        }
        run_malicious_simulation(sim_clone).await
    });

    info!("===========================================");
    info!("  Simulation Running");
    info!("===========================================");
    info!("");
    info!("You can now connect to the relays:");
    info!(
        "  curl -X POST http://127.0.0.1:{}/rpc \\",
        ALICE_RELAY_PORT
    );
    info!("    -H 'Content-Type: application/json' \\");
    info!("    -d '{{\"jsonrpc\":\"2.0\",\"method\":\"forum.list\",\"params\":{{}},\"id\":1}}'");
    info!("");
    info!("Press Ctrl+C to stop the simulation.");
    info!("");

    // Wait for all tasks (they run indefinitely until Ctrl+C)
    tokio::select! {
        _ = alice_task => {},
        _ = bob_task => {},
        _ = malicious_task => {},
        _ = tokio::signal::ctrl_c() => {
            info!("");
            info!("Shutting down simulator...");
        }
    }

    // Cleanup happens automatically when tempdir goes out of scope
    info!("Simulator stopped.");
    Ok(())
}

/// Alice's autonomous simulation - creates boards, threads, and posts
async fn run_alice_simulation(simulation: Arc<RwLock<Simulation>>) {
    info!("[Alice] Starting autonomous simulation...");

    // Alice creates an initial board
    {
        let mut sim = simulation.write().await;
        if let Err(e) = sim
            .alice_create_board("General Discussion", "Talk about anything!")
            .await
        {
            warn!("[Alice] Failed to create initial board: {}", e);
        }
    }

    // Alice creates an initial thread
    {
        let mut sim = simulation.write().await;
        if let Err(e) = sim
            .alice_create_thread(
                "Welcome to PQPGP!",
                "Let's discuss post-quantum cryptography.",
            )
            .await
        {
            warn!("[Alice] Failed to create initial thread: {}", e);
        }
    }

    let mut action_count = 0;
    loop {
        action_count += 1;

        // Randomly decide what to do: create board (5%), create thread (20%), or post (75%)
        let action = fastrand::u8(0..100);

        let mut sim = simulation.write().await;

        if action < 5 {
            // Create a new board
            let name = format!("Alice Board {}", action_count);
            info!("[Alice] Creating board: {}", name);
            if let Err(e) = sim
                .alice_create_board(&name, "A board created by Alice")
                .await
            {
                warn!("[Alice] Failed to create board: {}", e);
            }
        } else if action < 25 {
            // Create a new thread in a random board
            let title = format!("Alice's Thread #{}", action_count);
            let body = format!("Discussion topic {} from Alice", action_count);
            info!("[Alice] Creating thread: {}", title);
            if let Err(e) = sim.alice_create_thread(&title, &body).await {
                warn!("[Alice] Failed to create thread: {}", e);
            }
        } else {
            // Post in a random existing thread
            let body = format!("Alice's post #{} - thoughts on PQ crypto!", action_count);
            info!("[Alice] Posting reply...");
            if let Err(e) = sim.alice_create_post(&body).await {
                warn!("[Alice] Failed to create post: {}", e);
            }
        }

        // Log sync status periodically
        if action_count % 10 == 0 {
            let alice_count = sim.alice_relay().node_count().await;
            let bob_count = sim.bob_relay().node_count().await;
            info!(
                "[Sync] Alice relay: {} nodes, Bob relay: {} nodes",
                alice_count, bob_count
            );
        }

        // Drop the lock before sleeping
        drop(sim);

        // Pace actions: random delay between 50ms and 200ms (fast mode)
        let delay_ms = fastrand::u64(50..200);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

/// Bob's autonomous simulation - discovers and participates in forums
async fn run_bob_simulation(simulation: Arc<RwLock<Simulation>>) {
    info!("[Bob] Starting autonomous simulation...");

    // Bob is not a moderator, so he can't create boards - he just participates
    // in existing boards by creating threads and posts

    let mut action_count = 0;
    loop {
        action_count += 1;

        // Bob can't create boards (not a moderator), so he creates threads or posts
        // Create thread (20%), post (80%)
        let action = fastrand::u8(0..100);

        let mut sim = simulation.write().await;

        if action < 20 {
            // Create a new thread
            let title = format!("Bob's Thread #{}", action_count);
            let body = format!("Bob wants to discuss topic {}", action_count);
            info!("[Bob] Creating thread: {}", title);
            if let Err(e) = sim.bob_create_thread(&title, &body).await {
                warn!("[Bob] Failed to create thread: {}", e);
            }
        } else {
            // Post a reply
            let body = format!("Bob's reply #{} - great discussion!", action_count);
            info!("[Bob] Posting reply...");
            if let Err(e) = sim.bob_create_post(&body).await {
                warn!("[Bob] Failed to create post: {}", e);
            }
        }

        // Drop the lock before sleeping
        drop(sim);

        // Pace actions: random delay between 50ms and 200ms (fast mode)
        let delay_ms = fastrand::u64(50..200);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

/// Runs the malicious user simulation
async fn run_malicious_simulation(simulation: Arc<RwLock<Simulation>>) {
    info!("[Malicious] Starting malicious user simulation...");
    info!("[Malicious] Eve will attempt various attacks against Bob's relay...");

    let attacks = malicious::all_attacks();
    info!(
        "[Malicious] {} attack types available: {:?}",
        attacks.len(),
        attacks
    );

    for (i, attack) in attacks.iter().cycle().enumerate() {
        info!("[Malicious] Eve attempting attack #{}: {}", i + 1, attack);

        let result = {
            let sim = simulation.read().await;
            malicious::execute_attack(&sim, attack).await
        };

        match result {
            Ok(blocked) => {
                if blocked {
                    info!("[Malicious] Attack '{}' was correctly BLOCKED", attack);
                } else {
                    panic!(
                        "[SECURITY VULNERABILITY] Attack '{}' was NOT blocked! This indicates a security flaw.",
                        attack
                    );
                }
            }
            Err(e) => {
                info!(
                    "[Malicious] Attack '{}' failed with error (expected): {}",
                    attack, e
                );
            }
        }

        // Pace attacks: random delay between 200ms and 500ms (fast mode)
        let delay_ms = fastrand::u64(200..500);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}
