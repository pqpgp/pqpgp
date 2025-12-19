//! IP-based rate limiting middleware for the relay server.
//!
//! Implements a token bucket algorithm per IP address to prevent abuse and DoS attacks.
//!
//! ## Features
//!
//! - Per-IP rate limiting using token bucket algorithm
//! - Configurable request rate and burst capacity
//! - Automatic cleanup of stale entries
//! - Graceful handling of missing IP addresses

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
    response::IntoResponse,
};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tower::{Layer, Service};
use tracing::warn;

/// Rate limit configuration.
#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    /// Maximum requests per window.
    pub requests_per_window: u32,
    /// Time window duration.
    pub window_duration: Duration,
    /// Cleanup interval for stale entries.
    pub cleanup_interval: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            // 1000 requests per 10 seconds (100 req/sec average)
            requests_per_window: 1000,
            window_duration: Duration::from_secs(10),
            // Clean up stale entries every 5 minutes
            cleanup_interval: Duration::from_secs(300),
        }
    }
}

/// Token bucket state for a single IP.
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current number of tokens available.
    tokens: f64,
    /// Last time tokens were replenished.
    last_replenish: Instant,
}

impl TokenBucket {
    /// Creates a new bucket with full tokens.
    fn new(max_tokens: u32) -> Self {
        Self {
            tokens: max_tokens as f64,
            last_replenish: Instant::now(),
        }
    }

    /// Tries to consume a token, replenishing based on elapsed time.
    /// Returns true if request is allowed, false if rate limited.
    fn try_consume(&mut self, config: &RateLimitConfig) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_replenish);

        // Replenish tokens based on elapsed time
        let replenish_rate =
            config.requests_per_window as f64 / config.window_duration.as_secs_f64();
        let tokens_to_add = elapsed.as_secs_f64() * replenish_rate;

        self.tokens = (self.tokens + tokens_to_add).min(config.requests_per_window as f64);
        self.last_replenish = now;

        // Try to consume one token
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Returns true if this bucket hasn't been used recently and can be cleaned up.
    fn is_stale(&self, cleanup_interval: Duration) -> bool {
        self.last_replenish.elapsed() > cleanup_interval
    }
}

/// Shared rate limit state across all requests.
#[derive(Debug)]
struct RateLimitState {
    /// Per-IP token buckets.
    buckets: HashMap<IpAddr, TokenBucket>,
    /// Configuration.
    config: RateLimitConfig,
    /// Last cleanup time.
    last_cleanup: Instant,
}

impl RateLimitState {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            buckets: HashMap::new(),
            config,
            last_cleanup: Instant::now(),
        }
    }

    /// Checks if a request from the given IP should be allowed.
    fn check_rate_limit(&mut self, ip: IpAddr) -> bool {
        // Perform cleanup if needed
        if self.last_cleanup.elapsed() > self.config.cleanup_interval {
            self.cleanup_stale_buckets();
        }

        // Get or create bucket for this IP
        let bucket = self
            .buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(self.config.requests_per_window));

        bucket.try_consume(&self.config)
    }

    /// Removes stale buckets that haven't been used recently.
    fn cleanup_stale_buckets(&mut self) {
        let cleanup_interval = self.config.cleanup_interval;
        let before_count = self.buckets.len();
        self.buckets
            .retain(|_, bucket| !bucket.is_stale(cleanup_interval));
        let removed = before_count - self.buckets.len();
        if removed > 0 {
            tracing::debug!("Cleaned up {} stale rate limit buckets", removed);
        }
        self.last_cleanup = Instant::now();
    }
}

/// Rate limiting layer that wraps services.
#[derive(Clone)]
pub struct RateLimitLayer {
    state: Arc<RwLock<RateLimitState>>,
}

impl RateLimitLayer {
    /// Creates a new rate limit layer with default configuration.
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    /// Creates a new rate limit layer with custom configuration.
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(RateLimitState::new(config))),
        }
    }

    /// Creates a rate limit layer optimized for write operations (more restrictive).
    pub fn for_writes() -> Self {
        Self::with_config(RateLimitConfig {
            // 500 writes per 10 seconds (50 write/sec average)
            requests_per_window: 500,
            window_duration: Duration::from_secs(10),
            cleanup_interval: Duration::from_secs(300),
        })
    }
}

impl Default for RateLimitLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            state: self.state.clone(),
        }
    }
}

/// Rate limiting service wrapper.
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    state: Arc<RwLock<RateLimitState>>,
}

impl<S> Service<Request<Body>> for RateLimitService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Extract client IP from request
        let client_ip = extract_client_ip(&req);

        // Check rate limit
        // SECURITY: Default to DENY if IP cannot be determined to prevent bypass attacks
        let allowed = if let Some(ip) = client_ip {
            let mut state = self.state.write().unwrap_or_else(|poisoned| {
                warn!("Rate limit state was poisoned, recovering");
                poisoned.into_inner()
            });
            state.check_rate_limit(ip)
        } else {
            // SECURITY FIX: Default to DENY when IP cannot be determined
            // This prevents attackers from bypassing rate limiting by spoofing headers
            // or using proxies that don't properly forward client IP
            warn!("Could not determine client IP for rate limiting - denying request for security");
            false
        };

        if !allowed {
            if let Some(ip) = client_ip {
                warn!("Rate limit exceeded for IP: {}", ip);
            }
            // Return 429 Too Many Requests
            let response = (
                StatusCode::TOO_MANY_REQUESTS,
                [("Retry-After", "10")],
                "Rate limit exceeded. Please slow down.",
            )
                .into_response();
            return Box::pin(async move { Ok(response) });
        }

        // Request is allowed, forward to inner service
        let future = self.inner.call(req);
        Box::pin(future)
    }
}

/// Extracts the client IP address from the request.
///
/// **Security Note**: X-Forwarded-For and X-Real-IP headers are only trusted when
/// the `TRUST_PROXY_HEADERS` environment variable is set to "true". This prevents
/// attackers from spoofing their IP address when the relay is directly exposed.
///
/// Checks the following in order:
/// 1. X-Forwarded-For header (first IP in chain) - only if TRUST_PROXY_HEADERS=true
/// 2. X-Real-IP header - only if TRUST_PROXY_HEADERS=true
/// 3. Connection info (direct connection)
fn extract_client_ip<B>(req: &Request<B>) -> Option<IpAddr> {
    // Only trust proxy headers if explicitly configured (e.g., behind nginx/cloudflare)
    let trust_proxy_headers = std::env::var("TRUST_PROXY_HEADERS")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    if trust_proxy_headers {
        // Try X-Forwarded-For first (for reverse proxy setups)
        if let Some(forwarded) = req.headers().get("x-forwarded-for") {
            if let Ok(forwarded_str) = forwarded.to_str() {
                // Take the first IP in the chain (original client)
                if let Some(first_ip) = forwarded_str.split(',').next() {
                    if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }

        // Try X-Real-IP header
        if let Some(real_ip) = req.headers().get("x-real-ip") {
            if let Ok(real_ip_str) = real_ip.to_str() {
                if let Ok(ip) = real_ip_str.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // Fallback: try to get from connection info (always trusted)
    // Note: This requires the ConnectInfo extractor to be set up
    req.extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_basic() {
        let config = RateLimitConfig {
            requests_per_window: 10,
            window_duration: Duration::from_secs(1),
            cleanup_interval: Duration::from_secs(60),
        };

        let mut bucket = TokenBucket::new(10);

        // Should allow 10 requests
        for _ in 0..10 {
            assert!(bucket.try_consume(&config));
        }

        // 11th request should be denied
        assert!(!bucket.try_consume(&config));
    }

    #[test]
    fn test_rate_limit_state() {
        let config = RateLimitConfig {
            requests_per_window: 5,
            window_duration: Duration::from_secs(1),
            cleanup_interval: Duration::from_secs(60),
        };

        let mut state = RateLimitState::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow 5 requests
        for _ in 0..5 {
            assert!(state.check_rate_limit(ip));
        }

        // 6th request should be denied
        assert!(!state.check_rate_limit(ip));

        // Different IP should still be allowed
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        assert!(state.check_rate_limit(ip2));
    }
}
