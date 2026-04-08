use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_LOG_VALUE_CHARS: usize = 128;
const AUTH_WINDOW_SECS: u64 = 60;
const MAX_KEY_FAILURES_PER_WINDOW: usize = 8;

struct AuthRateLimiterState {
    keyed_failures: HashMap<String, VecDeque<Instant>>,
}

pub struct AuthRateLimiter {
    window: Duration,
    max_key_failures: usize,
    state: Mutex<AuthRateLimiterState>,
}

impl Default for AuthRateLimiter {
    fn default() -> Self {
        Self::new(
            Duration::from_secs(AUTH_WINDOW_SECS),
            MAX_KEY_FAILURES_PER_WINDOW,
        )
    }
}

impl AuthRateLimiter {
    pub fn new(window: Duration, max_key_failures: usize) -> Self {
        Self {
            window,
            max_key_failures,
            state: Mutex::new(AuthRateLimiterState {
                keyed_failures: HashMap::new(),
            }),
        }
    }

    pub fn allow_attempt(&self, key: &str) -> bool {
        let mut state = self.state.lock().unwrap();

        if let Some(keyed) = state.keyed_failures.get_mut(key) {
            prune_old(keyed, self.window);
            if keyed.len() >= self.max_key_failures {
                return false;
            }
            if keyed.is_empty() {
                state.keyed_failures.remove(key);
            }
        }

        true
    }

    pub fn record_failure(&self, key: &str) {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();

        let keyed = state.keyed_failures.entry(key.to_string()).or_default();
        prune_old(keyed, self.window);
        keyed.push_back(now);
    }

    pub fn reset_key(&self, key: &str) {
        let mut state = self.state.lock().unwrap();
        state.keyed_failures.remove(key);
    }
}

fn prune_old(entries: &mut VecDeque<Instant>, window: Duration) {
    let cutoff = Instant::now() - window;
    while matches!(entries.front(), Some(ts) if *ts < cutoff) {
        entries.pop_front();
    }
}

pub fn sanitize_for_log(value: &str) -> String {
    let mut sanitized = String::new();

    for ch in value.chars().take(MAX_LOG_VALUE_CHARS) {
        if ch.is_control() {
            sanitized.push('?');
        } else {
            sanitized.push(ch);
        }
    }

    if value.chars().count() > MAX_LOG_VALUE_CHARS {
        sanitized.push_str("...");
    }

    sanitized
}

pub fn auth_rate_limit_key(peer: Option<&str>, username: Option<&str>) -> String {
    match (peer, username) {
        (Some(peer), Some(username)) => format!("{}:{}", peer, username.to_ascii_lowercase()),
        (Some(peer), None) => peer.to_string(),
        (None, Some(username)) => format!("user:{}", username.to_ascii_lowercase()),
        (None, None) => "anonymous".to_string(),
    }
}

pub fn auth_failure_delay() -> Duration {
    if cfg!(test) {
        Duration::from_millis(1)
    } else {
        Duration::from_millis(250)
    }
}

pub fn default_auth_concurrency_limit() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(2, 8))
        .unwrap_or(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_blocks_after_key_threshold() {
        let limiter = AuthRateLimiter::new(Duration::from_secs(60), 2);
        assert!(limiter.allow_attempt("user:test"));
        limiter.record_failure("user:test");
        assert!(limiter.allow_attempt("user:test"));
        limiter.record_failure("user:test");
        assert!(!limiter.allow_attempt("user:test"));
    }

    #[test]
    fn limiter_is_scoped_to_each_key() {
        let limiter = AuthRateLimiter::new(Duration::from_secs(60), 1);
        limiter.record_failure("user:a");
        assert!(!limiter.allow_attempt("user:a"));
        assert!(limiter.allow_attempt("user:b"));
    }

    #[test]
    fn sanitize_for_log_replaces_control_characters() {
        assert_eq!(sanitize_for_log("alice\nbob\t"), "alice?bob?");
    }

    #[test]
    fn auth_rate_limit_key_prefers_peer_and_username() {
        assert_eq!(
            auth_rate_limit_key(Some("127.0.0.1"), Some("Alice")),
            "127.0.0.1:alice"
        );
    }
}
