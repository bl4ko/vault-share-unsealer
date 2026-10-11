use std::time::Duration;

pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Unseal,
    Idle,
}

pub fn decide(initialized: bool, sealed: bool) -> Action {
    if initialized && sealed {
        Action::Unseal
    } else {
        Action::Idle
    }
}

pub fn backoff(interval: Duration, failures: u32) -> Duration {
    if failures == 0 {
        return interval;
    }
    let cap = MAX_BACKOFF.max(interval);
    interval.saturating_mul(1u32 << failures.min(16)).min(cap)
}

pub fn next_delay(interval: Duration, failures: u32, unit: f64) -> Duration {
    let jittered = backoff(interval, failures).mul_f64(0.8 + 0.4 * unit.clamp(0.0, 1.0));
    if failures == 0 {
        jittered
    } else {
        jittered.min(MAX_BACKOFF.max(interval))
    }
}

pub fn random_unit() -> f64 {
    use std::hash::BuildHasher;
    let bits = std::collections::hash_map::RandomState::new().hash_one(std::time::Instant::now());
    (bits >> 11) as f64 / (1u64 << 53) as f64
}

pub fn classify_unseal_error(body: &str) -> &'static str {
    const KNOWN: [(&str, &str); 5] = [
        ("invalid key", "invalid key"),
        ("message authentication failed", "invalid key"),
        ("not initialized", "vault is not initialized"),
        ("must be a valid hex or base64", "malformed share"),
        ("rekey", "rekey in progress"),
    ];
    let lower = body.to_ascii_lowercase();
    KNOWN
        .iter()
        .find(|(needle, _)| lower.contains(needle))
        .map_or("rejected", |(_, label)| label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unseals_only_initialized_sealed_vault() {
        assert_eq!(decide(true, true), Action::Unseal);
        assert_eq!(decide(true, false), Action::Idle);
        assert_eq!(decide(false, true), Action::Idle);
        assert_eq!(decide(false, false), Action::Idle);
    }

    #[test]
    fn backoff_doubles_up_to_cap() {
        let i = Duration::from_secs(10);
        let got: Vec<u64> = (0..6).map(|f| backoff(i, f).as_secs()).collect();
        assert_eq!(got, [10, 20, 40, 60, 60, 60]);
        assert_eq!(backoff(i, u32::MAX), MAX_BACKOFF);
    }

    #[test]
    fn backoff_never_below_interval() {
        let i = Duration::from_secs(90);
        assert_eq!(backoff(i, 3), i);
        assert_eq!(next_delay(i, 3, 1.0), i);
    }

    #[test]
    fn jitter_stays_within_twenty_percent() {
        let i = Duration::from_secs(10);
        assert_eq!(next_delay(i, 0, 0.0), Duration::from_secs(8));
        assert_eq!(next_delay(i, 0, 1.0), Duration::from_secs(12));
        assert_eq!(next_delay(i, 0, 0.5), i);
        assert_eq!(next_delay(i, 5, 1.0), MAX_BACKOFF);
        assert_eq!(next_delay(i, 5, 0.0), Duration::from_secs(48));
        for _ in 0..1000 {
            let d = next_delay(i, 0, random_unit());
            assert!(d >= Duration::from_secs(8) && d <= Duration::from_secs(12));
        }
    }

    #[test]
    fn random_unit_in_range() {
        for _ in 0..1000 {
            let r = random_unit();
            assert!((0.0..1.0).contains(&r));
        }
    }

    #[test]
    fn classifies_without_echoing_body() {
        assert_eq!(
            classify_unseal_error(r#"{"errors":["Error unsealing: invalid key"]}"#),
            "invalid key"
        );
        assert_eq!(
            classify_unseal_error(r#"{"errors":["cipher: message authentication failed"]}"#),
            "invalid key"
        );
        assert_eq!(
            classify_unseal_error(r#"{"errors":["secret 0123abcd"]}"#),
            "rejected"
        );
        assert_eq!(classify_unseal_error(""), "rejected");
    }
}
