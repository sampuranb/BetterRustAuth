// Date utilities — maps to packages/better-auth/src/utils/date.ts

use chrono::{DateTime, Duration, Utc};

/// Get a date offset from now.
///
/// Matches TS `getDate(span, unit)`.
///
/// - `span`: offset amount
/// - `unit`: `"sec"` for seconds, `"ms"` for milliseconds (default)
pub fn get_date(span: i64, unit: DateUnit) -> DateTime<Utc> {
    match unit {
        DateUnit::Seconds => Utc::now() + Duration::seconds(span),
        DateUnit::Milliseconds => Utc::now() + Duration::milliseconds(span),
    }
}

/// Date unit for `get_date`.
#[derive(Debug, Clone, Copy)]
pub enum DateUnit {
    Seconds,
    Milliseconds,
}

/// Get a date that's `seconds` from now.
pub fn get_date_secs(seconds: i64) -> DateTime<Utc> {
    get_date(seconds, DateUnit::Seconds)
}

/// Get a date that's `milliseconds` from now.
pub fn get_date_ms(milliseconds: i64) -> DateTime<Utc> {
    get_date(milliseconds, DateUnit::Milliseconds)
}

/// Check if a datetime has expired (is in the past).
pub fn is_expired(dt: &DateTime<Utc>) -> bool {
    *dt < Utc::now()
}

/// Check if a datetime string (RFC 3339) has expired.
pub fn is_expired_str(dt_str: &str) -> bool {
    match DateTime::parse_from_rfc3339(dt_str) {
        Ok(dt) => dt < Utc::now(),
        Err(_) => true, // Invalid dates are considered expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_date_secs_future() {
        let future = get_date_secs(3600);
        assert!(future > Utc::now());
    }

    #[test]
    fn test_get_date_secs_past() {
        let past = get_date_secs(-3600);
        assert!(past < Utc::now());
    }

    #[test]
    fn test_is_expired() {
        let past = Utc::now() - Duration::hours(1);
        assert!(is_expired(&past));

        let future = Utc::now() + Duration::hours(1);
        assert!(!is_expired(&future));
    }

    #[test]
    fn test_is_expired_str() {
        assert!(is_expired_str("2020-01-01T00:00:00Z"));
        assert!(is_expired_str("invalid-date"));
        assert!(!is_expired_str("2099-01-01T00:00:00Z"));
    }
}
