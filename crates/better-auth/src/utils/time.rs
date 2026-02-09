// Time parsing utilities — maps to packages/better-auth/src/utils/time.ts
//
// Parses human-readable time strings like "7d", "30m", "2 hours" into
// milliseconds or seconds.

/// Time constants in milliseconds.
pub const SEC_MS: u64 = 1_000;
pub const MIN_MS: u64 = SEC_MS * 60;
pub const HOUR_MS: u64 = MIN_MS * 60;
pub const DAY_MS: u64 = HOUR_MS * 24;
pub const WEEK_MS: u64 = DAY_MS * 7;
pub const MONTH_MS: u64 = DAY_MS * 30;
pub const YEAR_MS: u64 = (DAY_MS as f64 * 365.25) as u64;

/// Parse a time string and return the value in milliseconds.
///
/// Matches TS `ms()`.
///
/// Supports formats:
/// - `"7d"`, `"30m"`, `"1h"`, `"2s"`
/// - `"1 hour"`, `"2 days"`, `"30 seconds"`
/// - `"-5m"`, `"+ 10s"`, `"2 hours ago"`
pub fn ms(value: &str) -> Result<i64, String> {
    parse_time_string(value)
}

/// Parse a time string and return the value in seconds.
///
/// Matches TS `sec()`.
pub fn sec(value: &str) -> Result<i64, String> {
    let millis = parse_time_string(value)?;
    Ok((millis as f64 / 1000.0).round() as i64)
}

fn parse_time_string(value: &str) -> Result<i64, String> {
    let value = value.trim();

    // Regex: optional sign, number, unit, optional "ago"/"from now"
    let re = regex::Regex::new(
        r"(?i)^([+\-])?\s*(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|months?|mo|years?|yrs?|y)(?:\s+(ago|from now))?$"
    ).unwrap();

    let caps = re.captures(value).ok_or_else(|| {
        format!(
            "Invalid time string format: \"{}\". Use formats like \"7d\", \"30m\", \"1 hour\".",
            value
        )
    })?;

    // Can't have both prefix sign and suffix
    if caps.get(1).is_some() && caps.get(4).is_some() {
        return Err(format!("Invalid time string format: \"{}\"", value));
    }

    let n: f64 = caps[2].parse().map_err(|_| format!("Invalid number in: {}", value))?;
    let unit = caps[3].to_lowercase();

    let multiplier: f64 = match unit.as_str() {
        "years" | "year" | "yrs" | "yr" | "y" => YEAR_MS as f64,
        "months" | "month" | "mo" => MONTH_MS as f64,
        "weeks" | "week" | "w" => WEEK_MS as f64,
        "days" | "day" | "d" => DAY_MS as f64,
        "hours" | "hour" | "hrs" | "hr" | "h" => HOUR_MS as f64,
        "minutes" | "minute" | "mins" | "min" | "m" => MIN_MS as f64,
        "seconds" | "second" | "secs" | "sec" | "s" => SEC_MS as f64,
        _ => return Err(format!("Unknown time unit: \"{}\"", unit)),
    };

    let result = (n * multiplier) as i64;

    // Check for negation
    let is_negative = caps.get(1).map_or(false, |m| m.as_str() == "-")
        || caps.get(4).map_or(false, |m| m.as_str().eq_ignore_ascii_case("ago"));

    Ok(if is_negative { -result } else { result })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ms_basic() {
        assert_eq!(ms("1d").unwrap(), 86_400_000);
        assert_eq!(ms("2h").unwrap(), 7_200_000);
        assert_eq!(ms("30s").unwrap(), 30_000);
        assert_eq!(ms("5m").unwrap(), 300_000);
    }

    #[test]
    fn test_ms_long_form() {
        assert_eq!(ms("1 day").unwrap(), 86_400_000);
        assert_eq!(ms("2 hours").unwrap(), 7_200_000);
        assert_eq!(ms("30 seconds").unwrap(), 30_000);
    }

    #[test]
    fn test_ms_negative() {
        assert_eq!(ms("-5m").unwrap(), -300_000);
        assert_eq!(ms("2 hours ago").unwrap(), -7_200_000);
    }

    #[test]
    fn test_sec() {
        assert_eq!(sec("1d").unwrap(), 86_400);
        assert_eq!(sec("2h").unwrap(), 7_200);
        assert_eq!(sec("-30s").unwrap(), -30);
    }

    #[test]
    fn test_weeks_and_months() {
        assert_eq!(ms("1w").unwrap(), 604_800_000);
        assert_eq!(ms("1mo").unwrap(), 2_592_000_000);
    }

    #[test]
    fn test_invalid() {
        assert!(ms("invalid").is_err());
        assert!(ms("").is_err());
    }
}
