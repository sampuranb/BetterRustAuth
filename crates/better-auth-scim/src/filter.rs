//! SCIM filter parsing (RFC 7644 §3.4.2.2).
//! Supports basic SCIM filter expressions.

use serde_json::Value;

/// A parsed SCIM filter expression.
#[derive(Debug, Clone, PartialEq)]
pub enum ScimFilter {
    /// attribute eq value
    Eq(String, String),
    /// attribute ne value
    Ne(String, String),
    /// attribute co value (contains)
    Co(String, String),
    /// attribute sw value (starts with)
    Sw(String, String),
    /// attribute ew value (ends with)
    Ew(String, String),
    /// attribute pr (present)
    Pr(String),
    /// filter and filter
    And(Box<ScimFilter>, Box<ScimFilter>),
    /// filter or filter
    Or(Box<ScimFilter>, Box<ScimFilter>),
    /// not filter
    Not(Box<ScimFilter>),
}

/// Parse a simple SCIM filter expression.
/// Supports: `attr eq "value"`, `attr ne "value"`, `attr co "value"`,
/// `attr sw "value"`, `attr ew "value"`, `attr pr`
pub fn parse_filter(input: &str) -> Option<ScimFilter> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }

    // Check for "and" / "or" (simple split, no precedence)
    if let Some(pos) = input.find(" and ") {
        let left = parse_filter(&input[..pos])?;
        let right = parse_filter(&input[pos + 5..])?;
        return Some(ScimFilter::And(Box::new(left), Box::new(right)));
    }
    if let Some(pos) = input.find(" or ") {
        let left = parse_filter(&input[..pos])?;
        let right = parse_filter(&input[pos + 4..])?;
        return Some(ScimFilter::Or(Box::new(left), Box::new(right)));
    }

    let parts: Vec<&str> = input.splitn(3, ' ').collect();

    match parts.len() {
        2 if parts[1].eq_ignore_ascii_case("pr") => {
            Some(ScimFilter::Pr(parts[0].to_string()))
        }
        3 => {
            let attr = parts[0].to_string();
            let value = parts[2].trim_matches('"').to_string();
            match parts[1].to_lowercase().as_str() {
                "eq" => Some(ScimFilter::Eq(attr, value)),
                "ne" => Some(ScimFilter::Ne(attr, value)),
                "co" => Some(ScimFilter::Co(attr, value)),
                "sw" => Some(ScimFilter::Sw(attr, value)),
                "ew" => Some(ScimFilter::Ew(attr, value)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Evaluate a SCIM filter against a JSON value.
pub fn matches_filter(value: &Value, filter: &ScimFilter) -> bool {
    match filter {
        ScimFilter::Eq(attr, expected) => {
            get_string_field(value, attr)
                .map(|v| v.eq_ignore_ascii_case(expected))
                .unwrap_or(false)
        }
        ScimFilter::Ne(attr, expected) => {
            get_string_field(value, attr)
                .map(|v| !v.eq_ignore_ascii_case(expected))
                .unwrap_or(true)
        }
        ScimFilter::Co(attr, substr) => {
            get_string_field(value, attr)
                .map(|v| v.to_lowercase().contains(&substr.to_lowercase()))
                .unwrap_or(false)
        }
        ScimFilter::Sw(attr, prefix) => {
            get_string_field(value, attr)
                .map(|v| v.to_lowercase().starts_with(&prefix.to_lowercase()))
                .unwrap_or(false)
        }
        ScimFilter::Ew(attr, suffix) => {
            get_string_field(value, attr)
                .map(|v| v.to_lowercase().ends_with(&suffix.to_lowercase()))
                .unwrap_or(false)
        }
        ScimFilter::Pr(attr) => {
            get_field(value, attr).is_some()
        }
        ScimFilter::And(left, right) => {
            matches_filter(value, left) && matches_filter(value, right)
        }
        ScimFilter::Or(left, right) => {
            matches_filter(value, left) || matches_filter(value, right)
        }
        ScimFilter::Not(inner) => {
            !matches_filter(value, inner)
        }
    }
}

fn get_field<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = value;
    for part in parts {
        current = current.get(part)?;
    }
    Some(current)
}

fn get_string_field(value: &Value, path: &str) -> Option<String> {
    get_field(value, path).and_then(|v| v.as_str().map(String::from))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_eq_filter() {
        let filter = parse_filter(r#"userName eq "john""#).unwrap();
        assert_eq!(filter, ScimFilter::Eq("userName".into(), "john".into()));
    }

    #[test]
    fn test_parse_pr_filter() {
        let filter = parse_filter("emails pr").unwrap();
        assert_eq!(filter, ScimFilter::Pr("emails".into()));
    }

    #[test]
    fn test_parse_and_filter() {
        let filter = parse_filter(r#"userName eq "john" and active eq "true""#).unwrap();
        assert!(matches!(filter, ScimFilter::And(_, _)));
    }

    #[test]
    fn test_matches_eq() {
        let user = json!({"userName": "john", "active": true});
        let filter = ScimFilter::Eq("userName".into(), "john".into());
        assert!(matches_filter(&user, &filter));

        let filter = ScimFilter::Eq("userName".into(), "jane".into());
        assert!(!matches_filter(&user, &filter));
    }

    #[test]
    fn test_matches_co() {
        let user = json!({"userName": "john.doe@example.com"});
        let filter = ScimFilter::Co("userName".into(), "doe".into());
        assert!(matches_filter(&user, &filter));
    }

    #[test]
    fn test_matches_sw() {
        let user = json!({"userName": "john.doe"});
        let filter = ScimFilter::Sw("userName".into(), "john".into());
        assert!(matches_filter(&user, &filter));
    }

    #[test]
    fn test_matches_pr() {
        let user = json!({"userName": "john", "email": "john@example.com"});
        assert!(matches_filter(&user, &ScimFilter::Pr("email".into())));
        assert!(!matches_filter(&user, &ScimFilter::Pr("phone".into())));
    }

    #[test]
    fn test_matches_and() {
        let user = json!({"userName": "john", "active": "true"});
        let filter = ScimFilter::And(
            Box::new(ScimFilter::Eq("userName".into(), "john".into())),
            Box::new(ScimFilter::Eq("active".into(), "true".into())),
        );
        assert!(matches_filter(&user, &filter));
    }
}
