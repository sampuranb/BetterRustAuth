// Query builder — converts core adapter types into SQL fragments.
//
// This module generates dynamic SQL strings with positional bind parameters ($1, $2, ...)
// for use with sqlx's `query()` / `query_as()` functions.

use better_auth_core::db::adapter::{
    Connector, FindManyQuery, Operator, SortDirection, WhereClause,
};

/// A built SQL fragment with its bind values.
#[derive(Debug, Clone)]
pub struct SqlFragment {
    /// The SQL string with $N placeholders.
    pub sql: String,
    /// The bind values in order.
    pub binds: Vec<serde_json::Value>,
}

impl SqlFragment {
    pub fn empty() -> Self {
        Self {
            sql: String::new(),
            binds: Vec::new(),
        }
    }
}

/// Build a WHERE clause from a slice of `WhereClause`.
///
/// Returns the SQL fragment starting with " WHERE ..." and the bind values.
/// If the slice is empty, returns an empty fragment.
pub fn build_where(clauses: &[WhereClause], bind_offset: usize) -> SqlFragment {
    if clauses.is_empty() {
        return SqlFragment::empty();
    }

    let mut sql = String::from(" WHERE ");
    let mut binds = Vec::new();
    let mut param_idx = bind_offset + 1;

    for (i, clause) in clauses.iter().enumerate() {
        if i > 0 {
            // The connector is set on the *previous* clause (e.g. `.and()` / `.or()`)
            let connector = clauses[i - 1].connector.as_ref().unwrap_or(&Connector::And);
            match connector {
                Connector::And => sql.push_str(" AND "),
                Connector::Or => sql.push_str(" OR "),
            }
        }

        let quoted_field = quote_identifier(&clause.field);

        match clause.operator {
            Operator::Eq => {
                if clause.value.is_null() {
                    sql.push_str(&format!("{} IS NULL", quoted_field));
                } else {
                    sql.push_str(&format!("{} = ${}", quoted_field, param_idx));
                    binds.push(clause.value.clone());
                    param_idx += 1;
                }
            }
            Operator::Ne => {
                if clause.value.is_null() {
                    sql.push_str(&format!("{} IS NOT NULL", quoted_field));
                } else {
                    sql.push_str(&format!("{} != ${}", quoted_field, param_idx));
                    binds.push(clause.value.clone());
                    param_idx += 1;
                }
            }
            Operator::Lt => {
                sql.push_str(&format!("{} < ${}", quoted_field, param_idx));
                binds.push(clause.value.clone());
                param_idx += 1;
            }
            Operator::Lte => {
                sql.push_str(&format!("{} <= ${}", quoted_field, param_idx));
                binds.push(clause.value.clone());
                param_idx += 1;
            }
            Operator::Gt => {
                sql.push_str(&format!("{} > ${}", quoted_field, param_idx));
                binds.push(clause.value.clone());
                param_idx += 1;
            }
            Operator::Gte => {
                sql.push_str(&format!("{} >= ${}", quoted_field, param_idx));
                binds.push(clause.value.clone());
                param_idx += 1;
            }
            Operator::In => {
                if let Some(arr) = clause.value.as_array() {
                    let placeholders: Vec<String> = arr
                        .iter()
                        .map(|v| {
                            let p = format!("${}", param_idx);
                            binds.push(v.clone());
                            param_idx += 1;
                            p
                        })
                        .collect();
                    sql.push_str(&format!(
                        "{} IN ({})",
                        quoted_field,
                        placeholders.join(", ")
                    ));
                } else {
                    // Single value IN
                    sql.push_str(&format!("{} = ${}", quoted_field, param_idx));
                    binds.push(clause.value.clone());
                    param_idx += 1;
                }
            }
            Operator::Contains => {
                sql.push_str(&format!("{} LIKE ${}", quoted_field, param_idx));
                let val = format!(
                    "%{}%",
                    clause.value.as_str().unwrap_or_default()
                );
                binds.push(serde_json::Value::String(val));
                param_idx += 1;
            }
            Operator::StartsWith => {
                sql.push_str(&format!("{} LIKE ${}", quoted_field, param_idx));
                let val = format!(
                    "{}%",
                    clause.value.as_str().unwrap_or_default()
                );
                binds.push(serde_json::Value::String(val));
                param_idx += 1;
            }
            Operator::EndsWith => {
                sql.push_str(&format!("{} LIKE ${}", quoted_field, param_idx));
                let val = format!(
                    "%{}",
                    clause.value.as_str().unwrap_or_default()
                );
                binds.push(serde_json::Value::String(val));
                param_idx += 1;
            }
        }
    }

    SqlFragment { sql, binds }
}

/// Build an ORDER BY clause from a `FindManyQuery`.
pub fn build_order_by(query: &FindManyQuery) -> String {
    match &query.sort_by {
        Some(sort) => {
            let dir = match sort.direction {
                SortDirection::Asc => "ASC",
                SortDirection::Desc => "DESC",
            };
            format!(" ORDER BY {} {}", quote_identifier(&sort.field), dir)
        }
        None => String::new(),
    }
}

/// Build LIMIT and OFFSET clauses.
pub fn build_limit_offset(query: &FindManyQuery) -> String {
    let mut sql = String::new();
    if let Some(limit) = query.limit {
        sql.push_str(&format!(" LIMIT {}", limit));
    } else if query.offset.is_some() {
        // SQLite requires LIMIT before OFFSET. Use -1 for unlimited.
        sql.push_str(" LIMIT -1");
    }
    if let Some(offset) = query.offset {
        sql.push_str(&format!(" OFFSET {}", offset));
    }
    sql
}

/// Build an INSERT statement.
///
/// Returns the full INSERT SQL and bind values.
pub fn build_insert(table: &str, data: &serde_json::Value) -> SqlFragment {
    let obj = match data.as_object() {
        Some(o) => o,
        None => {
            return SqlFragment {
                sql: String::new(),
                binds: Vec::new(),
            };
        }
    };

    let mut columns = Vec::new();
    let mut placeholders = Vec::new();
    let mut binds = Vec::new();
    let mut param_idx = 1;

    for (key, value) in obj {
        columns.push(quote_identifier(key));
        placeholders.push(format!("${}", param_idx));
        binds.push(value.clone());
        param_idx += 1;
    }

    let sql = format!(
        "INSERT INTO {} ({}) VALUES ({})",
        quote_identifier(table),
        columns.join(", "),
        placeholders.join(", ")
    );

    SqlFragment { sql, binds }
}

/// Build an UPDATE SET clause from a JSON object.
///
/// Returns the SET portion and bind values.
pub fn build_update_set(data: &serde_json::Value, bind_offset: usize) -> SqlFragment {
    let obj = match data.as_object() {
        Some(o) => o,
        None => return SqlFragment::empty(),
    };

    let mut set_parts = Vec::new();
    let mut binds = Vec::new();
    let mut param_idx = bind_offset + 1;

    for (key, value) in obj {
        set_parts.push(format!("{} = ${}", quote_identifier(key), param_idx));
        binds.push(value.clone());
        param_idx += 1;
    }

    SqlFragment {
        sql: set_parts.join(", "),
        binds,
    }
}

/// Quote a SQL identifier (table/column name) to prevent injection.
/// Uses double-quotes which work for SQLite, Postgres. MySQL would need backticks.
pub fn quote_identifier(name: &str) -> String {
    // Simple quoting — reject names with double-quotes
    let clean = name.replace('"', "");
    format!("\"{}\"", clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_where_empty() {
        let frag = build_where(&[], 0);
        assert!(frag.sql.is_empty());
        assert!(frag.binds.is_empty());
    }

    #[test]
    fn test_build_where_eq() {
        let clauses = vec![WhereClause::eq("email", "test@example.com")];
        let frag = build_where(&clauses, 0);
        assert_eq!(frag.sql, " WHERE \"email\" = $1");
        assert_eq!(frag.binds.len(), 1);
    }

    #[test]
    fn test_build_where_null() {
        let clauses = vec![WhereClause {
            field: "deleted_at".into(),
            value: serde_json::Value::Null,
            operator: Operator::Eq,
            connector: None,
        }];
        let frag = build_where(&clauses, 0);
        assert_eq!(frag.sql, " WHERE \"deleted_at\" IS NULL");
        assert!(frag.binds.is_empty());
    }

    #[test]
    fn test_build_where_and() {
        let clauses = vec![
            WhereClause::eq("provider_id", "google").and(),
            WhereClause::eq("account_id", "123"),
        ];
        let frag = build_where(&clauses, 0);
        assert_eq!(
            frag.sql,
            " WHERE \"provider_id\" = $1 AND \"account_id\" = $2"
        );
        assert_eq!(frag.binds.len(), 2);
    }

    #[test]
    fn test_build_where_or() {
        let clauses = vec![
            WhereClause::eq("status", "active").or(),
            WhereClause::eq("status", "pending"),
        ];
        let frag = build_where(&clauses, 0);
        assert!(frag.sql.contains(" OR "));
    }

    #[test]
    fn test_build_where_in() {
        let clauses = vec![WhereClause {
            field: "id".into(),
            value: serde_json::json!(["a", "b", "c"]),
            operator: Operator::In,
            connector: None,
        }];
        let frag = build_where(&clauses, 0);
        assert_eq!(frag.sql, " WHERE \"id\" IN ($1, $2, $3)");
        assert_eq!(frag.binds.len(), 3);
    }

    #[test]
    fn test_build_where_contains() {
        let clauses = vec![WhereClause {
            field: "name".into(),
            value: serde_json::json!("john"),
            operator: Operator::Contains,
            connector: None,
        }];
        let frag = build_where(&clauses, 0);
        assert_eq!(frag.sql, " WHERE \"name\" LIKE $1");
        assert_eq!(frag.binds[0], serde_json::json!("%john%"));
    }

    #[test]
    fn test_build_insert() {
        let data = serde_json::json!({
            "id": "abc",
            "email": "test@example.com"
        });
        let frag = build_insert("user", &data);
        assert!(frag.sql.starts_with("INSERT INTO \"user\""));
        assert_eq!(frag.binds.len(), 2);
    }

    #[test]
    fn test_build_update_set() {
        let data = serde_json::json!({
            "name": "John",
            "email": "john@example.com"
        });
        let frag = build_update_set(&data, 0);
        // JSON key ordering is not guaranteed, just check both keys are present
        assert!(frag.sql.contains("\"name\" = "));
        assert!(frag.sql.contains("\"email\" = "));
        assert_eq!(frag.binds.len(), 2);
    }

    #[test]
    fn test_quote_identifier() {
        assert_eq!(quote_identifier("user"), "\"user\"");
        assert_eq!(quote_identifier("my_table"), "\"my_table\"");
        // Injection attempt stripped
        assert_eq!(quote_identifier("a\"b"), "\"ab\"");
    }
}
