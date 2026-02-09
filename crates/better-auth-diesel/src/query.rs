// Diesel query builder — converts core adapter types into Diesel-compatible SQL.
//
// Uses raw SQL through Diesel's `sql_query` for dynamic queries, since the
// core Adapter trait operates on dynamic model/table names at runtime, which
// doesn't align with Diesel's compile-time schema DSL.

use better_auth_core::db::adapter::{
    Connector, FindManyQuery, Operator, SortDirection, WhereClause,
};

/// A built SQL fragment with bind values.
#[derive(Debug, Clone)]
pub struct SqlFragment {
    pub sql: String,
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

/// Quote a SQL identifier (table/column name) using double quotes.
pub fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Build a WHERE clause from WhereClause slice.
pub fn build_where(clauses: &[WhereClause], bind_offset: usize) -> SqlFragment {
    if clauses.is_empty() {
        return SqlFragment::empty();
    }

    let mut sql_parts = Vec::new();
    let mut binds = Vec::new();
    let mut idx = bind_offset;

    for (i, clause) in clauses.iter().enumerate() {
        if i > 0 {
            let connector = match clauses[i - 1].connector {
                Some(Connector::Or) => " OR ",
                _ => " AND ",
            };
            sql_parts.push(connector.to_string());
        }

        match clause.value {
            serde_json::Value::Null => match clause.operator {
                Operator::Eq => {
                    sql_parts.push(format!("{} IS NULL", quote_ident(&clause.field)));
                }
                Operator::Ne => {
                    sql_parts.push(format!("{} IS NOT NULL", quote_ident(&clause.field)));
                }
                _ => {
                    sql_parts.push(format!("{} IS NULL", quote_ident(&clause.field)));
                }
            },
            _ => {
                match clause.operator {
                    Operator::Eq => {
                        idx += 1;
                        sql_parts.push(format!("{} = ${}", quote_ident(&clause.field), idx));
                        binds.push(clause.value.clone());
                    }
                    Operator::Ne => {
                        idx += 1;
                        sql_parts.push(format!("{} != ${}", quote_ident(&clause.field), idx));
                        binds.push(clause.value.clone());
                    }
                    Operator::Lt => {
                        idx += 1;
                        sql_parts.push(format!("{} < ${}", quote_ident(&clause.field), idx));
                        binds.push(clause.value.clone());
                    }
                    Operator::Lte => {
                        idx += 1;
                        sql_parts.push(format!("{} <= ${}", quote_ident(&clause.field), idx));
                        binds.push(clause.value.clone());
                    }
                    Operator::Gt => {
                        idx += 1;
                        sql_parts.push(format!("{} > ${}", quote_ident(&clause.field), idx));
                        binds.push(clause.value.clone());
                    }
                    Operator::Gte => {
                        idx += 1;
                        sql_parts.push(format!("{} >= ${}", quote_ident(&clause.field), idx));
                        binds.push(clause.value.clone());
                    }
                    Operator::In => {
                        if let serde_json::Value::Array(arr) = &clause.value {
                            let placeholders: Vec<String> = arr
                                .iter()
                                .map(|v| {
                                    idx += 1;
                                    binds.push(v.clone());
                                    format!("${}", idx)
                                })
                                .collect();
                            sql_parts.push(format!(
                                "{} IN ({})",
                                quote_ident(&clause.field),
                                placeholders.join(", ")
                            ));
                        }
                    }
                    Operator::Contains => {
                        idx += 1;
                        sql_parts.push(format!("{} LIKE ${}", quote_ident(&clause.field), idx));
                        let s = clause.value.as_str().unwrap_or("");
                        binds.push(serde_json::json!(format!("%{}%", s)));
                    }
                    Operator::StartsWith => {
                        idx += 1;
                        sql_parts.push(format!("{} LIKE ${}", quote_ident(&clause.field), idx));
                        let s = clause.value.as_str().unwrap_or("");
                        binds.push(serde_json::json!(format!("{}%", s)));
                    }
                    Operator::EndsWith => {
                        idx += 1;
                        sql_parts.push(format!("{} LIKE ${}", quote_ident(&clause.field), idx));
                        let s = clause.value.as_str().unwrap_or("");
                        binds.push(serde_json::json!(format!("%{}", s)));
                    }
                }
            }
        }
    }

    SqlFragment {
        sql: format!(" WHERE {}", sql_parts.join("")),
        binds,
    }
}

/// Build an INSERT statement.
pub fn build_insert(table: &str, data: &serde_json::Value) -> SqlFragment {
    let obj = match data.as_object() {
        Some(o) => o,
        None => {
            return SqlFragment {
                sql: format!("INSERT INTO {} DEFAULT VALUES", quote_ident(table)),
                binds: Vec::new(),
            }
        }
    };

    let mut columns = Vec::new();
    let mut placeholders = Vec::new();
    let mut binds = Vec::new();
    let mut idx = 0;

    for (key, val) in obj {
        columns.push(quote_ident(key));
        idx += 1;
        placeholders.push(format!("${}", idx));
        binds.push(val.clone());
    }

    SqlFragment {
        sql: format!(
            "INSERT INTO {} ({}) VALUES ({})",
            quote_ident(table),
            columns.join(", "),
            placeholders.join(", ")
        ),
        binds,
    }
}

/// Build an UPDATE SET clause.
pub fn build_update_set(data: &serde_json::Value, bind_offset: usize) -> SqlFragment {
    let obj = match data.as_object() {
        Some(o) => o,
        None => return SqlFragment::empty(),
    };

    let mut parts = Vec::new();
    let mut binds = Vec::new();
    let mut idx = bind_offset;

    for (key, val) in obj {
        idx += 1;
        parts.push(format!("{} = ${}", quote_ident(key), idx));
        binds.push(val.clone());
    }

    SqlFragment {
        sql: parts.join(", "),
        binds,
    }
}

/// Build ORDER BY clause.
pub fn build_order_by(query: &FindManyQuery) -> String {
    match &query.sort_by {
        Some(sort) => {
            let dir = match sort.direction {
                SortDirection::Asc => "ASC",
                SortDirection::Desc => "DESC",
            };
            format!(" ORDER BY {} {}", quote_ident(&sort.field), dir)
        }
        None => String::new(),
    }
}

/// Build LIMIT/OFFSET clause.
pub fn build_limit_offset(query: &FindManyQuery) -> String {
    let mut s = String::new();
    if let Some(limit) = query.limit {
        s.push_str(&format!(" LIMIT {}", limit));
    }
    if let Some(offset) = query.offset {
        s.push_str(&format!(" OFFSET {}", offset));
    }
    s
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
        let clauses = vec![WhereClause::eq("id", "u1")];
        let frag = build_where(&clauses, 0);
        assert!(frag.sql.contains("\"id\" = $1"));
        assert_eq!(frag.binds.len(), 1);
    }

    #[test]
    fn test_build_insert() {
        let data = serde_json::json!({"id": "u1", "name": "Alice"});
        let frag = build_insert("user", &data);
        assert!(frag.sql.starts_with("INSERT INTO \"user\""));
        assert_eq!(frag.binds.len(), 2);
    }

    #[test]
    fn test_build_update_set() {
        let data = serde_json::json!({"name": "Bob"});
        let frag = build_update_set(&data, 0);
        assert!(frag.sql.contains("\"name\" = $1"));
        assert_eq!(frag.binds.len(), 1);
    }

    #[test]
    fn test_quote_ident() {
        assert_eq!(quote_ident("user"), "\"user\"");
        assert_eq!(quote_ident("my\"table"), "\"my\"\"table\"");
    }
}
