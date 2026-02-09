// Sea-ORM query builder — converts core adapter types into sea-query statements.

use better_auth_core::db::adapter::{
    Connector, FindManyQuery, Operator, SortDirection, WhereClause,
};
use better_auth_core::db::schema::{AuthSchema, FieldType};
use sea_query::{Alias, Condition, Expr, Iden, IntoCondition, Order, Query, SimpleExpr, SqliteQueryBuilder, Value};

/// Dynamic table identifier.
#[derive(Debug, Clone)]
pub struct DynTable(pub String);

impl Iden for DynTable {
    fn unquoted(&self, s: &mut dyn std::fmt::Write) {
        write!(s, "{}", self.0).unwrap();
    }
}

/// Dynamic column identifier.
#[derive(Debug, Clone)]
pub struct DynCol(pub String);

impl Iden for DynCol {
    fn unquoted(&self, s: &mut dyn std::fmt::Write) {
        write!(s, "{}", self.0).unwrap();
    }
}

/// Convert WhereClause slice to a sea-query Condition.
pub fn build_condition(clauses: &[WhereClause]) -> Condition {
    if clauses.is_empty() {
        return Condition::all();
    }

    // Collect all expressions, grouping OR-connected ones
    let mut and_exprs: Vec<SimpleExpr> = Vec::new();
    let mut or_exprs: Vec<SimpleExpr> = Vec::new();

    for (i, clause) in clauses.iter().enumerate() {
        let expr = match_clause_to_expr(clause);

        if i > 0 && matches!(clauses[i - 1].connector, Some(Connector::Or)) {
            // Previous clause connected via OR
            or_exprs.push(expr);
        } else {
            // Flush any OR group
            if !or_exprs.is_empty() {
                let mut or_cond = Condition::any();
                for oe in or_exprs.drain(..) {
                    or_cond = or_cond.add(oe);
                }
                and_exprs.push(or_cond.into_condition().into());
            }
            or_exprs.push(expr);
        }

        // Check if this clause connects to next via OR
        if !matches!(clause.connector, Some(Connector::Or)) {
            // End of OR chain, single expr
            if or_exprs.len() == 1 {
                and_exprs.push(or_exprs.pop().unwrap());
            } else if or_exprs.len() > 1 {
                let mut or_cond = Condition::any();
                for oe in or_exprs.drain(..) {
                    or_cond = or_cond.add(oe);
                }
                and_exprs.push(or_cond.into_condition().into());
            }
        }
    }

    // Flush remaining
    if or_exprs.len() == 1 {
        and_exprs.push(or_exprs.pop().unwrap());
    } else if or_exprs.len() > 1 {
        let mut or_cond = Condition::any();
        for oe in or_exprs.drain(..) {
            or_cond = or_cond.add(oe);
        }
        and_exprs.push(or_cond.into_condition().into());
    }

    let mut cond = Condition::all();
    for e in and_exprs {
        cond = cond.add(e);
    }
    cond
}

/// Convert a single WhereClause to a SimpleExpr.
fn match_clause_to_expr(clause: &WhereClause) -> sea_query::SimpleExpr {
    let col = Expr::col(DynCol(clause.field.clone()));

    match clause.value {
        serde_json::Value::Null => match clause.operator {
            Operator::Ne => col.is_not_null(),
            _ => col.is_null(),
        },
        _ => {
            let val = json_to_value(&clause.value);
            match clause.operator {
                Operator::Eq => col.eq(val),
                Operator::Ne => col.ne(val),
                Operator::Lt => col.lt(val),
                Operator::Lte => col.lte(val),
                Operator::Gt => col.gt(val),
                Operator::Gte => col.gte(val),
                Operator::In => {
                    if let serde_json::Value::Array(arr) = &clause.value {
                        let vals: Vec<Value> = arr.iter().map(json_to_value).collect();
                        col.is_in(vals)
                    } else {
                        col.eq(val)
                    }
                }
                Operator::Contains => {
                    let s = clause.value.as_str().unwrap_or("");
                    col.like(format!("%{}%", s))
                }
                Operator::StartsWith => {
                    let s = clause.value.as_str().unwrap_or("");
                    col.like(format!("{}%", s))
                }
                Operator::EndsWith => {
                    let s = clause.value.as_str().unwrap_or("");
                    col.like(format!("%{}", s))
                }
            }
        }
    }
}

/// Convert JSON value to sea-query Value.
pub fn json_to_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::String(s) => Value::String(Some(Box::new(s.clone()))),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::BigInt(Some(i))
            } else if let Some(f) = n.as_f64() {
                Value::Double(Some(f))
            } else {
                Value::String(Some(Box::new(n.to_string())))
            }
        }
        serde_json::Value::Bool(b) => Value::Bool(Some(*b)),
        serde_json::Value::Null => Value::String(None),
        _ => Value::String(Some(Box::new(v.to_string()))),
    }
}

/// Build a SELECT query string.
pub fn build_select(model: &str, query: &FindManyQuery) -> String {
    let table = DynTable(model.to_string());
    let mut select = Query::select();
    select.from(table).column(Alias::new("*"));

    // WHERE
    let cond = build_condition(&query.where_clauses);
    select.cond_where(cond);

    // ORDER BY
    if let Some(ref sort) = query.sort_by {
        let order = match sort.direction {
            SortDirection::Asc => Order::Asc,
            SortDirection::Desc => Order::Desc,
        };
        select.order_by(DynCol(sort.field.clone()), order);
    }

    // LIMIT / OFFSET
    if let Some(limit) = query.limit {
        select.limit(limit as u64);
    }
    if let Some(offset) = query.offset {
        select.offset(offset as u64);
    }

    select.to_string(SqliteQueryBuilder)
}

/// Build a COUNT query string.
pub fn build_count(model: &str, clauses: &[WhereClause]) -> String {
    let table = DynTable(model.to_string());
    let mut select = Query::select();
    select
        .from(table)
        .expr_as(Expr::col(Alias::new("*")).count(), Alias::new("count"));
    select.cond_where(build_condition(clauses));
    select.to_string(SqliteQueryBuilder)
}

/// Build an INSERT query string.
pub fn build_insert(model: &str, data: &serde_json::Value) -> String {
    let table = DynTable(model.to_string());
    let mut insert = Query::insert();
    insert.into_table(table);

    if let Some(obj) = data.as_object() {
        let cols: Vec<DynCol> = obj.keys().map(|k| DynCol(k.clone())).collect();
        let vals: Vec<SimpleExpr> = obj.values().map(|v| Expr::val(json_to_value(v)).into()).collect();
        insert.columns(cols);
        insert.values_panic(vals);
    }

    insert.to_string(SqliteQueryBuilder)
}

/// Build an UPDATE query string.
pub fn build_update(model: &str, where_clauses: &[WhereClause], data: &serde_json::Value) -> String {
    let table = DynTable(model.to_string());
    let mut update = Query::update();
    update.table(table);

    if let Some(obj) = data.as_object() {
        for (key, val) in obj {
            update.value(DynCol(key.clone()), json_to_value(val));
        }
    }

    update.cond_where(build_condition(where_clauses));
    update.to_string(SqliteQueryBuilder)
}

/// Build a DELETE query string.
pub fn build_delete(model: &str, where_clauses: &[WhereClause]) -> String {
    let table = DynTable(model.to_string());
    let mut delete = Query::delete();
    delete.from_table(table);
    delete.cond_where(build_condition(where_clauses));
    delete.to_string(SqliteQueryBuilder)
}

/// Generate DDL statements from an AuthSchema.
pub fn build_schema_ddl(schema: &AuthSchema) -> Vec<String> {
    let mut stmts = Vec::new();

    for (table_name, table) in &schema.tables {
        let mut cols = Vec::new();
        let mut fks = Vec::new();

        for (field_name, field) in &table.fields {
            let col_type = match field.field_type {
                FieldType::String => "TEXT",
                FieldType::Number => "INTEGER",
                FieldType::Boolean => "BOOLEAN",
                FieldType::Date => "TIMESTAMP",
            };

            let mut col_def = format!("\"{}\" {}", field_name, col_type);
            if field_name == "id" {
                col_def.push_str(" PRIMARY KEY");
            }
            if field.required && field_name != "id" {
                col_def.push_str(" NOT NULL");
            }
            if field.unique {
                col_def.push_str(" UNIQUE");
            }
            if let Some(ref default) = field.default_value {
                match default {
                    serde_json::Value::String(s) => col_def.push_str(&format!(" DEFAULT '{}'", s)),
                    serde_json::Value::Bool(b) => col_def.push_str(&format!(" DEFAULT {}", if *b { "TRUE" } else { "FALSE" })),
                    serde_json::Value::Number(n) => col_def.push_str(&format!(" DEFAULT {}", n)),
                    _ => {}
                }
            }
            cols.push(col_def);

            if let Some(ref reference) = field.references {
                fks.push(format!(
                    "FOREIGN KEY (\"{}\") REFERENCES \"{}\"(\"{}\") ON DELETE CASCADE",
                    field_name, reference.model, reference.field
                ));
            }
        }

        let mut all_defs = cols;
        all_defs.extend(fks);

        stmts.push(format!(
            "CREATE TABLE IF NOT EXISTS \"{}\" ({})",
            table_name,
            all_defs.join(", ")
        ));
    }

    stmts
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::db::adapter::SortBy;

    #[test]
    fn test_build_select_all() {
        let query = FindManyQuery::default();
        let sql = build_select("user", &query);
        assert!(sql.contains("SELECT"));
        assert!(sql.contains("user"));
    }

    #[test]
    fn test_build_select_with_where() {
        let query = FindManyQuery {
            where_clauses: vec![WhereClause::eq("id", "u1")],
            ..Default::default()
        };
        let sql = build_select("user", &query);
        assert!(sql.contains("WHERE"));
        assert!(sql.contains("id"));
    }

    #[test]
    fn test_build_select_with_limit_offset() {
        let query = FindManyQuery {
            limit: Some(10),
            offset: Some(5),
            ..Default::default()
        };
        let sql = build_select("user", &query);
        assert!(sql.contains("LIMIT"));
        assert!(sql.contains("OFFSET"));
    }

    #[test]
    fn test_build_select_with_sort() {
        let query = FindManyQuery {
            sort_by: Some(SortBy {
                field: "name".into(),
                direction: SortDirection::Desc,
            }),
            ..Default::default()
        };
        let sql = build_select("user", &query);
        assert!(sql.contains("ORDER BY"));
        assert!(sql.contains("DESC"));
    }

    #[test]
    fn test_build_count() {
        let sql = build_count("user", &[WhereClause::eq("active", true)]);
        assert!(sql.contains("COUNT"));
    }

    #[test]
    fn test_build_insert() {
        let data = serde_json::json!({"id": "u1", "name": "Alice"});
        let sql = build_insert("user", &data);
        assert!(sql.contains("INSERT INTO"));
        assert!(sql.contains("user"));
    }

    #[test]
    fn test_build_update() {
        let data = serde_json::json!({"name": "Bob"});
        let sql = build_update("user", &[WhereClause::eq("id", "u1")], &data);
        assert!(sql.contains("UPDATE"));
        assert!(sql.contains("SET"));
    }

    #[test]
    fn test_build_delete() {
        let sql = build_delete("user", &[WhereClause::eq("id", "u1")]);
        assert!(sql.contains("DELETE FROM"));
    }
}
