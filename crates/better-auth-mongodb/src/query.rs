// MongoDB query builder — converts core adapter types into MongoDB BSON documents.

use better_auth_core::db::adapter::{
    Connector, FindManyQuery, Operator, SortDirection, WhereClause,
};
use mongodb::bson::{doc, Bson, Document};

/// Convert WhereClause slice to a MongoDB filter document.
pub fn build_filter(clauses: &[WhereClause]) -> Document {
    if clauses.is_empty() {
        return doc! {};
    }

    let mut and_conditions: Vec<Document> = Vec::new();
    let mut or_group: Vec<Document> = Vec::new();
    let mut in_or = false;

    for (_i, clause) in clauses.iter().enumerate() {
        let field_filter = match_clause_to_doc(clause);

        if in_or {
            or_group.push(field_filter);
        } else {
            // If previous clause had OR, start collecting into OR group
            and_conditions.push(field_filter);
        }

        // Check if this clause connects to the next via OR
        if matches!(clause.connector, Some(Connector::Or)) {
            if !in_or {
                // Move the last AND condition into the OR group
                if let Some(last) = and_conditions.pop() {
                    or_group.push(last);
                }
                in_or = true;
            }
        } else if in_or {
            // Flush OR group
            and_conditions.push(doc! { "$or": or_group.clone() });
            or_group.clear();
            in_or = false;
        }
    }

    // Flush any remaining OR group
    if !or_group.is_empty() {
        and_conditions.push(doc! { "$or": or_group });
    }

    if and_conditions.len() == 1 {
        and_conditions.into_iter().next().unwrap()
    } else if and_conditions.is_empty() {
        doc! {}
    } else {
        doc! { "$and": and_conditions }
    }
}

/// Convert a single WhereClause to a MongoDB filter document.
fn match_clause_to_doc(clause: &WhereClause) -> Document {
    let field = if clause.field == "id" { "_id" } else { &clause.field };
    let value = json_to_bson(&clause.value);

    match clause.operator {
        Operator::Eq => doc! { field: value },
        Operator::Ne => doc! { field: { "$ne": value } },
        Operator::Lt => doc! { field: { "$lt": value } },
        Operator::Lte => doc! { field: { "$lte": value } },
        Operator::Gt => doc! { field: { "$gt": value } },
        Operator::Gte => doc! { field: { "$gte": value } },
        Operator::In => {
            if let Bson::Array(arr) = value {
                doc! { field: { "$in": arr } }
            } else {
                doc! { field: { "$in": [value] } }
            }
        }
        Operator::Contains => {
            let s = clause.value.as_str().unwrap_or("");
            doc! { field: { "$regex": regex_escape(s), "$options": "i" } }
        }
        Operator::StartsWith => {
            let s = clause.value.as_str().unwrap_or("");
            doc! { field: { "$regex": format!("^{}", regex_escape(s)) } }
        }
        Operator::EndsWith => {
            let s = clause.value.as_str().unwrap_or("");
            doc! { field: { "$regex": format!("{}$", regex_escape(s)) } }
        }
    }
}

/// Convert serde_json::Value to MongoDB BSON.
pub fn json_to_bson(v: &serde_json::Value) -> Bson {
    match v {
        serde_json::Value::Null => Bson::Null,
        serde_json::Value::Bool(b) => Bson::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Bson::Int64(i)
            } else if let Some(f) = n.as_f64() {
                Bson::Double(f)
            } else {
                Bson::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => Bson::String(s.clone()),
        serde_json::Value::Array(arr) => {
            Bson::Array(arr.iter().map(json_to_bson).collect())
        }
        serde_json::Value::Object(map) => {
            let mut doc = Document::new();
            for (k, v) in map {
                doc.insert(k.clone(), json_to_bson(v));
            }
            Bson::Document(doc)
        }
    }
}

/// Convert BSON to serde_json::Value.
pub fn bson_to_json(b: &Bson) -> serde_json::Value {
    match b {
        Bson::Null => serde_json::Value::Null,
        Bson::Boolean(b) => serde_json::json!(*b),
        Bson::Int32(i) => serde_json::json!(*i),
        Bson::Int64(i) => serde_json::json!(*i),
        Bson::Double(f) => serde_json::json!(*f),
        Bson::String(s) => serde_json::json!(s),
        Bson::ObjectId(oid) => serde_json::json!(oid.to_hex()),
        Bson::Array(arr) => serde_json::Value::Array(arr.iter().map(bson_to_json).collect()),
        Bson::Document(doc) => doc_to_json(doc),
        Bson::DateTime(dt) => serde_json::json!(dt.timestamp_millis()),
        _ => serde_json::Value::Null,
    }
}

/// Convert a MongoDB Document to serde_json::Value.
pub fn doc_to_json(doc: &Document) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (k, v) in doc {
        // Convert _id to id
        let key = if k == "_id" { "id".to_string() } else { k.clone() };
        map.insert(key, bson_to_json(v));
    }
    serde_json::Value::Object(map)
}

/// Convert a JSON data object to a MongoDB insert document.
pub fn build_insert_doc(data: &serde_json::Value) -> Document {
    let mut doc = Document::new();
    if let Some(obj) = data.as_object() {
        for (k, v) in obj {
            // Map "id" to "_id" for MongoDB
            let key = if k == "id" { "_id".to_string() } else { k.clone() };
            doc.insert(key, json_to_bson(v));
        }
    }
    doc
}

/// Convert a JSON data object to a MongoDB $set update document.
pub fn build_update_doc(data: &serde_json::Value) -> Document {
    let mut set = Document::new();
    if let Some(obj) = data.as_object() {
        for (k, v) in obj {
            let key = if k == "id" { "_id".to_string() } else { k.clone() };
            set.insert(key, json_to_bson(v));
        }
    }
    doc! { "$set": set }
}

/// Build sort document from FindManyQuery.
pub fn build_sort(query: &FindManyQuery) -> Option<Document> {
    query.sort_by.as_ref().map(|sort| {
        let direction = match sort.direction {
            SortDirection::Asc => 1,
            SortDirection::Desc => -1,
        };
        let field = if sort.field == "id" { "_id".to_string() } else { sort.field.clone() };
        doc! { field: direction }
    })
}

/// Escape regex special characters.
fn regex_escape(s: &str) -> String {
    let special = ['.', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '^', '$', '\\'];
    let mut escaped = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        if special.contains(&c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_filter_empty() {
        let filter = build_filter(&[]);
        assert_eq!(filter, doc! {});
    }

    #[test]
    fn test_build_filter_eq() {
        let filter = build_filter(&[WhereClause::eq("name", "Alice")]);
        assert_eq!(filter, doc! { "name": "Alice" });
    }

    #[test]
    fn test_build_filter_id_mapping() {
        let filter = build_filter(&[WhereClause::eq("id", "u1")]);
        assert_eq!(filter, doc! { "_id": "u1" });
    }

    #[test]
    fn test_json_to_bson_string() {
        let bson = json_to_bson(&serde_json::json!("hello"));
        assert_eq!(bson, Bson::String("hello".into()));
    }

    #[test]
    fn test_json_to_bson_number() {
        let bson = json_to_bson(&serde_json::json!(42));
        assert_eq!(bson, Bson::Int64(42));
    }

    #[test]
    fn test_json_to_bson_null() {
        let bson = json_to_bson(&serde_json::Value::Null);
        assert_eq!(bson, Bson::Null);
    }

    #[test]
    fn test_build_insert_doc() {
        let data = serde_json::json!({"id": "u1", "name": "Alice"});
        let doc = build_insert_doc(&data);
        assert!(doc.contains_key("_id"));
        assert!(doc.contains_key("name"));
        assert!(!doc.contains_key("id"));
    }

    #[test]
    fn test_build_update_doc() {
        let data = serde_json::json!({"name": "Bob"});
        let doc = build_update_doc(&data);
        assert!(doc.contains_key("$set"));
    }

    #[test]
    fn test_doc_to_json_id_mapping() {
        let doc = doc! { "_id": "u1", "name": "Alice" };
        let json = doc_to_json(&doc);
        assert_eq!(json["id"], "u1");
        assert_eq!(json["name"], "Alice");
        assert!(json.get("_id").is_none());
    }

    #[test]
    fn test_regex_escape() {
        assert_eq!(regex_escape("hello.world"), "hello\\.world");
        assert_eq!(regex_escape("a+b"), "a\\+b");
    }

    #[test]
    fn test_build_sort() {
        use better_auth_core::db::adapter::SortBy;
        let query = FindManyQuery {
            sort_by: Some(SortBy {
                field: "name".into(),
                direction: SortDirection::Desc,
            }),
            ..Default::default()
        };
        let sort = build_sort(&query);
        assert!(sort.is_some());
        assert_eq!(sort.unwrap(), doc! { "name": -1 });
    }
}
