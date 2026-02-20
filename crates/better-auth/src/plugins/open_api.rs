// OpenAPI plugin — Generates OpenAPI spec and Scalar reference page.
//
// Maps to: packages/better-auth/src/plugins/open-api/index.ts (140 lines)
// + generator.ts (603 lines) + logo.ts (58 lines)
//
// Full implementation with spec generation and HTML reference rendering.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use better_auth_core::db::schema::AuthTable;
use better_auth_core::plugin::{BetterAuthPlugin, HttpMethod, PluginEndpoint};

// ---------------------------------------------------------------------------
// Scalar themes
// ---------------------------------------------------------------------------

/// Scalar API Reference themes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScalarTheme {
    Alternate,
    Default,
    Moon,
    Purple,
    Solarized,
    BluePlanet,
    Saturn,
    Kepler,
    Mars,
    DeepSpace,
    Laserwave,
    None,
}

impl std::fmt::Display for ScalarTheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ScalarTheme::Alternate => "alternate",
            ScalarTheme::Default => "default",
            ScalarTheme::Moon => "moon",
            ScalarTheme::Purple => "purple",
            ScalarTheme::Solarized => "solarized",
            ScalarTheme::BluePlanet => "bluePlanet",
            ScalarTheme::Saturn => "saturn",
            ScalarTheme::Kepler => "kepler",
            ScalarTheme::Mars => "mars",
            ScalarTheme::DeepSpace => "deepSpace",
            ScalarTheme::Laserwave => "laserwave",
            ScalarTheme::None => "none",
        };
        write!(f, "{}", s)
    }
}

impl Default for ScalarTheme {
    fn default() -> Self {
        Self::Default
    }
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// OpenAPI plugin options.
#[derive(Debug, Clone)]
pub struct OpenApiOptions {
    /// Path to the OpenAPI reference page (default: "/reference").
    pub path: String,
    /// Disable the default Scalar reference page (default: false).
    pub disable_default_reference: bool,
    /// Scalar theme (default: "default").
    pub theme: ScalarTheme,
    /// CSP nonce for inline scripts.
    pub nonce: Option<String>,
}

impl Default for OpenApiOptions {
    fn default() -> Self {
        Self {
            path: "/reference".to_string(),
            disable_default_reference: false,
            theme: ScalarTheme::Default,
            nonce: None,
        }
    }
}

// ---------------------------------------------------------------------------
// OpenAPI schema types
// ---------------------------------------------------------------------------

/// OpenAPI schema type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpenApiSchemaType {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Object,
}

/// A single field's schema in OpenAPI representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSchema {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "readOnly", skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

/// A model schema (table) in OpenAPI representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiModelSchema {
    pub r#type: String,
    pub properties: HashMap<String, FieldSchema>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
}

/// OpenAPI path operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "operationId", skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<Vec<HashMap<String, Vec<String>>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<serde_json::Value>>,
    #[serde(rename = "requestBody", skip_serializing_if = "Option::is_none")]
    pub request_body: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responses: Option<HashMap<String, serde_json::Value>>,
}

/// OpenAPI path item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get: Option<PathOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post: Option<PathOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub put: Option<PathOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<PathOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<PathOperation>,
}

/// Complete OpenAPI specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: OpenApiInfo,
    pub components: serde_json::Value,
    pub security: Vec<serde_json::Value>,
    pub servers: Vec<OpenApiServer>,
    pub tags: Vec<OpenApiTag>,
    pub paths: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiInfo {
    pub title: String,
    pub description: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiServer {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiTag {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/// Convert a route path from `:param` format to `{param}` format.
pub fn to_openapi_path(path: &str) -> String {
    path.split('/')
        .map(|part| {
            if let Some(param) = part.strip_prefix(':') {
                format!("{{{}}}", param)
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Generate default error responses for OpenAPI spec.
pub fn default_error_responses() -> HashMap<String, serde_json::Value> {
    let error_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "message": { "type": "string" }
        },
        "required": ["message"]
    });

    let mut responses = HashMap::new();
    responses.insert("400".to_string(), serde_json::json!({
        "content": { "application/json": { "schema": error_schema } },
        "description": "Bad Request. Usually due to missing parameters, or invalid parameters."
    }));
    responses.insert("401".to_string(), serde_json::json!({
        "content": { "application/json": { "schema": error_schema } },
        "description": "Unauthorized. Due to missing or invalid authentication."
    }));
    responses.insert("403".to_string(), serde_json::json!({
        "content": { "application/json": { "schema": error_schema } },
        "description": "Forbidden. You do not have permission to access this resource or to perform this action."
    }));
    responses.insert("404".to_string(), serde_json::json!({
        "content": { "application/json": { "schema": error_schema } },
        "description": "Not Found. The requested resource was not found."
    }));
    responses.insert("429".to_string(), serde_json::json!({
        "content": { "application/json": { "schema": error_schema } },
        "description": "Too Many Requests. You have exceeded the rate limit. Try again later."
    }));
    responses.insert("500".to_string(), serde_json::json!({
        "content": { "application/json": { "schema": error_schema } },
        "description": "Internal Server Error. This is a problem with the server that you cannot fix."
    }));
    responses
}

/// Build a model schema from an AuthTable.
pub fn build_model_schema(table: &AuthTable) -> OpenApiModelSchema {
    use better_auth_core::db::schema::FieldType;

    let mut properties = HashMap::new();
    let mut required = Vec::new();

    // Add id field
    properties.insert(
        "id".to_string(),
        FieldSchema {
            r#type: "string".to_string(),
            format: None,
            default: None,
            description: None,
            read_only: None,
        },
    );

    for (field_name, field) in &table.fields {
        let (field_type_str, format) = match field.field_type {
            FieldType::Date => ("string".to_string(), Some("date-time".to_string())),
            FieldType::String => ("string".to_string(), None),
            FieldType::Number => ("number".to_string(), None),
            FieldType::Boolean => ("boolean".to_string(), None),
        };

        properties.insert(
            field_name.clone(),
            FieldSchema {
                r#type: field_type_str,
                format,
                default: field.default_value.clone(),
                description: None,
                read_only: if !field.input { Some(true) } else { None },
            },
        );

        if field.required && field.input {
            required.push(field_name.clone());
        }
    }

    OpenApiModelSchema {
        r#type: "object".to_string(),
        properties,
        required: if required.is_empty() { None } else { Some(required) },
    }
}

/// Generate a complete OpenAPI spec from endpoints and tables.
pub fn generate_openapi_spec(
    base_url: &str,
    endpoints: &[PluginEndpoint],
    tables: &[AuthTable],
) -> OpenApiSpec {
    // Build components/schemas from tables
    let mut schemas = HashMap::new();
    for table in tables {
        let model_name = {
            let mut chars = table.name.chars();
            match chars.next() {
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        };
        schemas.insert(model_name, serde_json::to_value(build_model_schema(table)).unwrap_or_default());
    }

    let components = serde_json::json!({
        "schemas": schemas,
        "securitySchemes": {
            "apiKeyCookie": {
                "type": "apiKey",
                "in": "cookie",
                "name": "apiKeyCookie",
                "description": "API Key authentication via cookie"
            },
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "description": "Bearer token authentication"
            }
        }
    });

    // Build paths from endpoints
    let mut paths: HashMap<String, serde_json::Value> = HashMap::new();
    for endpoint in endpoints {
        let path = to_openapi_path(&endpoint.path);

        let mut security = HashMap::new();
        security.insert("bearerAuth".to_string(), Vec::<String>::new());

        let operation = serde_json::json!({
            "tags": ["Default"],
            "security": [security],
            "responses": default_error_responses()
        });

        let method = match endpoint.method {
            HttpMethod::Get => "get",
            HttpMethod::Post => "post",
            HttpMethod::Put => "put",
            HttpMethod::Patch => "patch",
            HttpMethod::Delete => "delete",
        };

        if let Some(existing) = paths.get_mut(&path) {
            existing.as_object_mut().unwrap().insert(
                method.to_string(),
                operation,
            );
        } else {
            let mut path_item = serde_json::Map::new();
            path_item.insert(method.to_string(), operation);
            paths.insert(path, serde_json::Value::Object(path_item));
        }
    }

    OpenApiSpec {
        openapi: "3.1.1".to_string(),
        info: OpenApiInfo {
            title: "Better Auth".to_string(),
            description: "API Reference for your Better Auth Instance".to_string(),
            version: "1.1.0".to_string(),
        },
        components,
        security: vec![serde_json::json!({
            "apiKeyCookie": [],
            "bearerAuth": []
        })],
        servers: vec![OpenApiServer {
            url: base_url.to_string(),
        }],
        tags: vec![OpenApiTag {
            name: "Default".to_string(),
            description: Some(
                "Default endpoints that are included with Better Auth by default. These endpoints are not part of any plugin.".to_string()
            ),
        }],
        paths,
    }
}

// ---------------------------------------------------------------------------
// Scalar HTML reference page
// ---------------------------------------------------------------------------

/// Better Auth SVG logo for the Scalar reference page.
pub const BETTER_AUTH_LOGO: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>"#;

/// Generate the HTML for the Scalar API reference page.
pub fn generate_scalar_html(
    api_reference: &serde_json::Value,
    theme: &ScalarTheme,
    nonce: Option<&str>,
) -> String {
    let nonce_attr = nonce.map(|n| format!(r#" nonce="{}""#, n)).unwrap_or_default();
    let logo_encoded = urlencoding::encode(BETTER_AUTH_LOGO);
    let api_json = serde_json::to_string(api_reference).unwrap_or_default();

    format!(
        r#"<!doctype html>
<html>
  <head>
    <title>Scalar API Reference</title>
    <meta charset="utf-8" />
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script
      id="api-reference"
      type="application/json">
    {api_json}
    </script>
    <script{nonce_attr}>
      var configuration = {{
        favicon: "data:image/svg+xml;utf8,{logo_encoded}",
        theme: "{theme}",
        metaData: {{
          title: "Better Auth API",
          description: "API Reference for your Better Auth Instance",
        }}
      }}

      document.getElementById('api-reference').dataset.configuration =
        JSON.stringify(configuration)
    </script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"{nonce_attr}></script>
  </body>
</html>"#,
        api_json = api_json,
        nonce_attr = nonce_attr,
        logo_encoded = logo_encoded,
        theme = theme,
    )
}

// ---------------------------------------------------------------------------
// Plugin definition
// ---------------------------------------------------------------------------

/// OpenAPI plugin.
#[derive(Debug)]
pub struct OpenApiPlugin {
    options: OpenApiOptions,
}

impl OpenApiPlugin {
    pub fn new(options: OpenApiOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &OpenApiOptions {
        &self.options
    }
}

impl Default for OpenApiPlugin {
    fn default() -> Self {
        Self::new(OpenApiOptions::default())
    }
}

#[async_trait]
impl BetterAuthPlugin for OpenApiPlugin {
    fn id(&self) -> &str {
        "open-api"
    }

    fn name(&self) -> &str {
        "OpenAPI"
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        use std::sync::Arc;
        use better_auth_core::plugin::{PluginHandlerFn, PluginHandlerRequest, PluginHandlerResponse};

        let opts = self.options.clone();

        // GET /open-api/generate-schema
        let schema_handler: PluginHandlerFn = Arc::new(move |ctx_any, _req: PluginHandlerRequest| {
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                // Collect endpoints from all plugins
                let mut all_endpoints = Vec::new();
                for plugin in ctx.plugin_registry.plugins() {
                    all_endpoints.extend(plugin.endpoints());
                }
                let tables = ctx.plugin_registry.plugins().iter()
                    .flat_map(|p| p.schema())
                    .collect::<Vec<_>>();
                let spec = generate_openapi_spec(ctx.base_url.as_deref().unwrap_or(""), &all_endpoints, &tables);
                PluginHandlerResponse::ok(serde_json::to_value(spec).unwrap_or_default())
            })
        });

        // GET /reference (or custom path)
        let ref_opts = opts.clone();
        let reference_handler: PluginHandlerFn = Arc::new(move |ctx_any, _req: PluginHandlerRequest| {
            let opts = ref_opts.clone();
            Box::pin(async move {
                let ctx = ctx_any.downcast::<crate::context::AuthContext>()
                    .expect("Expected AuthContext");
                let mut all_endpoints = Vec::new();
                for plugin in ctx.plugin_registry.plugins() {
                    all_endpoints.extend(plugin.endpoints());
                }
                let tables = ctx.plugin_registry.plugins().iter()
                    .flat_map(|p| p.schema())
                    .collect::<Vec<_>>();
                let spec = generate_openapi_spec(ctx.base_url.as_deref().unwrap_or(""), &all_endpoints, &tables);
                let spec_json = serde_json::to_value(&spec).unwrap_or_default();
                let html = generate_scalar_html(&spec_json, &opts.theme, opts.nonce.as_deref());
                PluginHandlerResponse {
                    status: 200,
                    body: serde_json::json!({"html": html}),
                    headers: HashMap::from([("Content-Type".to_string(), "text/html".to_string())]),
                    redirect: None,
                }
            })
        });

        vec![
            PluginEndpoint::with_handler("/open-api/generate-schema", HttpMethod::Get, false, schema_handler),
            PluginEndpoint::with_handler(&opts.path, HttpMethod::Get, false, reference_handler),
        ]
    }

    fn schema(&self) -> Vec<AuthTable> {
        vec![] // OpenAPI plugin doesn't define any tables
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_id() {
        let plugin = OpenApiPlugin::default();
        assert_eq!(plugin.id(), "open-api");
    }

    #[test]
    fn test_plugin_name() {
        let plugin = OpenApiPlugin::default();
        assert_eq!(plugin.name(), "OpenAPI");
    }

    #[test]
    fn test_endpoints() {
        let plugin = OpenApiPlugin::default();
        let eps = plugin.endpoints();
        assert_eq!(eps.len(), 2);
        assert_eq!(eps[0].path, "/open-api/generate-schema");
        assert_eq!(eps[1].path, "/reference");
    }

    #[test]
    fn test_custom_path() {
        let plugin = OpenApiPlugin::new(OpenApiOptions {
            path: "/docs".into(),
            ..Default::default()
        });
        let eps = plugin.endpoints();
        assert_eq!(eps[1].path, "/docs");
    }

    #[test]
    fn test_scalar_themes() {
        assert_eq!(ScalarTheme::Default.to_string(), "default");
        assert_eq!(ScalarTheme::Moon.to_string(), "moon");
        assert_eq!(ScalarTheme::DeepSpace.to_string(), "deepSpace");
    }

    #[test]
    fn test_to_openapi_path() {
        assert_eq!(to_openapi_path("/users/:id"), "/users/{id}");
        assert_eq!(
            to_openapi_path("/reset-password/:token"),
            "/reset-password/{token}"
        );
        assert_eq!(to_openapi_path("/users"), "/users");
    }

    #[test]
    fn test_generate_scalar_html() {
        let spec = serde_json::json!({"openapi": "3.1.1"});
        let html = generate_scalar_html(&spec, &ScalarTheme::Default, None);
        assert!(html.contains("Scalar API Reference"));
        assert!(html.contains("3.1.1"));
        assert!(html.contains("@scalar/api-reference"));
    }

    #[test]
    fn test_generate_scalar_html_with_nonce() {
        let spec = serde_json::json!({"openapi": "3.1.1"});
        let html = generate_scalar_html(&spec, &ScalarTheme::Moon, Some("abc123"));
        assert!(html.contains(r#"nonce="abc123""#));
    }

    #[test]
    fn test_default_error_responses() {
        let responses = default_error_responses();
        assert!(responses.contains_key("400"));
        assert!(responses.contains_key("401"));
        assert!(responses.contains_key("403"));
        assert!(responses.contains_key("404"));
        assert!(responses.contains_key("429"));
        assert!(responses.contains_key("500"));
    }

    #[test]
    fn test_generate_openapi_spec() {
        let endpoints = vec![
            PluginEndpoint {
                path: "/users".into(),
                method: HttpMethod::Get,
                require_auth: true,
                metadata: HashMap::new(),
                    handler: None,
            },
            PluginEndpoint {
                path: "/users/:id".into(),
                method: HttpMethod::Get,
                require_auth: true,
                metadata: HashMap::new(),
                    handler: None,
            },
        ];

        let spec = generate_openapi_spec("https://example.com/api/auth", &endpoints, &[]);
        assert_eq!(spec.openapi, "3.1.1");
        assert_eq!(spec.info.title, "Better Auth");
        assert!(spec.paths.contains_key("/users"));
        assert!(spec.paths.contains_key("/users/{id}"));
    }

    #[test]
    fn test_build_model_schema() {
        let table = AuthTable::new("user")
            .field("name", better_auth_core::db::schema::SchemaField::required_string())
            .field("email", better_auth_core::db::schema::SchemaField::required_string());
        let schema = build_model_schema(&table);
        assert_eq!(schema.r#type, "object");
        assert!(schema.properties.contains_key("id"));
        assert!(schema.properties.contains_key("name"));
        assert!(schema.properties.contains_key("email"));
    }
}
