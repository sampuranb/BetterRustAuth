// Error page route — maps to the TS error page rendering.
//
// Returns an HTML error page for OAuth/auth error redirects.

use serde::Deserialize;

/// Error page query parameters.
#[derive(Debug, Deserialize)]
pub struct ErrorPageQuery {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

/// Render an HTML error page.
///
/// Returns a simple, styled HTML page showing the error details.
pub fn render_error_page(query: &ErrorPageQuery) -> String {
    let error = query.error.as_deref().unwrap_or("unknown_error");
    let description = query.error_description.as_deref().unwrap_or(
        "An authentication error occurred. Please try again.",
    );

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Error</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background: #f8f9fa;
            color: #333;
        }}
        .container {{
            text-align: center;
            max-width: 480px;
            padding: 2rem;
        }}
        .icon {{
            font-size: 3rem;
            margin-bottom: 1rem;
        }}
        h1 {{
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
            color: #dc3545;
        }}
        .error-code {{
            font-family: monospace;
            background: #f1f3f5;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.875rem;
            color: #666;
            margin-bottom: 1rem;
            display: inline-block;
        }}
        p {{
            color: #666;
            line-height: 1.6;
        }}
        a {{
            color: #007bff;
            text-decoration: none;
            margin-top: 1.5rem;
            display: inline-block;
        }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⚠️</div>
        <h1>Authentication Error</h1>
        <div class="error-code">{error}</div>
        <p>{description}</p>
        <a href="/">← Return Home</a>
    </div>
</body>
</html>"#,
        error = error,
        description = description,
    )
}
