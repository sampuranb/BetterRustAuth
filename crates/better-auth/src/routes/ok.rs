// OK/health route — maps to packages/better-auth/src/api/routes/ok.ts

use serde::Serialize;

/// Health check response.
#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

/// Handle health check endpoint.
pub fn handle_ok() -> OkResponse {
    OkResponse { ok: true }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok_response() {
        let response = handle_ok();
        assert!(response.ok);

        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"ok":true}"#);
    }
}
