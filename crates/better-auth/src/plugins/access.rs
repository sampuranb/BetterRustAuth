// Access Control plugin — role-based access control (RBAC).
//
// Maps to: packages/better-auth/src/plugins/access/access.ts
//          packages/better-auth/src/plugins/access/types.ts

use std::collections::HashMap;

/// Statements: resource → list of allowed actions.
pub type Statements = HashMap<String, Vec<String>>;

/// Authorization result.
#[derive(Debug, Clone)]
pub enum AuthorizeResult {
    Success,
    Denied { error: String },
}

impl AuthorizeResult {
    /// Check if the result is a success.
    pub fn is_success(&self) -> bool {
        matches!(self, AuthorizeResult::Success)
    }
}

/// A role with its associated statements.
#[derive(Debug, Clone)]
pub struct Role {
    statements: Statements,
}

impl Role {
    pub fn new(statements: Statements) -> Self {
        Self { statements }
    }

    /// Get the role's statements.
    pub fn statements(&self) -> &Statements {
        &self.statements
    }

    /// Check if the given request is authorized under this role.
    /// `connector` specifies whether multiple resources use AND or OR logic.
    ///
    /// Supports wildcard actions ("*") which grant all action permissions on a resource.
    pub fn authorize(
        &self,
        request: &HashMap<String, Vec<String>>,
        connector: &str,
    ) -> AuthorizeResult {
        let mut any_success = false;
        let mut all_checked = false;

        for (resource, requested_actions) in request {
            let Some(allowed_actions) = self.statements.get(resource) else {
                // Check for wildcard resource
                if let Some(wildcard_actions) = self.statements.get("*") {
                    let success = requested_actions.iter().all(|action| {
                        wildcard_actions.contains(action)
                            || wildcard_actions.iter().any(|a| a == "*")
                    });
                    if success && connector == "OR" {
                        return AuthorizeResult::Success;
                    }
                    if !success && connector == "AND" {
                        return AuthorizeResult::Denied {
                            error: format!("unauthorized to access resource \"{}\"", resource),
                        };
                    }
                    any_success = any_success || success;
                    all_checked = true;
                    continue;
                }
                // No matching resource and no wildcard
                if connector == "AND" {
                    return AuthorizeResult::Denied {
                        error: format!("You are not allowed to access resource: {}", resource),
                    };
                }
                // In OR mode, continue to check other resources
                all_checked = true;
                continue;
            };

            let success = requested_actions.iter().all(|action| {
                allowed_actions.contains(action)
                    || allowed_actions.iter().any(|a| a == "*")
            });

            if success && connector == "OR" {
                return AuthorizeResult::Success;
            }
            if !success && connector == "AND" {
                return AuthorizeResult::Denied {
                    error: format!("unauthorized to access resource \"{}\"", resource),
                };
            }
            any_success = any_success || success;
            all_checked = true;
        }

        if any_success || all_checked {
            if connector == "AND" {
                AuthorizeResult::Success
            } else if any_success {
                AuthorizeResult::Success
            } else {
                AuthorizeResult::Denied {
                    error: "Not authorized".to_string(),
                }
            }
        } else {
            AuthorizeResult::Denied {
                error: "Not authorized".to_string(),
            }
        }
    }
}

/// Access control factory — creates roles from a base set of statements.
pub struct AccessControl {
    pub statements: Statements,
}

impl AccessControl {
    pub fn new(statements: Statements) -> Self {
        Self { statements }
    }

    /// Create a new role scoped to a subset of the base statements.
    pub fn new_role(&self, statements: Statements) -> Role {
        Role::new(statements)
    }
}

/// Default roles used by the admin plugin.
pub fn default_roles() -> HashMap<String, Role> {
    let mut roles = HashMap::new();

    let mut admin_statements = HashMap::new();
    admin_statements.insert(
        "user".to_string(),
        vec![
            "create".into(),
            "read".into(),
            "update".into(),
            "delete".into(),
        ],
    );
    admin_statements.insert(
        "session".to_string(),
        vec![
            "create".into(),
            "read".into(),
            "update".into(),
            "delete".into(),
        ],
    );

    let mut user_statements = HashMap::new();
    user_statements.insert("user".to_string(), vec!["read".into()]);

    roles.insert("admin".to_string(), Role::new(admin_statements));
    roles.insert("user".to_string(), Role::new(user_statements));

    roles
}

/// Org-level access control statements used by the organization plugin.
pub fn default_org_statements() -> Statements {
    let mut statements = HashMap::new();
    statements.insert(
        "organization".to_string(),
        vec![
            "create".into(),
            "read".into(),
            "update".into(),
            "delete".into(),
        ],
    );
    statements.insert(
        "member".to_string(),
        vec![
            "create".into(),
            "read".into(),
            "update".into(),
            "delete".into(),
        ],
    );
    statements.insert(
        "invitation".to_string(),
        vec![
            "create".into(),
            "read".into(),
            "update".into(),
            "delete".into(),
        ],
    );
    statements.insert(
        "team".to_string(),
        vec![
            "create".into(),
            "read".into(),
            "update".into(),
            "delete".into(),
        ],
    );
    statements
}

/// Default organization roles.
pub fn default_org_roles() -> HashMap<String, Role> {
    let mut roles = HashMap::new();

    // Owner gets full access
    roles.insert("owner".to_string(), Role::new(default_org_statements()));

    // Admin gets full access
    roles.insert("admin".to_string(), Role::new(default_org_statements()));

    // Member gets read on org, read on members, read on invitations
    let mut member_stmts = HashMap::new();
    member_stmts.insert("organization".to_string(), vec!["read".into()]);
    member_stmts.insert("member".to_string(), vec!["read".into()]);
    member_stmts.insert("invitation".to_string(), vec!["read".into()]);
    roles.insert("member".to_string(), Role::new(member_stmts));

    roles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_role_authorize() {
        let roles = default_roles();
        let admin = &roles["admin"];

        let mut req = HashMap::new();
        req.insert("user".to_string(), vec!["create".to_string()]);

        assert!(matches!(
            admin.authorize(&req, "AND"),
            AuthorizeResult::Success
        ));
    }

    #[test]
    fn test_user_role_denied() {
        let roles = default_roles();
        let user = &roles["user"];

        let mut req = HashMap::new();
        req.insert("user".to_string(), vec!["delete".to_string()]);

        assert!(matches!(
            user.authorize(&req, "AND"),
            AuthorizeResult::Denied { .. }
        ));
    }

    #[test]
    fn test_user_role_read_allowed() {
        let roles = default_roles();
        let user = &roles["user"];

        let mut req = HashMap::new();
        req.insert("user".to_string(), vec!["read".to_string()]);

        assert!(matches!(
            user.authorize(&req, "AND"),
            AuthorizeResult::Success
        ));
    }

    #[test]
    fn test_or_connector() {
        let roles = default_roles();
        let admin = &roles["admin"];

        let mut req = HashMap::new();
        req.insert("user".to_string(), vec!["create".to_string()]);
        req.insert("nonexistent".to_string(), vec!["action".to_string()]);

        // OR = at least one resource match is enough
        assert!(matches!(
            admin.authorize(&req, "OR"),
            AuthorizeResult::Success
        ));
    }

    #[test]
    fn test_and_connector_fail() {
        let roles = default_roles();
        let admin = &roles["admin"];

        let mut req = HashMap::new();
        req.insert("user".to_string(), vec!["create".to_string()]);
        req.insert("nonexistent".to_string(), vec!["action".to_string()]);

        // AND = all resources must match
        assert!(matches!(
            admin.authorize(&req, "AND"),
            AuthorizeResult::Denied { .. }
        ));
    }

    #[test]
    fn test_wildcard_actions() {
        let mut stmts = HashMap::new();
        stmts.insert("user".to_string(), vec!["*".to_string()]);
        let role = Role::new(stmts);

        let mut req = HashMap::new();
        req.insert(
            "user".to_string(),
            vec!["create".to_string(), "delete".to_string()],
        );

        assert!(matches!(
            role.authorize(&req, "AND"),
            AuthorizeResult::Success
        ));
    }

    #[test]
    fn test_authorize_result_is_success() {
        assert!(AuthorizeResult::Success.is_success());
        assert!(
            !AuthorizeResult::Denied {
                error: "test".to_string()
            }
            .is_success()
        );
    }

    #[test]
    fn test_default_org_roles() {
        let roles = default_org_roles();
        assert!(roles.contains_key("owner"));
        assert!(roles.contains_key("admin"));
        assert!(roles.contains_key("member"));

        // Owner can create organizations
        let mut req = HashMap::new();
        req.insert("organization".to_string(), vec!["create".to_string()]);
        assert!(roles["owner"].authorize(&req, "AND").is_success());

        // Member cannot delete organizations
        let mut req2 = HashMap::new();
        req2.insert("organization".to_string(), vec!["delete".to_string()]);
        assert!(!roles["member"].authorize(&req2, "AND").is_success());
    }

    #[test]
    fn test_access_control_new_role() {
        let ac = AccessControl::new(default_org_statements());
        let mut custom_stmts = HashMap::new();
        custom_stmts.insert(
            "organization".to_string(),
            vec!["read".to_string(), "update".to_string()],
        );
        let role = ac.new_role(custom_stmts);

        let mut req = HashMap::new();
        req.insert("organization".to_string(), vec!["read".to_string()]);
        assert!(role.authorize(&req, "AND").is_success());

        let mut req2 = HashMap::new();
        req2.insert("organization".to_string(), vec!["delete".to_string()]);
        assert!(!role.authorize(&req2, "AND").is_success());
    }
}
