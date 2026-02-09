//! SCIM error codes.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimError {
    Unauthorized,
    ResourceNotFound,
    InvalidFilter,
    InvalidValue,
    Mutability,
    Uniqueness,
    TooMany,
    InvalidPath,
    InvalidSyntax,
    NoTarget,
}

impl ScimError {
    pub fn scim_type(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::ResourceNotFound => "resourceNotFound",
            Self::InvalidFilter => "invalidFilter",
            Self::InvalidValue => "invalidValue",
            Self::Mutability => "mutability",
            Self::Uniqueness => "uniqueness",
            Self::TooMany => "tooMany",
            Self::InvalidPath => "invalidPath",
            Self::InvalidSyntax => "invalidSyntax",
            Self::NoTarget => "noTarget",
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::ResourceNotFound => 404,
            Self::InvalidFilter | Self::InvalidValue | Self::InvalidSyntax |
            Self::InvalidPath | Self::NoTarget => 400,
            Self::Mutability => 400,
            Self::Uniqueness => 409,
            Self::TooMany => 400,
        }
    }

    pub fn detail(&self) -> &'static str {
        match self {
            Self::Unauthorized => "Authentication required",
            Self::ResourceNotFound => "Resource not found",
            Self::InvalidFilter => "Invalid SCIM filter",
            Self::InvalidValue => "Invalid value",
            Self::Mutability => "Attribute is read-only",
            Self::Uniqueness => "Attribute must be unique",
            Self::TooMany => "Too many results",
            Self::InvalidPath => "Invalid attribute path",
            Self::InvalidSyntax => "Invalid SCIM syntax",
            Self::NoTarget => "No target for patch operation",
        }
    }
}

impl std::fmt::Display for ScimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.scim_type(), self.detail())
    }
}

impl std::error::Error for ScimError {}
