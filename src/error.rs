use thiserror::Error;

#[derive(Debug, Error)]
pub enum NotedError {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("{context}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{context}")]
    Json {
        context: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("{context}")]
    Yaml {
        context: String,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("{context}")]
    Db {
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("{context}")]
    Http {
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl NotedError {
    pub fn message(&self) -> &str {
        match self {
            NotedError::NotFound(m)
            | NotedError::Forbidden(m)
            | NotedError::InvalidInput(m)
            | NotedError::Unavailable(m) => m,
            NotedError::Io { context, .. }
            | NotedError::Json { context, .. }
            | NotedError::Yaml { context, .. }
            | NotedError::Db { context, .. }
            | NotedError::Http { context, .. } => context,
        }
    }

    pub fn is_rejection(&self) -> bool {
        matches!(
            self,
            NotedError::NotFound(_) | NotedError::Forbidden(_) | NotedError::InvalidInput(_)
        )
    }
}

impl From<NotedError> for String {
    fn from(e: NotedError) -> String {
        e.message().to_string()
    }
}

pub type Result<T> = std::result::Result<T, NotedError>;

pub fn rejected(msg: impl Into<String>) -> NotedError {
    NotedError::InvalidInput(msg.into())
}

pub fn not_found(msg: impl Into<String>) -> NotedError {
    NotedError::NotFound(msg.into())
}

pub fn forbidden(msg: impl Into<String>) -> NotedError {
    NotedError::Forbidden(msg.into())
}

pub fn unavailable(msg: impl Into<String>) -> NotedError {
    NotedError::Unavailable(msg.into())
}

pub fn io_error(context: impl Into<String>, source: std::io::Error) -> NotedError {
    NotedError::Io {
        context: context.into(),
        source,
    }
}

pub fn json_error(context: impl Into<String>, source: serde_json::Error) -> NotedError {
    NotedError::Json {
        context: context.into(),
        source,
    }
}

pub fn yaml_error(context: impl Into<String>, source: serde_yaml::Error) -> NotedError {
    NotedError::Yaml {
        context: context.into(),
        source,
    }
}

pub fn db_error(context: impl Into<String>, source: impl Into<redb::Error>) -> NotedError {
    NotedError::Db {
        context: context.into(),
        source: Box::new(source.into()),
    }
}

pub fn http_error(context: impl Into<String>, source: reqwest::Error) -> NotedError {
    NotedError::Http {
        context: context.into(),
        source: Box::new(source),
    }
}
