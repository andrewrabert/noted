macro_rules! str_surface {
    ($ty:ident) => {
        impl $ty {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl From<$ty> for String {
            fn from(v: $ty) -> String {
                v.0
            }
        }
        impl PartialEq<str> for $ty {
            fn eq(&self, o: &str) -> bool {
                self.0 == o
            }
        }
        impl PartialEq<&str> for $ty {
            fn eq(&self, o: &&str) -> bool {
                self.0 == *o
            }
        }
        impl PartialEq<String> for $ty {
            fn eq(&self, o: &String) -> bool {
                &self.0 == o
            }
        }
    };
}

macro_rules! str_newtype {
    ($ty:ident) => {
        $crate::newtype::str_surface!($ty);
        impl $ty {
            pub fn new(s: impl Into<String>) -> $ty {
                $ty(s.into())
            }
        }
        impl From<&str> for $ty {
            fn from(s: &str) -> $ty {
                $ty(s.to_string())
            }
        }
        impl From<String> for $ty {
            fn from(s: String) -> $ty {
                $ty(s)
            }
        }
        impl std::str::FromStr for $ty {
            type Err = $crate::error::NotedError;
            fn from_str(s: &str) -> $crate::error::Result<$ty> {
                Ok($ty(s.to_string()))
            }
        }
    };
}

macro_rules! str_newtype_validated {
    ($ty:ident, $validate:path) => {
        $crate::newtype::str_surface!($ty);
        impl $ty {
            pub fn new(s: impl Into<String>) -> $crate::error::Result<$ty> {
                let s = s.into();
                $validate(&s)?;
                Ok($ty(s))
            }
        }
        impl std::str::FromStr for $ty {
            type Err = $crate::error::NotedError;
            fn from_str(s: &str) -> $crate::error::Result<$ty> {
                $ty::new(s)
            }
        }
        impl std::convert::TryFrom<String> for $ty {
            type Error = $crate::error::NotedError;
            fn try_from(s: String) -> $crate::error::Result<$ty> {
                $ty::new(s)
            }
        }
    };
}

macro_rules! secret_newtype {
    ($ty:ident) => {
        impl $ty {
            pub fn new(s: impl Into<String>) -> $ty {
                $ty(s.into())
            }
            pub fn expose(&self) -> &str {
                &self.0
            }
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }
        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
        impl From<$ty> for String {
            fn from(v: $ty) -> String {
                v.0
            }
        }
        impl From<&str> for $ty {
            fn from(s: &str) -> $ty {
                $ty(s.to_string())
            }
        }
        impl From<String> for $ty {
            fn from(s: String) -> $ty {
                $ty(s)
            }
        }
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}(…)", stringify!($ty))
            }
        }
    };
}

pub(crate) use secret_newtype;
pub(crate) use str_newtype;
pub(crate) use str_newtype_validated;
pub(crate) use str_surface;
