#[macro_export]
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

#[macro_export]
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

#[macro_export]
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

#[macro_export]
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

#[macro_export]
macro_rules! str_enum {
    (
        $(#[$meta:meta])*
        pub enum $ty:ident {
            $( $(#[$vmeta:meta])* $V:ident => $s:literal ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $ty {
            $( $(#[$vmeta])* $V ),*
        }
        impl $ty {
            pub const ALL: &'static [Self] = &[$( Self::$V ),*];
            pub fn as_str(self) -> &'static str {
                match self {
                    $( Self::$V => $s ),*
                }
            }
        }
        impl std::str::FromStr for $ty {
            type Err = $crate::error::NotedError;
            fn from_str(s: &str) -> $crate::error::Result<$ty> {
                match s {
                    $( $s => Ok(Self::$V), )*
                    _ => Err($crate::error::rejected(format!(
                        "'{s}' is not one of: {}",
                        [$( $s ),*].join(", ")
                    ))),
                }
            }
        }
        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
        impl ::serde::Serialize for $ty {
            fn serialize<S: ::serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }
        impl<'de> ::serde::Deserialize<'de> for $ty {
            fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> std::result::Result<$ty, D::Error> {
                let s = <String as ::serde::Deserialize>::deserialize(d)?;
                s.parse().map_err(::serde::de::Error::custom)
            }
        }
        impl ::clap::ValueEnum for $ty {
            fn value_variants<'a>() -> &'a [$ty] {
                Self::ALL
            }
            fn to_possible_value(&self) -> Option<::clap::builder::PossibleValue> {
                Some(::clap::builder::PossibleValue::new(self.as_str()))
            }
        }
        impl ::schemars::JsonSchema for $ty {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($ty).into()
            }
            fn json_schema(_: &mut ::schemars::SchemaGenerator) -> ::schemars::Schema {
                ::schemars::json_schema!({
                    "type": "string",
                    "enum": [$( $s ),*],
                })
            }
        }
    };
}

pub use secret_newtype;
pub use str_enum;
pub use str_newtype;
pub use str_newtype_validated;
pub use str_surface;
