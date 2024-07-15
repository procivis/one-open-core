/// Implements [`std::fmt::Display`] for a newtype, assuming that the inner type implements Display.
macro_rules! impl_display {
    ($newtype: ty) => {
        impl std::fmt::Display for $newtype {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}
pub(crate) use impl_display;

/// Implements [`std::convert::From`]
macro_rules! impl_from {
    ($newtype: ty; $inner: ty) => {
        impl std::convert::From<$inner> for $newtype {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }
    };
}
pub(crate) use impl_from;

/// Implements [`std::convert::Into`]
macro_rules! impl_into {
    ($newtype: ty; $inner: ty) => {
        impl std::convert::From<$newtype> for $inner {
            fn from(value: $newtype) -> Self {
                value.0
            }
        }
    };
}
pub(crate) use impl_into;
