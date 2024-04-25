pub mod proto;
pub mod config;
pub mod ioutil;
pub mod generate;
pub mod crypto;
pub mod error;

// Break barrier
#[macro_export]
macro_rules! bb{
    ($l: lifetime _; $($t: tt) *) => {
        $l: loop {
            #[allow(unreachable_code)] break {
                $($t) *
            };
        }
    };
    ($($t: tt) *) => {
        loop {
            #[allow(unreachable_code)] break {
                $($t) *
            };
        }
    };
}

/// Doing underscore assignment to ignore errors also ignores futures which is very
/// bad.
pub trait IgnoreErr<T> {
    fn ignore(self);
}

impl<T, E> IgnoreErr<T> for Result<T, E> {
    fn ignore(self) {
        _ = self;
    }
}
