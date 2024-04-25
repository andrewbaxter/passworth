use std::any::Any;
use loga::ErrContext;

pub enum UiErr {
    Internal(loga::Error),
    InternalUnresolvable(loga::Error),
    External(String, Option<loga::Error>),
}

impl UiErr {
    pub fn external(x: &str) -> UiErr {
        return UiErr::External(x.to_string(), None);
    }
}

impl From<loga::Error> for UiErr {
    fn from(value: loga::Error) -> Self {
        return Self::InternalUnresolvable(value);
    }
}

pub trait ToUiErr<T> {
    fn to_ui_err_external(self, context: &str) -> Result<T, UiErr>;
    fn to_ui_err_internal_resolvable(self) -> Result<T, UiErr>;
}

impl<T, E: Into<loga::Error>> ToUiErr<T> for Result<T, E> {
    fn to_ui_err_external(self, context: &str) -> Result<T, UiErr> {
        match self {
            Ok(x) => return Ok(x),
            Err(e) => {
                return Err(UiErr::External(context.to_string(), Some(e.context(context))));
            },
        }
    }

    fn to_ui_err_internal_resolvable(self) -> Result<T, UiErr> {
        match self {
            Ok(x) => return Ok(x),
            Err(e) => {
                return Err(UiErr::Internal(e.into()));
            },
        }
    }
}

pub trait FromAnyErr<T> {
    fn any_context(self) -> Result<T, loga::Error>;
}

impl<T> FromAnyErr<T> for Result<T, Box<dyn Any + Send>> {
    fn any_context(self) -> Result<T, loga::Error> {
        return self.map_err(|e| match e.downcast::<&dyn std::error::Error>() {
            Ok(e) => loga::Error::from(e),
            Err(_) => loga::err("Opaque thread error"),
        });
    }
}
