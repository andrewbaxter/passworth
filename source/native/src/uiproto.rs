//! Protocol between `passworth-server` and the `passworth-ui` helper process. The
//! server writes `ToUi` messages and the helper writes `FromUi` messages, one JSON
//! object per line, over the helper's stdin/stdout. The helper has no access to the
//! database or any derived key; it only collects what the user types and reports
//! button presses. Each open window has an id chosen by the server.
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Title {
    Initialize(String),
    Prompt(String),
    Unlock(String),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Body {
    /// Enter a new password, with confirmation and a generator. Result: `Bytes`.
    NewPassword {
        message: String,
    },
    /// Enter an existing password. Result: `Bytes`.
    Password {
        message: String,
    },
    /// Pick one of several options. Result: `Index`.
    Choose {
        message: String,
        options: Vec<String>,
    },
    /// Display a recovery phrase for the user to write down. Result: `Ok`.
    ShowPhrase {
        message: String,
        words: Vec<String>,
    },
    /// Enter a recovery phrase. Result: `Bytes` (words joined by single spaces).
    EnterPhrase {
        message: String,
    },
    /// Enter a smartcard pin. Result: `Text`.
    Pin {
        message: String,
    },
    /// Informational only; stays open until closed by the server or cancelled by the
    /// user.
    Message {
        message: String,
    },
    /// Ask the user to approve an access request. Result: `Bool`.
    Prompt {
        rule: String,
        principal: String,
        paths: Vec<String>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ToUi {
    Open {
        id: u64,
        title: Title,
        /// An error from a previous attempt to show above the body.
        error: Option<String>,
        body: Body,
    },
    Close {
        id: u64,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum UiValue {
    Bytes(Vec<u8>),
    Text(String),
    Index(usize),
    Bool(bool),
    Ok,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum FromUi {
    Result {
        id: u64,
        value: UiValue,
    },
    /// The user closed the window without answering.
    Cancelled {
        id: u64,
    },
}
