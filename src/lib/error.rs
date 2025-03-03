//
// lesspass-client error.rs
// Copyright (C) 2021-2025 Óscar García Amor <ogarcia@connectical.com>
// Distributed under terms of the GNU GPLv3 license.
//

use std::fmt;

/// A `Result` alias where the `Err` case is `lesspass_client::Error`.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub(crate) enum Kind {
    Reqwest,
    UrlParse
}

pub struct Error {
    kind: Kind,
    message: String,
    status: Option<reqwest::StatusCode>
}

impl Error {
     /// Returns true if the error is from Reqwest
     pub fn is_reqwest(&self) -> bool {
         matches!(self.kind, Kind::Reqwest)
     }

     /// Returns true if the error is from UrlParse
     pub fn is_url_parse(&self) -> bool {
         matches!(self.kind, Kind::UrlParse)
     }

     /// Returns message as is
     pub fn message(&self) -> String {
         self.message.clone()
     }

     /// Returns the status code as u16
     pub fn status(&self) -> Option<u16> {
         self.status.map(|e| e.as_u16())
     }

     /// Returns the status code as is
     pub fn status_code(&self) -> Option<reqwest::StatusCode> {
         self.status
     }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            Kind::Reqwest => f.write_str("reqwest error")?,
            Kind::UrlParse => f.write_str("URL parse error")?,
        };
        write!(f, ", {}", self.message)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Error {{ kind: {:?}, message: {}, status: {:?} }}",
            self.kind, self.message, self.status
        )
    }
}

// Implement std::convert::From for Error from reqwest::Error
impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Error {
            kind: Kind::Reqwest,
            message: error.to_string(),
            status: error.status()
        }
    }
}

// Implement std::convert::From for Error from url::ParseError
impl From<url::ParseError> for Error {
    fn from(error: url::ParseError) -> Self {
        Error {
            kind: Kind::UrlParse,
            message: error.to_string(),
            status: None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error() {
        // A reqwest error
        let error = Error {
            kind: Kind::Reqwest,
            message: "a reqwest error".to_string(),
            status: Some(reqwest::StatusCode::from_u16(500).unwrap())
        };
        assert_eq!("Error { kind: Reqwest, message: a reqwest error, status: Some(500) }", format!("{error:?}"));
        assert_eq!("reqwest error, a reqwest error", error.to_string());
        assert_eq!("a reqwest error", error.message());
        assert_eq!(Some(500), error.status());
        assert_eq!(Some(reqwest::StatusCode::INTERNAL_SERVER_ERROR), error.status_code());
        assert!(error.is_reqwest());
        // A URL parse error
        let error = Error {
            kind: Kind::UrlParse,
            message: "an URL parse error".to_string(),
            status: None
        };
        assert_eq!("Error { kind: UrlParse, message: an URL parse error, status: None }", format!("{error:?}"));
        assert_eq!("URL parse error, an URL parse error", error.to_string());
        assert_eq!("an URL parse error", error.message());
        assert_eq!(None, error.status());
        assert!(error.is_url_parse());
    }
}
