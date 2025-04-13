//
// lesspass-client model.rs
// Copyright (C) 2021-2025 Óscar García Amor <ogarcia@connectical.com>
// Distributed under terms of the GNU GPLv3 license.
//

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use serde::{Deserialize, Deserializer, Serialize};

/// To store the authentication response
#[derive(Debug, Deserialize)]
pub struct Token {
    pub access: String,
    pub refresh: String
}

/// To perform authentication and create new users
#[derive(Debug, Serialize)]
pub struct Auth {
    pub email: String,
    pub password: String
}

/// To perform the token refresh
#[derive(Debug, Serialize)]
pub struct Refresh {
    pub refresh: String
}

/// To store the user info
#[derive(Debug, Deserialize)]
pub struct User {
    #[serde(deserialize_with = "id_deserializer")]
    pub id: String,
    pub email: String
}

/// To delete user
#[derive(Debug, Serialize)]
pub struct UserPassword {
    pub current_password: String
}

/// To change the password for a user
#[derive(Debug, Serialize)]
pub struct UserChangePassword {
    pub current_password: String,
    pub new_password: String
}

/// To create a new password entry
#[derive(Debug, Deserialize, Serialize)]
pub struct NewPassword {
    pub site: String,
    pub login: String,
    pub lowercase: bool,
    pub uppercase: bool,
    pub symbols: bool,
    pub digits: bool,
    pub length: u8,
    pub counter: u32,
    pub version: u8
}

/// To store the password list
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Passwords {
    pub count: u32,
    // API implementation does not use (for now) previous and next
    // so are commented to avoid use memory with garbage
    //
    // pub previous: Option<u8>,
    // pub next: Option<u8>,
    pub results: Vec<Password>
}

/// A password item in the password list
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Password {
    pub id: String,
    pub site: String,
    pub login: String,
    pub lowercase: bool,
    pub uppercase: bool,
    pub symbols: bool,
    pub digits: bool,
    pub length: u8,
    pub counter: u32,
    pub version: u8,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>
}

/// The numbers field is deprecated and has been replaced by digits so depending on the
/// implementation the response may contain the first, the second or even both. We deserialize to
/// an intermediate structure with both fields and return the final structure with only the digits
/// field (which takes precedence over numbers).
impl<'de> Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de>, {
        #[derive(Deserialize)]
        struct RawPassword {
            #[serde(deserialize_with = "id_deserializer")]
            id: String,
            site: String,
            login: String,
            lowercase: bool,
            uppercase: bool,
            symbols: bool,
            digits: Option<bool>,
            numbers: Option<bool>,
            length: u8,
            counter: u32,
            version: u8,
            #[serde(deserialize_with = "date_deserializer")]
            created: DateTime<Utc>,
            #[serde(deserialize_with = "date_deserializer")]
            modified: DateTime<Utc>
        }
        let RawPassword {id, site, login, lowercase, uppercase, symbols, digits, numbers, length, counter, version, created, modified} = RawPassword::deserialize(deserializer)?;
        let digits = digits.or(numbers).ok_or(serde::de::Error::missing_field("digits or numbers"))?;
        Ok(Password {id, site, login, lowercase, uppercase, symbols, digits, length, counter, version, created, modified})
    }
}

/// Some server implementations (like Rockpass) store IDs in simple integers instead of strings,
/// this function deserializes unsigned integers or strings.
fn id_deserializer<'de, D>(deserializer: D) -> Result<String, D::Error> where D: Deserializer<'de>, {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrInteger {
        String(String),
        Integer(u64)
    }
    match StringOrInteger::deserialize(deserializer)? {
        StringOrInteger::String(string) => Ok(string),
        StringOrInteger::Integer(integer) => Ok(integer.to_string())
    }
}

/// Some server implementations (like Rockpass) store dates in NaiveDateTime,
/// this function deserializes NaiveDateTime and DateTime with TimeZone.
fn date_deserializer<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error> where D: Deserializer<'de>, {
    let s = String::deserialize(deserializer)?;
    match s.parse::<NaiveDateTime>() {
        Ok(date) => Ok(Utc.from_utc_datetime(&date)),
        Err(_) => s.parse::<DateTime<Utc>>().map_err(serde::de::Error::custom)
    }
}

/// Turns a NewPassword into a Password using empty string for id and current date for created and
/// modified fields
impl From<NewPassword> for Password {
    fn from(new_password: NewPassword) -> Self {
        Password {
            id: String::new(),
            site: new_password.site,
            login: new_password.login,
            lowercase: new_password.lowercase,
            uppercase: new_password.uppercase,
            symbols: new_password.symbols,
            digits: new_password.digits,
            length: new_password.length,
            counter: new_password.counter,
            version: new_password.version,
            created: Utc::now(),
            modified: Utc::now()
        }
    }
}
