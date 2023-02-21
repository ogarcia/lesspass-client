//
// lesspass-client
// Copyright (C) 2021-2023 Óscar García Amor <ogarcia@connectical.com>
// Distributed under terms of the GNU GPLv3 license.
//

//! lesspass-client is a tiny-crate for interacting with [LessPass][lesspass] server API from Rust.
//!
//! # Overview
//!
//! lesspass-client can interact with several implementations of LessPass server API,
//! it is specially designed to use with [Rockpass][rockpass] (a small and ultrasecure
//! Lesspass database server written in Rust) and [official][lesspassapi] ones.
//!
//! # Using the Client
//! ```rust,no_run
//! use reqwest::Url;
//! use lesspass_client::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Define a host URL to conect to
//!     let host = Url::parse("https://api.lesspass.com").unwrap();
//!
//!     // Create LessPass API client
//!     let client = Client::new(host);
//!
//!     // Perform an authentication with user and password
//!     let token = client
//!         .create_token("user@example.com".to_string(), "password".to_string())
//!         .await?;
//!
//!     // Get the password list
//!     let passwords = client.get_passwords(token.access).await?;
//!
//!     // Print the list
//!     println!("{:?}", passwords);
//!     Ok(())
//! }
//! ```
//!
//! For details, see:
//! * [Client][Client] for implementation of LessPass server API client.
//! * [CLI][cli] for a full example of use.
//!
//! [lesspass]: https://gitlab.com/lesspass/lesspass
//! [rockpass]: https://gitlab.com/ogarcia/rockpass
//! [lesspassapi]: https://github.com/lesspass/lesspass/tree/main/containers
//! [cli]: https://gitlab.com/ogarcia/lesspass-client/-/blob/master/src/main.rs

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use log::debug;
use serde::{Deserialize, Deserializer, Serialize};
use reqwest::{Response, Url};

const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
);

/// To perform authentication and create new users
#[derive(Serialize, Debug)]
pub struct Auth {
    pub email: String,
    pub password: String
}

/// To perform the token refresh
#[derive(Serialize, Debug)]
pub struct Refresh {
    pub refresh: String
}

/// To delete user
#[derive(Serialize, Debug)]
pub struct UserPassword {
    pub current_password: String
}

/// To change the password for a user
#[derive(Serialize, Debug)]
pub struct ChangeUserPassword {
    pub current_password: String,
    pub new_password: String
}

/// To create a new passwords list
#[derive(Deserialize, Debug)]
pub struct NewPasswords {
    pub results: Vec<NewPassword>
}

/// To create a new password entry
#[derive(Deserialize, Serialize, Debug)]
pub struct NewPassword {
    pub site: String,
    pub login: String,
    pub lowercase: bool,
    pub uppercase: bool,
    pub symbols: bool,
    pub numbers: bool,
    pub length: u8,
    pub counter: u32,
    pub version: u8
}

/// To store the authentication response
#[derive(Deserialize, Debug)]
pub struct Token {
    pub access: String,
    pub refresh: String
}

/// To store the user info
#[derive(Deserialize, Debug)]
pub struct User {
    #[serde(deserialize_with = "id_deserializer")]
    pub id: String,
    pub email: String
}

/// To store the password list
#[derive(Deserialize, Serialize, Debug)]
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
#[derive(Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd, Debug)]
pub struct Password {
    #[serde(deserialize_with = "id_deserializer")]
    pub id: String,
    pub site: String,
    pub login: String,
    pub lowercase: bool,
    pub uppercase: bool,
    pub symbols: bool,
    pub numbers: bool,
    pub length: u8,
    pub counter: u32,
    pub version: u8,
    #[serde(deserialize_with = "date_deserializer")]
    pub created: DateTime<Utc>,
    #[serde(deserialize_with = "date_deserializer")]
    pub modified: DateTime<Utc>
}

/// Client for connecting to LessPass server
#[derive(Debug)]
pub struct Client {
    pub host: Url,
    pub client: reqwest::Client
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

/// Builder interface to Client
///
/// Usage:
/// ```
/// use reqwest::Url;
/// use lesspass_client::Client;
///
/// let host = Url::parse("https://api.lesspass.com").unwrap();
/// let lpc = Client::new(host);
/// ```
impl Client {

    /// Configure the client itself
    pub fn new(host: Url) -> Client {
        Client {
            host,
            client: reqwest::Client::builder()
                .connection_verbose(true)
                .user_agent(USER_AGENT)
                .build()
                .expect("Client::new()")
        }
    }

    /// Internal helper function to join host with endpoint
    fn build_url(&self, path: &str) -> Url {
        // Calling .unwrap() is safe here because path is always valid
        self.host.join(&path).unwrap()
    }

    /// Internal function to perform authenticated get requests
    async fn get(&self, url: &Url, token: String) -> Result<Response, String> {
        let authorization = format!("Bearer {}", token);
        match self.client.get(url.as_str()).header("Authorization", authorization).send().await {
            Ok(response) => {
                // Ok response code to all GET to LessPass API is 200
                if response.status() == 200 {
                    Ok(response)
                } else {
                    Err(format!("Error in GET request, unexpected status code {}", response.status()))
                }
            },
            // Cannot reach server by any reason
            Err(_) => Err(format!("Error making GET request to {}", url))
        }
    }

    /// Internal function to perform (un)authenticated post requests
    async fn post<T: Serialize + ?Sized>(&self, url: &Url, token: Option<String>, json: &T) -> Result<Response, String> {
        let request = match token {
            Some(token) => {
                let authorization = format!("Bearer {}", token);
                self.client.post(url.as_str()).header("Authorization", authorization).json(&json).send().await
            },
            None => self.client.post(url.as_str()).json(&json).send().await
        };
        match request {
            Ok(response) => {
                // Ok response code to all POST to LessPass API is 200, 201 or 204
                if response.status() == 200 || response.status() == 201 || response.status() == 204 {
                    Ok(response)
                } else {
                    Err(format!("Error in POST request, unexpected status code {}", response.status()))
                }
            },
            // Cannot reach server by any reason
            Err(_) => Err(format!("Error making POST request to {}", url))
        }
    }

    /// Internal function to perform authenticated put requests
    async fn put<T: Serialize + ?Sized>(&self, url: &Url, token: String, json: &T) -> Result<Response, String> {
        let authorization = format!("Bearer {}", token);
        match self.client.put(url.as_str()).header("Authorization", authorization).json(&json).send().await {
            Ok(response) => {
                // Ok response code to all PUT to LessPass API is 200 or 201
                if response.status() == 200 || response.status() == 201 {
                    Ok(response)
                } else {
                    Err(format!("Error in PUT request, unexpected status code {}", response.status()))
                }
            },
            // Cannot reach server by any reason
            Err(_) => Err(format!("Error making PUT request to {}", url))
        }
    }

    /// Internal function to perform authenticated delete requests with empty body
    async fn empty_delete(&self, url: &Url, token: String) -> Result<Response, String> {
        let authorization = format!("Bearer {}", token);
        match self.client.delete(url.as_str()).header("Authorization", authorization).send().await {
            Ok(response) => {
                // Ok response code to all DELETE to LessPass API is 200 or 204
                if response.status() == 200 || response.status() == 204 {
                    Ok(response)
                } else {
                    Err(format!("Error in DELETE request, unexpected status code {}", response.status()))
                }
            },
            // Cannot reach server by any reason
            Err(_) => Err(format!("Error making DELETE request to {}", url))
        }
    }

    /// Internal function to perform authenticated delete requests
    async fn delete<T: Serialize + ?Sized>(&self, url: &Url, token: String, json: &T) -> Result<Response, String> {
        let authorization = format!("Bearer {}", token);
        match self.client.delete(url.as_str()).header("Authorization", authorization).json(&json).send().await {
            Ok(response) => {
                // Ok response code to all DELETE to LessPass API is 200 or 204
                if response.status() == 200 || response.status() == 204 {
                    Ok(response)
                } else {
                    Err(format!("Error in DELETE request, unexpected status code {}", response.status()))
                }
            },
            // Cannot reach server by any reason
            Err(_) => Err(format!("Error making DELETE request to {}", url))
        }
    }

    /// Creates a new user
    pub async fn create_user(&self, email: String, password: String) -> Result<(), String> {
        let url = self.build_url("auth/users/");
        let body = Auth { email: email, password: password };
        self.post(&url, None, &body).await.map(|_|())
    }

    /// Gets current user info
    ///
    /// Need access token string
    pub async fn get_user(&self, token: String) -> Result<User, String> {
        let url = self.build_url("auth/users/me/");
        let user: User = match self.get(&url, token).await?.json().await {
            Ok(user) => user,
            Err(err) => return Err(format!("Unexpected response, {}", err))
        };
        Ok(user)
    }

    /// Deletes current user
    ///
    /// Need access token string
    pub async fn delete_user(&self, token: String, current_password: String) -> Result<(), String> {
        let url = self.build_url("auth/users/me/");
        let body = UserPassword { current_password: current_password };
        self.delete(&url, token, &body).await.map(|_|())
    }

    /// Changes current user password
    ///
    /// Need access token string
    pub async fn change_user_password(&self, token: String, current_password: String, new_password: String) -> Result<(), String> {
        let url = self.build_url("auth/users/set_password/");
        let body = ChangeUserPassword { current_password: current_password, new_password: new_password };
        self.post(&url, Some(token), &body).await.map(|_|())
    }

    /// Create a new token (perform initial auth with username and password)
    pub async fn create_token(&self, email: String, password: String) -> Result<Token, String> {
        let url = self.build_url("auth/jwt/create/");
        let body = Auth { email: email, password: password };
        let token: Token = match self.post(&url, None, &body).await?.json().await {
            Ok(token) => {
                debug!("New token created successfully");
                token
            },
            Err(err) => return Err(format!("Unexpected response, {}", err))
        };
        Ok(token)
    }

    /// Refresh a token
    ///
    /// Need refresh token string
    pub async fn refresh_token(&self, token: String) -> Result<Token, String> {
        let url = self.build_url("auth/jwt/refresh/");
        let body = Refresh { refresh: token };
        let token: Token = match self.post(&url, None, &body).await?.json().await {
            Ok(token) => {
                debug!("Token refreshed successfully");
                token
            },
            Err(err) => return Err(format!("Unexpected response, {}", err))
        };
        Ok(token)
    }

    /// Gets the password list
    ///
    /// Need access token string
    pub async fn get_passwords(&self, token: String) -> Result<Passwords, String> {
        let url = self.build_url("passwords/");
        let passwords: Passwords = match self.get(&url, token).await?.json().await {
            Ok(passwords) => passwords,
            Err(err) => return Err(format!("Unexpected response, {}", err))
        };
        Ok(passwords)
    }

    /// Creates a new password
    ///
    /// Need access token string
    pub async fn post_password(&self, token: String, password: &NewPassword) -> Result<(), String> {
        let url = self.build_url("passwords/");
        self.post(&url, Some(token), &password).await.map(|_|())
    }

    /// Updates existing password
    ///
    /// Need access token string
    pub async fn put_password(&self, token: String, id: String, password: &NewPassword) -> Result<(), String> {
        let path = format!("passwords/{}/", id);
        let url = self.build_url(&path);
        self.put(&url, token, &password).await.map(|_|())
    }

    /// Deletes existing password
    ///
    /// Need access token string
    pub async fn delete_password(&self, token: String, id: String) -> Result<(), String> {
        let path = format!("passwords/{}/", id);
        let url = self.build_url(&path);
        self.empty_delete(&url, token).await.map(|_|())
    }

}
