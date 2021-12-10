//
// lesspass-client
// Copyright (C) 2021 Óscar García Amor <ogarcia@connectical.com>
// Distributed under terms of the GNU GPLv3 license.
//

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use log::debug;
use serde::{Deserialize, Deserializer, Serialize};
use reqwest::{Response, Url};

#[derive(Serialize, Debug)]
pub struct Auth {
    pub email: String,
    pub password: String
}

#[derive(Serialize, Debug)]
pub struct Refresh {
    pub refresh: String
}

#[derive(Serialize, Debug)]
pub struct ChangeUserPassword {
    pub current_password: String,
    pub new_password: String
}

#[derive(Serialize, Debug)]
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

#[derive(Deserialize, Debug)]
pub struct Token {
    pub access: String,
    pub refresh: String
}

#[derive(Deserialize, Debug)]
pub struct Passwords {
    pub count: u32,
    // API implementation does not use (for now) previous and next
    // so are commented to avoid use memory with garbage
    //
    // pub previous: Option<u8>,
    // pub next: Option<u8>,
    pub results: Vec<Password>
}

#[derive(Deserialize, Eq, Ord, PartialEq, PartialOrd, Debug)]
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

#[derive(Debug)]
pub struct Client {
    pub host: Url
}

fn id_deserializer<'de, D>(deserializer: D) -> Result<String, D::Error> where D: Deserializer<'de>, {
    // Some server implementations (like Rockpass) store IDs in simple integers instead of strings
    // This function deserializes unsigned integers or strings
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

fn date_deserializer<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error> where D: Deserializer<'de>, {
    // Some server implementations (like Rockpass) store dates in NaiveDateTime
    // This function deserializes NaiveDateTime and DateTime with TimeZone
    let s = String::deserialize(deserializer)?;
    match s.parse::<NaiveDateTime>() {
        Ok(date) => Ok(Utc.from_utc_datetime(&date)),
        Err(_) => s.parse::<DateTime<Utc>>().map_err(serde::de::Error::custom)
    }
}

impl Client {

    pub fn new(host: Url) -> Client {
        Client { host: host }
    }

    fn build_url(self: &Self, path: &str) -> Url {
        // Calling .unwrap() is safe here because path is always valid
        self.host.join(&path).unwrap()
    }

    async fn get(self: &Self, url: &Url, token: String) -> Result<Response, String> {
        // Internal function to perform authenticated get requests
        let authorization = format!("Bearer {}", token);
        match reqwest::Client::new().get(url.as_str()).header("Authorization", authorization).send().await {
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

    async fn post<T: Serialize + ?Sized>(self: &Self, url: &Url, token: Option<String>, json: &T) -> Result<Response, String> {
        // Internal function to perform post requests
        let request = match token {
            Some(token) => {
                let authorization = format!("Bearer {}", token);
                reqwest::Client::new().post(url.as_str()).header("Authorization", authorization).json(&json).send().await
            },
            None => reqwest::Client::new().post(url.as_str()).json(&json).send().await
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

    async fn put<T: Serialize + ?Sized>(self: &Self, url: &Url, token: String, json: &T) -> Result<Response, String> {
        // Internal function to perform authenticated put requests
        let authorization = format!("Bearer {}", token);
        match reqwest::Client::new().put(url.as_str()).header("Authorization", authorization).json(&json).send().await {
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

    async fn delete(self: &Self, url: &Url, token: String) -> Result<Response, String> {
        // Internal function to perform authenticated delete requests
        let authorization = format!("Bearer {}", token);
        match reqwest::Client::new().delete(url.as_str()).header("Authorization", authorization).send().await {
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

    pub async fn create_user(self: &Self, auth: &Auth) -> Result<(), String> {
        let url = self.build_url("auth/users/");
        self.post(&url, None, &auth).await.map(|_|())
    }

    pub async fn change_user_password(self: &Self, token: String, password: &ChangeUserPassword) -> Result<(), String> {
        let url = self.build_url("auth/users/set_password/");
        self.post(&url, Some(token), &password).await.map(|_|())
    }

    pub async fn create_token(self: &Self, email: String, password: String) -> Result<Token, String> {
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

    pub async fn refresh_token(self: &Self, token: String) -> Result<Token, String> {
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

    pub async fn get_passwords(self: &Self, token: String) -> Result<Passwords, String> {
        let url = self.build_url("passwords/");
        let passwords: Passwords = match self.get(&url, token).await?.json().await {
            Ok(passwords) => passwords,
            Err(err) => return Err(format!("Unexpected response, {}", err))
        };
        Ok(passwords)
    }

    pub async fn post_password(self: &Self, token: String, password: &NewPassword) -> Result<(), String> {
        let url = self.build_url("passwords/");
        self.post(&url, Some(token), &password).await.map(|_|())
    }

    pub async fn put_password(self: &Self, token: String, id: String, password: &NewPassword) -> Result<(), String> {
        let path = format!("passwords/{}/", id);
        let url = self.build_url(&path);
        self.put(&url, token, &password).await.map(|_|())
    }

    pub async fn delete_password(self: &Self, token: String, id: String) -> Result<(), String> {
        let path = format!("passwords/{}/", id);
        let url = self.build_url(&path);
        self.delete(&url, token).await.map(|_|())
    }

}
