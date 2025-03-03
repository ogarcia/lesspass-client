//
// lesspass-client client.rs
// Copyright (C) 2021-2025 Óscar García Amor <ogarcia@connectical.com>
// Distributed under terms of the GNU GPLv3 license.
//

use log::{debug, trace};
use reqwest::{Method, Response, Url};
use serde::Serialize;

use super::error::Result;
use super::model::{
    Token,
    Auth,
    Refresh,
    User,
    UserPassword,
    UserChangePassword,
    NewPassword,
    Passwords
};

const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION")
);

/// Client for connecting to LessPass server
#[derive(Clone, Debug)]
pub struct Client {
    pub url: String,
    pub client: reqwest::Client
}

/// Builder interface to Client
///
/// Usage:
/// ```
/// use lesspass_client::Client;
///
/// let url = "https://api.lesspass.com";
/// let lpc = Client::new(url);
/// ```
impl Client {

    /// Configure the client itself
    pub fn new(url: impl Into<String>) -> Client {
        Client {
            url: url.into(),
            client: reqwest::Client::builder()
                .connection_verbose(true)
                .user_agent(USER_AGENT)
                .build()
                .expect("Client::new()")
        }
    }

    /// Internal helper function to join host url with endpoint path
    fn build_url(&self, path: &str) -> Result<Url> {
        Ok(Url::parse(&self.url)?.join(path)?)
    }

    /// Internal function to perform authenticated empty requests
    async fn empty_request(&self, method: Method, url: &Url, token: &str) -> Result<Response> {
        let authorization = format!("Bearer {}", token);
        Ok(self.client.request(method, url.as_str())
            .header("Authorization", authorization)
            .send().await?
            .error_for_status()?)
    }

    /// Internal function to perform (un)authenticated requests with body
    async fn request<J: Serialize + ?Sized>(&self, method: Method, url: &Url, token: Option<&str>, json: &J) -> Result<Response> {
        match token {
            Some(token) => {
                let authorization = format!("Bearer {}", token);
                Ok(self.client.request(method, url.as_str())
                    .header("Authorization", authorization)
                    .json(&json).send().await?
                    .error_for_status()?)
            },
            None => Ok(self.client.request(method, url.as_str()).json(&json).send().await?.error_for_status()?)
        }
    }

    /// Internal function to perform authenticated get requests
    async fn get(&self, path: &str, token: &str) -> Result<Response> {
        let url = self.build_url(path)?;
        trace!("GET: {url}");
        self.empty_request(Method::GET, &url, token).await
    }

    /// Internal function to perform (un)authenticated post requests
    async fn post<J: Serialize + ?Sized>(&self, path: &str, token: Option<&str>, json: &J) -> Result<Response> {
        let url = self.build_url(path)?;
        trace!("POST: {url}");
        self.request(Method::POST, &url, token, json).await
    }

    /// Internal function to perform authenticated put requests
    async fn put<J: Serialize + ?Sized>(&self, path: &str, token: &str, json: &J) -> Result<Response> {
        let url = self.build_url(path)?;
        trace!("PUT: {url}");
        self.request(Method::PUT, &url, Some(token), json).await
    }

    /// Internal function to perform authenticated delete requests without body
    async fn empty_delete(&self, path: &str, token: &str) -> Result<Response> {
        let url = self.build_url(path)?;
        trace!("DELETE: {url}");
        self.empty_request(Method::DELETE, &url, token).await
    }

    /// Internal function to perform authenticated delete requests
    async fn delete<J: Serialize + ?Sized>(&self, path: &str, token: &str, json: &J) -> Result<Response> {
        let url = self.build_url(path)?;
        trace!("DELETE: {url}");
        self.request(Method::DELETE, &url, Some(token), json).await
    }

    /// Create a new token (perform initial auth with email and password)
    pub async fn create_token(&self, email: &str, password: &str) -> Result<Token> {
        debug!("Requesting new token");
        let body = Auth { email: email.into(), password: password.into() };
        Ok(self.post("auth/jwt/create/", None, &body).await?.json::<Token>().await?)
    }

    /// Refresh a token
    ///
    /// Need refresh token string
    pub async fn refresh_token(&self, token: &str) -> Result<Token> {
        debug!("Requesting refreshed token");
        let body = Refresh { refresh: token.into() };
        Ok(self.post("auth/jwt/refresh/", None, &body).await?.json::<Token>().await?)
    }

    /// Creates a new user
    pub async fn create_user(&self, email: &str, password: &str) -> Result<()> {
        debug!("Requesting new user");
        let body = Auth { email: email.into(), password: password.into() };
        self.post("auth/users/", None, &body).await?;
        Ok(())
    }

    /// Gets current user info
    ///
    /// Need access token string
    pub async fn get_user(&self, token: &str) -> Result<User> {
        debug!("Requesting user info");
        Ok(self.get("auth/users/me/", token).await?.json::<User>().await?)
    }

    /// Changes current user password
    ///
    /// Need access token string
    pub async fn change_user_password(&self, token: &str, current_password: &str, new_password: &str) -> Result<()> {
        debug!("Requesting a password change");
        let body = UserChangePassword { current_password: current_password.into(), new_password: new_password.into() };
        self.post("auth/users/set_password/", Some(token), &body).await?;
        Ok(())
    }

    /// Deletes current user
    ///
    /// Need access token string
    pub async fn delete_user(&self, token: &str, current_password: &str) -> Result<()> {
        debug!("Requesting user deletion");
        let body = UserPassword { current_password: current_password.into() };
        self.delete("auth/users/me/", token, &body).await?;
        Ok(())
    }

    /// Gets the password list
    ///
    /// Need access token string
    pub async fn get_passwords(&self, token: &str) -> Result<Passwords> {
        Ok(self.get("passwords/", token).await?.json::<Passwords>().await?)
    }

    /// Creates a new password
    ///
    /// Need access token string
    pub async fn post_password(&self, token: &str, password: &NewPassword) -> Result<()> {
        self.post("passwords/", Some(token), password).await?;
        Ok(())
    }

    /// Updates existing password
    ///
    /// Need access token string
    pub async fn put_password(&self, token: &str, id: &str, password: &NewPassword) -> Result<()> {
        self.put(&format!("passwords/{id}/"), token, password).await?;
        Ok(())
    }

    /// Deletes existing password
    ///
    /// Need access token string
    pub async fn delete_password(&self, token: &str, id: &str) -> Result<()> {
        self.empty_delete(&format!("passwords/{id}/"), token).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::{NaiveDate, Utc};
    use mockito::{Matcher, Server};

    const JH: (&str, &str) = ("content-type", "application/json");

    #[tokio::test]
    async fn create_token() {
        let mut server = Server::new_async().await;
        let client = Client::new(&server.url());
        let request_body = r#"{"email": "user@example.com", "password": "password"}"#;
        let response_body = r#"{"access": "access-token", "refresh": "refresh-token"}"#;
        let _m = server.mock("POST", "/auth/jwt/create/")
            .with_status(201)
            .with_header(JH.0, JH.1)
            .match_body(Matcher::JsonString(request_body.to_string()))
            .with_body(response_body)
            .create_async()
            .await;
        // Ok response
        let token = client.create_token("user@example.com", "password").await.unwrap();
        assert_eq!("access-token", &token.access);
        assert_eq!("refresh-token", &token.refresh);
        // Bad response caused by auth error
        let error_token = client.create_token("bad", "bad").await.unwrap_err();
        assert_eq!(Some(501), error_token.status());
        let _m = server.mock("POST", "/auth/jwt/create/")
            .with_status(201)
            .with_header(JH.0, JH.1)
            .with_body("unexpected")
            .create_async()
            .await;
        // Bad response caused by unexpected json body
        let error_body = client.create_token("bad", "bad").await.unwrap_err();
        assert_eq!("reqwest error, error decoding response body", error_body.to_string());
    }

    #[tokio::test]
    async fn refresh_token() {
        let mut server = Server::new_async().await;
        let client = Client::new(&server.url());
        let request_body = r#"{"refresh": "refresh-token"}"#;
        let response_body = r#"{"access": "new-access-token", "refresh": "new-refresh-token"}"#;
        let _m = server.mock("POST", "/auth/jwt/refresh/")
            .with_status(201)
            .with_header(JH.0, JH.1)
            .match_body(Matcher::JsonString(request_body.to_string()))
            .with_body(response_body)
            .create_async()
            .await;
        // Ok response
        let token = client.refresh_token("refresh-token").await.unwrap();
        assert_eq!("new-access-token", &token.access);
        assert_eq!("new-refresh-token", &token.refresh);
        // Bad response caused by auth error
        let error_token = client.refresh_token("bad-token").await.unwrap_err();
        assert_eq!(Some(501), error_token.status());
        let _m = server.mock("POST", "/auth/jwt/refresh/")
            .with_status(201)
            .with_header(JH.0, JH.1)
            .with_body("unexpected")
            .create_async()
            .await;
        // Bad response caused by unexpected json body
        let error_body = client.refresh_token("bad-token").await.unwrap_err();
        assert_eq!("reqwest error, error decoding response body", error_body.to_string());
    }

    #[tokio::test]
    async fn create_user() {
        let mut server = Server::new_async().await;
        let client = Client::new(&server.url());
        let request_body = r#"{"email": "newuser@example.com", "password": "newpassword"}"#;
        let _m = server.mock("POST", "/auth/users/")
            .with_status(201)
            .with_header(JH.0, JH.1)
            .match_body(Matcher::JsonString(request_body.to_string()))
            .create_async()
            .await;
        // Ok response
        let user = client.create_user("newuser@example.com", "newpassword").await.unwrap();
        assert_eq!((), user);
    }

    #[tokio::test]
    async fn get_user() {
        let mut server = Server::new_async().await;
        let client = Client::new(&server.url());
        let response_body = r#"{"id":1, "email": "newuser@example.com"}"#;
        let _m = server.mock("GET", "/auth/users/me/")
            .with_status(200)
            .with_header(JH.0, JH.1)
            .match_header("authorization", "Bearer access-token")
            .with_body(response_body)
            .create_async()
            .await;
        // Ok response
        let user = client.get_user("access-token").await.unwrap();
        assert_eq!("1", user.id);
        assert_eq!("newuser@example.com", user.email);
        // Bad response caused by token error
        let error_in_token = client.get_user("bad-token").await.unwrap_err();
        assert_eq!(Some(501), error_in_token.status());
    }

    #[tokio::test]
    async fn change_user_password() {
        let mut server = Server::new_async().await;
        let client = Client::new(&server.url());
        let request_body = r#"{"current_password": "current", "new_password": "new"}"#;
        let _m = server.mock("POST", "/auth/users/set_password/")
            .with_status(201)
            .with_header(JH.0, JH.1)
            .match_header("authorization", "Bearer access-token")
            .match_body(Matcher::JsonString(request_body.to_string()))
            .create_async()
            .await;
        // Ok response
        let change_password = client.change_user_password("access-token", "current", "new").await.unwrap();
        assert_eq!((), change_password);
        // Bad response caused by token error
        let error_in_token = client.change_user_password("bad-token", "current", "new").await.unwrap_err();
        assert_eq!(Some(501), error_in_token.status());
    }

    #[tokio::test]
    async fn delete_user() {
        let mut server = Server::new_async().await;
        let client = Client::new(&server.url());
        let request_body = r#"{"current_password": "current"}"#;
        let _m = server.mock("DELETE", "/auth/users/me/")
            .with_status(200)
            .with_header(JH.0, JH.1)
            .match_header("authorization", "Bearer access-token")
            .match_body(Matcher::JsonString(request_body.to_string()))
            .create_async()
            .await;
        // Ok response
        let delete_user = client.delete_user("access-token", "current").await.unwrap();
        assert_eq!((), delete_user);
        // Bad response caused by token error
        let error_in_token = client.delete_user("bad-token", "current").await.unwrap_err();
        assert_eq!(Some(501), error_in_token.status());
    }

    #[tokio::test]
    async fn get_passwords() {
        let mut server = Server::new_async().await;
        let client = Client::new(&server.url());
        let response_body = r#"
        {
          "count": 3,
          "next": null,
          "previous": null,
          "results": [
            {
              "id": "e1a7e83c-9014-4585-95f5-4595160afe99",
              "login": "user@example.com",
              "site": "alice.example.com",
              "lowercase": true,
              "uppercase": true,
              "symbols": true,
              "digits": true,
              "counter": 10,
              "length": 16,
              "version": 2,
              "created": "2021-12-06T11:39:47.874027Z",
              "modified": "2021-12-06T11:39:47.874143Z"
            },
            {
              "id": "5f01f483-2b63-4faa-9c0c-b2dae03440f1",
              "login": "user@example.com",
              "site": "bob.example.com",
              "lowercase": false,
              "uppercase": true,
              "symbols": true,
              "numbers": false,
              "counter": 1,
              "length": 35,
              "version": 2,
              "created": "2021-11-21T11:34:18.361454Z",
              "modified": "2021-12-07T04:12:05.131415Z"
            },
            {
              "id": "10",
              "login": "user@example.com",
              "site": "charlie.example.com",
              "lowercase": false,
              "uppercase": true,
              "symbols": true,
              "digits": false,
              "numbers": true,
              "counter": 1,
              "length": 8,
              "version": 2,
              "created": "2023-05-10T12:05:36",
              "modified": "2023-06-02T17:33:54"
            }
          ]
        }
        "#;
        let _m = server.mock("GET", "/passwords/")
            .with_status(200)
            .with_header(JH.0, JH.1)
            .match_header("authorization", "Bearer access-token")
            .with_body(response_body)
            .create_async()
            .await;
        // Ok response
        let passwords = client.get_passwords("access-token").await.unwrap();
        assert_eq!(3, passwords.count);
        assert_eq!("e1a7e83c-9014-4585-95f5-4595160afe99", &passwords.results[0].id);
        assert_eq!("10", &passwords.results[2].id);
        assert_eq!(true, passwords.results[0].lowercase);
        assert_eq!("bob.example.com", &passwords.results[1].site);
        assert_eq!(false, passwords.results[1].digits);
        assert_eq!(NaiveDate::from_ymd_opt(2021, 11, 21).unwrap().and_hms_micro_opt(11, 34, 18, 361454).unwrap().and_local_timezone(Utc).unwrap(), passwords.results[1].created);
        assert_eq!(NaiveDate::from_ymd_opt(2021, 12, 7).unwrap().and_hms_micro_opt(4, 12, 5, 131415).unwrap().and_local_timezone(Utc).unwrap(), passwords.results[1].modified);
        assert_eq!(NaiveDate::from_ymd_opt(2023, 06, 2).unwrap().and_hms_micro_opt(17, 33, 54, 0).unwrap().and_local_timezone(Utc).unwrap(), passwords.results[2].modified);
        // Bad response caused by token error
        let error_in_token = client.get_passwords("bad-token").await.unwrap_err();
        assert_eq!(Some(501), error_in_token.status());
    }

    #[tokio::test]
    async fn post_password() {
        let mut server = Server::new_async().await;
        let client = Client::new(&server.url());
        let request_body = r#"
        {
          "login": "newuser@example.com",
          "site": "new.example.com",
          "uppercase": true,
          "lowercase": true,
          "digits": false,
          "symbols": true,
          "length": 18,
          "counter": 5,
          "version": 2
        }
        "#;
        let password = NewPassword {
            site: "new.example.com".to_string(),
            login: "newuser@example.com".to_string(),
            lowercase: true,
            uppercase: true,
            symbols: true,
            digits: false,
            length: 18,
            counter: 5,
            version: 2
        };
        let _m = server.mock("POST", "/passwords/")
            .with_status(201)
            .with_header(JH.0, JH.1)
            .match_header("authorization", "Bearer access-token")
            .match_body(Matcher::JsonString(request_body.to_string()))
            .create_async()
            .await;
        // Ok Response
        let post_password = client.post_password("access-token", &password).await.unwrap();
        assert_eq!((), post_password);
        // Bad response caused by token error
        let error_in_token = client.post_password("bad-token", &password).await.unwrap_err();
        assert_eq!(Some(501), error_in_token.status());
    }

    #[tokio::test]
    async fn put_password() {
        let mut server = Server::new_async().await;
        let client = Client::new(&server.url());
        let request_body = r#"
        {
          "login": "updateuser@example.com",
          "site": "update.example.com",
          "uppercase": true,
          "lowercase": true,
          "digits": false,
          "symbols": false,
          "length": 22,
          "counter": 1,
          "version": 2
        }
        "#;
        let password = NewPassword {
            site: "update.example.com".to_string(),
            login: "updateuser@example.com".to_string(),
            lowercase: true,
            uppercase: true,
            symbols: false,
            digits: false,
            length: 22,
            counter: 1,
            version: 2
        };
        let _m = server.mock("PUT", "/passwords/ce2835da-9047-43eb-a107-bad4f01d22a0/")
            .with_status(200)
            .with_header(JH.0, JH.1)
            .match_header("authorization", "Bearer access-token")
            .match_body(Matcher::JsonString(request_body.to_string()))
            .create_async()
            .await;
        // Ok Response
        let put_password = client.put_password("access-token", "ce2835da-9047-43eb-a107-bad4f01d22a0", &password).await.unwrap();
        assert_eq!((), put_password);
        // Bad response caused by token error
        let error_in_token = client.put_password("bad-token", "ce2835da-9047-43eb-a107-bad4f01d22a0", &password).await.unwrap_err();
        assert_eq!(Some(501), error_in_token.status());
        // Bad response caused by id error
        let error_in_id = client.put_password("access-token", "bad-id", &password).await.unwrap_err();
        assert_eq!(Some(501), error_in_id.status());
    }

    #[tokio::test]
    async fn delete_password() {
        let mut server = Server::new_async().await;
        let client = Client::new(&server.url());
        let _m = server.mock("DELETE", "/passwords/1c461df9-11eb-4bf1-976b-1c49d5598b8f/")
            .with_status(204)
            .with_header(JH.0, JH.1)
            .match_header("authorization", "Bearer access-token")
            .create_async()
            .await;
        // Ok Response
        let delete_password = client.delete_password("access-token", "1c461df9-11eb-4bf1-976b-1c49d5598b8f").await.unwrap();
        assert_eq!((), delete_password);
        // Bad response caused by token error
        let error_in_token = client.delete_password("bad-token", "1c461df9-11eb-4bf1-976b-1c49d5598b8f").await.unwrap_err();
        assert_eq!(Some(501), error_in_token.status());
        // Bad response caused by id error
        let error_in_id = client.delete_password("access-token", "bad-id").await.unwrap_err();
        assert_eq!(Some(501), error_in_id.status());
    }
}
