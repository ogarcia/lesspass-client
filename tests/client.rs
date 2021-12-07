//
// client.rs
// Copyright (C) 2021 Óscar García Amor <ogarcia@connectical.com>
// Distributed under terms of the GNU GPLv3 license.
//

use lesspass_client::{Client, NewPassword};
use chrono::{TimeZone, Utc};
use mockito::{Matcher, mock, server_url};
use reqwest::Url;

const JH: (&str, &str) = ("content-type", "application/json");

#[tokio::test]
async fn create_token() {
    let client = Client::new(Url::parse(&server_url()).unwrap());
    let request_body = r#"{"email": "user@example.com", "password": "password"}"#;
    let response_body = r#"{"access": "access-token", "refresh": "refresh-token"}"#;
    let _m = mock("POST", "/auth/jwt/create/")
        .with_status(201)
        .with_header(JH.0, JH.1)
        .match_body(Matcher::JsonString(request_body.to_string()))
        .with_body(response_body)
        .create();
    // Ok response
    let token = client.create_token("user@example.com".to_string(), "password".to_string()).await.unwrap();
    assert_eq!("access-token", &token.access);
    assert_eq!("refresh-token", &token.refresh);
    // Bad response caused by auth error
    let error_token = client.create_token("bad".to_string(), "bad".to_string()).await.unwrap_err();
    assert_eq!("Error in POST request, unexpected status code 501 Not Implemented", error_token);
    let _m = mock("POST", "/auth/jwt/create/")
        .with_status(201)
        .with_header(JH.0, JH.1)
        .with_body("unexpected")
        .create();
    // Bad response caused by unexpected json body
    let error_body = client.create_token("bad".to_string(), "bad".to_string()).await.unwrap_err();
    assert_eq!("Unexpected response, error decoding response body: expected value at line 1 column 1", error_body);
}

#[tokio::test]
async fn refresh_token() {
    let client = Client::new(Url::parse(&server_url()).unwrap());
    let request_body = r#"{"refresh": "refresh-token"}"#;
    let response_body = r#"{"access": "new-access-token", "refresh": "new-refresh-token"}"#;
    let _m = mock("POST", "/auth/jwt/refresh/")
        .with_status(201)
        .with_header(JH.0, JH.1)
        .match_body(Matcher::JsonString(request_body.to_string()))
        .with_body(response_body)
        .create();
    // Ok response
    let token = client.refresh_token("refresh-token".to_string()).await.unwrap();
    assert_eq!("new-access-token", &token.access);
    assert_eq!("new-refresh-token", &token.refresh);
    // Bad response caused by auth error
    let error_token = client.refresh_token("bad-token".to_string()).await.unwrap_err();
    assert_eq!("Error in POST request, unexpected status code 501 Not Implemented", error_token);
    let _m = mock("POST", "/auth/jwt/refresh/")
        .with_status(201)
        .with_header(JH.0, JH.1)
        .with_body("unexpected")
        .create();
    // Bad response caused by unexpected json body
    let error_body = client.refresh_token("bad-token".to_string()).await.unwrap_err();
    assert_eq!("Unexpected response, error decoding response body: expected value at line 1 column 1", error_body);
}

#[tokio::test]
async fn get_passwords() {
    let client = Client::new(Url::parse(&server_url()).unwrap());
    let response_body = r#"
{
  "count": 2,
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
      "numbers": true,
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
    }
  ]
}
    "#;
    let _m = mock("GET", "/passwords/")
        .with_status(200)
        .with_header(JH.0, JH.1)
        .match_header("authorization", "Bearer access-token")
        .with_body(response_body)
        .create();
    // Ok response
    let passwords = client.get_passwords("access-token".to_string()).await.unwrap();
    assert_eq!(2, passwords.count);
    assert_eq!("e1a7e83c-9014-4585-95f5-4595160afe99", &passwords.results[0].id);
    assert_eq!(true, passwords.results[0].lowercase);
    assert_eq!("bob.example.com", &passwords.results[1].site);
    assert_eq!(false, passwords.results[1].numbers);
    assert_eq!(Utc.ymd(2021, 11, 21).and_hms_micro(11, 34, 18, 361454), passwords.results[1].created);
    assert_eq!(Utc.ymd(2021, 12, 7).and_hms_micro(4, 12, 5, 131415), passwords.results[1].modified);
    // Bad response caused by token error
    let error_in_token = client.get_passwords("bad-token".to_string()).await.unwrap_err();
    assert_eq!("Error in GET request, unexpected status code 501 Not Implemented", error_in_token);
}

#[tokio::test]
async fn post_password() {
    let client = Client::new(Url::parse(&server_url()).unwrap());
    let request_body = r#"
{
  "login": "newuser@example.com",
  "site": "new.example.com",
  "uppercase": true,
  "lowercase": true,
  "numbers": false,
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
        numbers: false,
        length: 18,
        counter: 5,
        version: 2
    };
    let _m = mock("POST", "/passwords/")
        .with_status(201)
        .with_header(JH.0, JH.1)
        .match_header("authorization", "Bearer access-token")
        .match_body(Matcher::JsonString(request_body.to_string()))
        .create();
    let post_password = client.post_password("access-token".to_string(), &password).await.unwrap();
    // Ok Response
    assert_eq!((), post_password);
    // Bad response caused by token error
    let error_in_token = client.post_password("bad-token".to_string(), &password).await.unwrap_err();
    assert_eq!("Error in POST request, unexpected status code 501 Not Implemented", error_in_token);
}
