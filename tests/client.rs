//
// client.rs
// Copyright (C) 2021-2023 Óscar García Amor <ogarcia@connectical.com>
// Distributed under terms of the GNU GPLv3 license.
//

use lesspass_client::{Client, NewPassword};
use chrono::{NaiveDate, Utc};
use mockito::{Matcher, Server};
use reqwest::Url;

const JH: (&str, &str) = ("content-type", "application/json");

#[tokio::test]
async fn create_user() {
    let mut server = Server::new_async().await;
    let client = Client::new(Url::parse(&server.url()).unwrap());
    let request_body = r#"{"email": "newuser@example.com", "password": "newpassword"}"#;
    let _m = server.mock("POST", "/auth/users/")
        .with_status(201)
        .with_header(JH.0, JH.1)
        .match_body(Matcher::JsonString(request_body.to_string()))
        .create_async()
        .await;
    // Ok response
    let user = client.create_user("newuser@example.com".to_string(), "newpassword".to_string()).await.unwrap();
    assert_eq!((), user);
}

#[tokio::test]
async fn get_user() {
    let mut server = Server::new_async().await;
    let client = Client::new(Url::parse(&server.url()).unwrap());
    let response_body = r#"{"id":1, "email": "newuser@example.com"}"#;
    let _m = server.mock("GET", "/auth/users/me/")
        .with_status(200)
        .with_header(JH.0, JH.1)
        .match_header("authorization", "Bearer access-token")
        .with_body(response_body)
        .create_async()
        .await;
    // Ok response
    let user = client.get_user("access-token".to_string()).await.unwrap();
    assert_eq!("1", user.id);
    assert_eq!("newuser@example.com", user.email);
    // Bad response caused by token error
    let error_in_token = client.get_user("bad-token".to_string()).await.unwrap_err();
    assert_eq!("Error in GET request, unexpected status code 501 Not Implemented", error_in_token);
}

#[tokio::test]
async fn delete_user() {
    let mut server = Server::new_async().await;
    let client = Client::new(Url::parse(&server.url()).unwrap());
    let request_body = r#"{"current_password": "current"}"#;
    let _m = server.mock("DELETE", "/auth/users/me/")
        .with_status(200)
        .with_header(JH.0, JH.1)
        .match_header("authorization", "Bearer access-token")
        .match_body(Matcher::JsonString(request_body.to_string()))
        .create_async()
        .await;
    // Ok response
    let delete_user = client.delete_user("access-token".to_string(), "current".to_string()).await.unwrap();
    assert_eq!((), delete_user);
    // Bad response caused by token error
    let error_in_token = client.delete_user("bad-token".to_string(), "current".to_string()).await.unwrap_err();
    assert_eq!("Error in DELETE request, unexpected status code 501 Not Implemented", error_in_token);
}

#[tokio::test]
async fn change_user_password() {
    let mut server = Server::new_async().await;
    let client = Client::new(Url::parse(&server.url()).unwrap());
    let request_body = r#"{"current_password": "current", "new_password": "new"}"#;
    let _m = server.mock("POST", "/auth/users/set_password/")
        .with_status(201)
        .with_header(JH.0, JH.1)
        .match_header("authorization", "Bearer access-token")
        .match_body(Matcher::JsonString(request_body.to_string()))
        .create_async()
        .await;
    // Ok response
    let change_password = client.change_user_password("access-token".to_string(), "current".to_string(), "new".to_string()).await.unwrap();
    assert_eq!((), change_password);
    // Bad response caused by token error
    let error_in_token = client.change_user_password("bad-token".to_string(), "current".to_string(), "new".to_string()).await.unwrap_err();
    assert_eq!("Error in POST request, unexpected status code 501 Not Implemented", error_in_token);
}

#[tokio::test]
async fn create_token() {
    let mut server = Server::new_async().await;
    let client = Client::new(Url::parse(&server.url()).unwrap());
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
    let token = client.create_token("user@example.com".to_string(), "password".to_string()).await.unwrap();
    assert_eq!("access-token", &token.access);
    assert_eq!("refresh-token", &token.refresh);
    // Bad response caused by auth error
    let error_token = client.create_token("bad".to_string(), "bad".to_string()).await.unwrap_err();
    assert_eq!("Error in POST request, unexpected status code 501 Not Implemented", error_token);
    let _m = server.mock("POST", "/auth/jwt/create/")
        .with_status(201)
        .with_header(JH.0, JH.1)
        .with_body("unexpected")
        .create_async()
        .await;
    // Bad response caused by unexpected json body
    let error_body = client.create_token("bad".to_string(), "bad".to_string()).await.unwrap_err();
    assert_eq!("Unexpected response, error decoding response body", error_body);
}

#[tokio::test]
async fn refresh_token() {
    let mut server = Server::new_async().await;
    let client = Client::new(Url::parse(&server.url()).unwrap());
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
    let token = client.refresh_token("refresh-token".to_string()).await.unwrap();
    assert_eq!("new-access-token", &token.access);
    assert_eq!("new-refresh-token", &token.refresh);
    // Bad response caused by auth error
    let error_token = client.refresh_token("bad-token".to_string()).await.unwrap_err();
    assert_eq!("Error in POST request, unexpected status code 501 Not Implemented", error_token);
    let _m = server.mock("POST", "/auth/jwt/refresh/")
        .with_status(201)
        .with_header(JH.0, JH.1)
        .with_body("unexpected")
        .create_async()
        .await;
    // Bad response caused by unexpected json body
    let error_body = client.refresh_token("bad-token".to_string()).await.unwrap_err();
    assert_eq!("Unexpected response, error decoding response body", error_body);
}

#[tokio::test]
async fn get_passwords() {
    let mut server = Server::new_async().await;
    let client = Client::new(Url::parse(&server.url()).unwrap());
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
    let passwords = client.get_passwords("access-token".to_string()).await.unwrap();
    assert_eq!(3, passwords.count);
    assert_eq!("e1a7e83c-9014-4585-95f5-4595160afe99", &passwords.results[0].id);
    assert_eq!("10", &passwords.results[2].id);
    assert_eq!(true, passwords.results[0].lowercase);
    assert_eq!("bob.example.com", &passwords.results[1].site);
    assert_eq!(false, passwords.results[1].numbers);
    assert_eq!(NaiveDate::from_ymd_opt(2021, 11, 21).unwrap().and_hms_micro_opt(11, 34, 18, 361454).unwrap().and_local_timezone(Utc).unwrap(), passwords.results[1].created);
    assert_eq!(NaiveDate::from_ymd_opt(2021, 12, 7).unwrap().and_hms_micro_opt(4, 12, 5, 131415).unwrap().and_local_timezone(Utc).unwrap(), passwords.results[1].modified);
    assert_eq!(NaiveDate::from_ymd_opt(2023, 06, 2).unwrap().and_hms_micro_opt(17, 33, 54, 0).unwrap().and_local_timezone(Utc).unwrap(), passwords.results[2].modified);
    // Bad response caused by token error
    let error_in_token = client.get_passwords("bad-token".to_string()).await.unwrap_err();
    assert_eq!("Error in GET request, unexpected status code 501 Not Implemented", error_in_token);
}

#[tokio::test]
async fn post_password() {
    let mut server = Server::new_async().await;
    let client = Client::new(Url::parse(&server.url()).unwrap());
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
    let _m = server.mock("POST", "/passwords/")
        .with_status(201)
        .with_header(JH.0, JH.1)
        .match_header("authorization", "Bearer access-token")
        .match_body(Matcher::JsonString(request_body.to_string()))
        .create_async()
        .await;
    // Ok Response
    let post_password = client.post_password("access-token".to_string(), &password).await.unwrap();
    assert_eq!((), post_password);
    // Bad response caused by token error
    let error_in_token = client.post_password("bad-token".to_string(), &password).await.unwrap_err();
    assert_eq!("Error in POST request, unexpected status code 501 Not Implemented", error_in_token);
}

#[tokio::test]
async fn put_password() {
    let mut server = Server::new_async().await;
    let client = Client::new(Url::parse(&server.url()).unwrap());
    let request_body = r#"
{
  "login": "updateuser@example.com",
  "site": "update.example.com",
  "uppercase": true,
  "lowercase": true,
  "numbers": false,
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
        numbers: false,
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
    let put_password = client.put_password("access-token".to_string(), "ce2835da-9047-43eb-a107-bad4f01d22a0".to_string(), &password).await.unwrap();
    assert_eq!((), put_password);
    // Bad response caused by token error
    let error_in_token = client.put_password("bad-token".to_string(), "ce2835da-9047-43eb-a107-bad4f01d22a0".to_string(), &password).await.unwrap_err();
    assert_eq!("Error in PUT request, unexpected status code 501 Not Implemented", error_in_token);
    // Bad response caused by id error
    let error_in_id = client.put_password("access-token".to_string(), "bad-id".to_string(), &password).await.unwrap_err();
    assert_eq!("Error in PUT request, unexpected status code 501 Not Implemented", error_in_id);
}

#[tokio::test]
async fn delete_password() {
    let mut server = Server::new_async().await;
    let client = Client::new(Url::parse(&server.url()).unwrap());
    let _m = server.mock("DELETE", "/passwords/1c461df9-11eb-4bf1-976b-1c49d5598b8f/")
        .with_status(204)
        .with_header(JH.0, JH.1)
        .match_header("authorization", "Bearer access-token")
        .create_async()
        .await;
    // Ok Response
    let delete_password = client.delete_password("access-token".to_string(), "1c461df9-11eb-4bf1-976b-1c49d5598b8f".to_string()).await.unwrap();
    assert_eq!((), delete_password);
    // Bad response caused by token error
    let error_in_token = client.delete_password("bad-token".to_string(), "1c461df9-11eb-4bf1-976b-1c49d5598b8f".to_string()).await.unwrap_err();
    assert_eq!("Error in DELETE request, unexpected status code 501 Not Implemented", error_in_token);
    // Bad response caused by id error
    let error_in_id = client.delete_password("access-token".to_string(), "bad-id".to_string()).await.unwrap_err();
    assert_eq!("Error in DELETE request, unexpected status code 501 Not Implemented", error_in_id);
}
