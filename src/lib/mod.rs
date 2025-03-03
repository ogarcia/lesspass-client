//
// lesspass-client
// Copyright (C) 2021-2025 Óscar García Amor <ogarcia@connectical.com>
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
//! use lesspass_client::{Client, Result};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Define a host URL to conect to
//!     let url = "https://api.lesspass.com";
//!
//!     // Create LessPass API client
//!     let client = Client::new(url);
//!
//!     // Perform an authentication with user and password
//!     let token = client
//!         .create_token("user@example.com", "password")
//!         .await?;
//!
//!     // Get the password list
//!     let passwords = client.get_passwords(&token.access).await?;
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

mod client;
mod error;
pub mod model;

pub use client::Client;
pub use error::{Error, Result};
