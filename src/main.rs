//
// lesspass-client
// Copyright (C) 2021 Óscar García Amor <ogarcia@connectical.com>
// Distributed under terms of the GNU GPLv3 license.
//

#[macro_use]
extern crate log;
extern crate clap;
extern crate xdg;
use clap::{crate_authors, crate_version, Arg, App};
use env_logger::Builder;
use log::LevelFilter;
use xdg::BaseDirectories;
use lesspass_client::{Auth, Client};

#[tokio::main]
async fn main() {
    pub const APP_NAME: &str = "lesspass-client";
}
