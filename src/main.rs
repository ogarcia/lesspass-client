//
// lesspass-client
// Copyright (C) 2021 Óscar García Amor <ogarcia@connectical.com>
// Distributed under terms of the GNU GPLv3 license.
//

#[macro_use]
extern crate log;
extern crate clap;
extern crate xdg;
use clap::{crate_authors, crate_version, Arg, App, AppSettings, SubCommand};
use env_logger::Builder;
use log::LevelFilter;
use reqwest::Url;
use xdg::BaseDirectories;
use lesspass_client::{Auth, Client, Password, Token};

use std::{fs, path, process};

fn print_site(site: &Password) {
    println!("ID: {}", site.id);
    println!("Site: {}", site.site);
    println!("Login: {}", site.login);
    println!("Lowercase: {}", site.lowercase);
    println!("Uppercase: {}", site.uppercase);
    println!("Symbols: {}", site.symbols);
    println!("Numbers: {}", site.numbers);
    println!("Length: {}", site.length);
    println!("Couter: {}", site.counter);
}

async fn refresh_token(client: &Client, token: String) -> Result<Token, String> {
    // If token is empty simply return an error
    if token == "" || token == "\n" {
        debug!("Token file does not exists or is empty");
        return Err("Invalid token found".to_string())
    }
    client.refresh_token(token).await
}

async fn auth(client: &Client, token: String, user: Option<&str>, pass: Option<&str>) -> Result<Token, String> {
    // Try refresh token first
    match refresh_token(client, token).await {
        Ok(refreshed_token) => {
            info!("Token refreshed successfully");
            Ok(refreshed_token)
        },
        Err(_) => {
            // Token cannot be refreshed we need to obtain a new one
            warn!("Stored token is expired or invalid, it is necessary to re-authenticate with username and password");
            let user = match user {
                Some(user) => user.to_string(),
                None => {
                    println!("You must provide username");
                    process::exit(0x0100);
                }
            };
            trace!("Using {} as LESSPASS_USER", user);
            let pass = match pass {
                Some(pass) => pass.to_string(),
                None => {
                    println!("You must provide password");
                    process::exit(0x0100);
                }
            };
            trace!("Using {} (value is masked) as LESSPASS_PASS", "*".repeat(pass.len()));
            client.create_token(user, pass).await
        }
    }
}

#[tokio::main]
async fn main() {
    pub const APP_NAME: &str = "lesspass-client";

    let matches = App::new(APP_NAME)
        .version(crate_version!())
        .author(crate_authors!())
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg(Arg::with_name("host")
             .short("s")
             .long("server")
             .env("LESSPASS_HOST")
             .default_value("https://api.lesspass.com")
             .help("URL of LessPass server"))
        .arg(Arg::with_name("username")
             .short("u")
             .long("user")
             .env("LESSPASS_USER")
             .help("Username for auth on the LessPass server"))
        .arg(Arg::with_name("password")
             .short("p")
             .long("password")
             .env("LESSPASS_PASSWORD")
             .help("Password for auth on the LessPass server"))
        .arg(Arg::with_name("verbosity")
             .short("v")
             .long("verbose")
             .multiple(true)
             .help("Sets the level of verbosity"))
        .subcommand(SubCommand::with_name("user")
                    .about("user related commands")
                    .setting(AppSettings::SubcommandRequiredElseHelp)
                    .subcommand(SubCommand::with_name("create")
                                .about("create new user")
                                .setting(AppSettings::ArgRequiredElseHelp)
                                .arg(Arg::with_name("email")
                                     .help("login email")
                                     .required(true))
                                .arg(Arg::with_name("password")
                                     .help("login password")
                                     .required(true)))
                    .subcommand(SubCommand::with_name("password")
                                .about("change your user password")
                                .setting(AppSettings::ArgRequiredElseHelp)
                                .arg(Arg::with_name("old")
                                     .help("old password")
                                     .required(true))
                                .arg(Arg::with_name("new")
                                     .help("new password")
                                     .required(true))))
        .subcommand(SubCommand::with_name("password")
                    .about("password related commands")
                    .setting(AppSettings::SubcommandRequiredElseHelp)
                    .subcommand(SubCommand::with_name("add")
                                .about("add new password")
                                .setting(AppSettings::ArgRequiredElseHelp)
                                .arg(Arg::with_name("site")
                                     .help("target website")
                                     .required(true))
                                .arg(Arg::with_name("login")
                                     .help("site username")
                                     .required(true))
                                .arg(Arg::with_name("lowercase")
                                     .help("exclude lowercase characters")
                                     .short("L")
                                     .long("no-lower"))
                                .arg(Arg::with_name("uppercase")
                                     .help("exclude uppercase characters")
                                     .short("U")
                                     .long("no-upper"))
                                .arg(Arg::with_name("numbers")
                                     .help("exclude numbers")
                                     .short("N")
                                     .long("no-numbers"))
                                .arg(Arg::with_name("symbols")
                                     .help("exclude symbols")
                                     .short("S")
                                     .long("no-symbols"))
                                .arg(Arg::with_name("counter")
                                     .help("password counter [default: 1]")
                                     .short("c")
                                     .long("counter")
                                     .takes_value(true))
                                .arg(Arg::with_name("length")
                                     .help("length of the generated password [default: 16]")
                                     .short("l")
                                     .long("length")
                                     .takes_value(true)))
                    .subcommand(SubCommand::with_name("list")
                                .about("list all passwords")
                                .arg(Arg::with_name("long")
                                     .help("long list")
                                     .short("l")
                                     .long("long")))
                    .subcommand(SubCommand::with_name("show")
                                .about("show one password")
                                .setting(AppSettings::ArgRequiredElseHelp)
                                .arg(Arg::with_name("site")
                                     .help("target website")
                                     .required(true)))
                    .subcommand(SubCommand::with_name("update")
                                .about("update existing password")
                                .setting(AppSettings::ArgRequiredElseHelp)
                                .arg(Arg::with_name("id")
                                     .help("site id")
                                     .required(true))
                                .arg(Arg::with_name("site")
                                     .help("target website")
                                     .required(true))
                                .arg(Arg::with_name("login")
                                     .help("site username")
                                     .required(true))
                                .arg(Arg::with_name("lowercase")
                                     .help("exclude lowercase characters")
                                     .short("L")
                                     .long("no-lower"))
                                .arg(Arg::with_name("uppercase")
                                     .help("exclude uppercase characters")
                                     .short("U")
                                     .long("no-upper"))
                                .arg(Arg::with_name("numbers")
                                     .help("exclude numbers")
                                     .short("N")
                                     .long("no-numbers"))
                                .arg(Arg::with_name("symbols")
                                     .help("exclude symbols")
                                     .short("S")
                                     .long("no-symbols"))
                                .arg(Arg::with_name("counter")
                                     .help("password counter [default: 1]")
                                     .short("c")
                                     .long("counter")
                                     .takes_value(true))
                                .arg(Arg::with_name("length")
                                     .help("length of the generated password [default: 16]")
                                     .short("l")
                                     .long("length")
                                     .takes_value(true))))
        .get_matches();

    // Configure loglevel
    match matches.occurrences_of("verbosity") {
        0 => Builder::new().filter_level(LevelFilter::Off).init(),
        1 => Builder::new().filter_level(LevelFilter::Info).init(),
        2 => Builder::new().filter_level(LevelFilter::Debug).init(),
        3 | _ => Builder::new().filter_level(LevelFilter::Trace).init()
    };

    // Is safe to unwrap because it have default value
    let host = matches.value_of("host").unwrap();

    info!("Log level {:?}", log::max_level());
    trace!("Using {} as LESSPASS_HOST", host);

    // Validate host
    let host = match Url::parse(&host) {
        Ok(host) => host,
        Err(_) => {
            println!("LESSPASS_HOST {} is not a valid URL", host);
            process::exit(0x0100);
        }
    };

    // Try to get token form cache file
    let token_cache_file = match BaseDirectories::with_prefix(APP_NAME).unwrap().place_cache_file("token") {
        Ok(token_cache_file) => {
            debug!("Using cache file {} for read and store token", token_cache_file.as_path().display());
            token_cache_file
        },
        Err(err) => {
            warn!("There is a problem accessing to cache file caused by {}, disabling cache", err);
            path::PathBuf::new()
        }
    };
    let token = match fs::read_to_string(token_cache_file.as_path()) {
        Ok(token) => {
            trace!("Current token '{}'", token);
            token
        },
        Err(_) => String::from("")
    };

    // Configure client
    let client = Client::new(host);

    match matches.subcommand() {
        ("user", user_sub_matches) => {
            match user_sub_matches.unwrap().subcommand() {
                ("create", user_create_sub_matches) => println!("create"),
                ("password", user_password_sub_matches) => println!("password"),
                _ => unreachable!()
            };
        },
        ("password", password_sub_matches) => {
            match password_sub_matches.unwrap().subcommand() {
                ("add", password_add_sub_matches) => println!("add"),
                ("list", password_list_sub_matches) => {
                    // First auth
                    let token = match auth(&client, token, matches.value_of("username"), matches.value_of("password")).await {
                        Ok(token) => token,
                        Err(err) => {
                            println!("{}", err);
                            process::exit(0x0100);
                        }
                    };
                    // Get the password list
                    let mut passwords = match client.get_passwords(token.access).await {
                        Ok(passwords) => {
                            info!("Password list obtained successfully");
                            passwords
                        },
                        Err(err) => {
                            println!("{}", err);
                            process::exit(0x0100);
                        }
                    };
                    info!("Returning password list");
                    passwords.results.sort_by_key(|k| k.site.clone());
                    if password_list_sub_matches.unwrap().is_present("long") {
                        let mut counter = 0;
                        for password in passwords.results.iter() {
                            // If list has more than one item print a separator
                            if counter > 0 {
                                println!("{}", "- -".repeat(20));
                            }
                            print_site(password);
                            counter += 1;
                        }
                    } else {
                        for password in passwords.results.iter() {
                            println!("{}", password.site);
                        }
                    }
                },
                ("show", password_show_sub_matches) => println!("show"),
                ("update", password_update_sub_matches) => println!("update"),
                _ => unreachable!()
            };
        },
        ("create", user_create_sub_matches) => println!("create"),
        _ => unreachable!()
    };
}
