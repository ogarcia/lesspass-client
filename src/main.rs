//
// lesspass-client
// Copyright (C) 2021 Óscar García Amor <ogarcia@connectical.com>
// Distributed under terms of the GNU GPLv3 license.
//

#[macro_use]
extern crate log;
extern crate clap;
extern crate xdg;
use clap::{crate_authors, crate_version, Arg, ArgMatches, App, AppSettings, SubCommand};
use env_logger::Builder;
use log::LevelFilter;
use reqwest::Url;
use xdg::BaseDirectories;
use lesspass_client::{Auth, ChangeUserPassword, NewPassword, Password, Passwords, Token, Client};

use std::{fs, path, process};

const APP_NAME: &str = "lesspass-client";

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

fn parse_password_matches(matches: &ArgMatches) -> NewPassword {
    let lower = matches.is_present("lowercase");
    let upper = matches.is_present("uppercase");
    let numbers = matches.is_present("numbers");
    let symbols = matches.is_present("symbols");
    if lower && upper && numbers && symbols {
        println!("Not all character sets can be excluded");
        process::exit(0x0100);
    }
    // Matches values are strings, pase to integers
    let length: u8 = match matches.value_of("length").unwrap_or("16").parse() {
        Ok(length) => length,
        Err(err) => {
            println!("Cannot parse length: {}", err);
            process::exit(0x0100);
        }
    };
    let counter: u32 = match matches.value_of("counter").unwrap_or("1").parse() {
        Ok(counter) => counter,
        Err(err) => {
            println!("Cannot parse counter: {}", err);
            process::exit(0x0100);
        }
    };
    // Min password length is 5 and max 35
    if !(5..=35).contains(&length) {
        println!("The minimum password length is 5 and the maximum is 35");
        process::exit(0x0100);
    }
    // Counter cannot be 0
    if counter == 0 {
        println!("Invalid counter value");
        process::exit(0x0100);
    }
    NewPassword {
        site: matches.value_of("site").unwrap().to_string(),
        login: matches.value_of("login").unwrap().to_string(),
        lowercase: !lower,
        uppercase: !upper,
        symbols: !symbols,
        numbers: !numbers,
        length: length,
        counter: counter,
        version: 2
    }
}

async fn refresh_token(client: &Client, token: String) -> Result<Token, String> {
    // If token is empty simply return an error
    if token == "" || token == "\n" {
        debug!("Token file does not exists or is empty");
        return Err("Invalid token found".to_string())
    }
    client.refresh_token(token).await
}

async fn auth(client: &Client, user: Option<&str>, pass: Option<&str>) -> Token {
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

    // Try refresh token first
    let requested_token = match refresh_token(client, token).await {
        Ok(refreshed_token) => {
            info!("Token refreshed successfully");
            refreshed_token
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
            match client.create_token(user, pass).await {
                Ok(token) => token,
                Err(err) => {
                    println!("{}", err);
                    process::exit(0x0100);
                }
            }
        }
    };

    trace!("Access token '{}'", requested_token.access);
    trace!("Refresh token '{}'", requested_token.refresh);

    // Save new refresh token
    if token_cache_file != path::PathBuf::new() {
        match fs::write(token_cache_file.as_path(), &requested_token.refresh) {
            Ok(_) => info!("Refreshed token stored successfully"),
            Err(err) => warn!("There is a problem storing refreshed token file caused by {}", err)
        };
    }

    requested_token
}


async fn get_passwords(client: &Client, user: Option<&str>, pass: Option<&str>) -> Passwords {
    // First auth to get token
    let token = auth(&client, user, pass).await;
    // Get the password list
    match client.get_passwords(token.access).await {
        Ok(passwords) => {
            debug!("Password list obtained successfully");
            return passwords
        },
        Err(err) => {
            println!("{}", err);
            process::exit(0x0100);
        }
    };
}

#[tokio::main]
async fn main() {

    let matches = App::new(APP_NAME)
        .version(crate_version!())
        .author(crate_authors!())
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::VersionlessSubcommands)
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
                    .setting(AppSettings::VersionlessSubcommands)
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
                    .setting(AppSettings::VersionlessSubcommands)
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
                    .subcommand(SubCommand::with_name("delete")
                                .about("delete existing password")
                                .setting(AppSettings::ArgRequiredElseHelp)
                                .arg(Arg::with_name("id")
                                     .help("site id")
                                     .required(true)))
                    .subcommand(SubCommand::with_name("list")
                                .about("list all passwords")
                                .arg(Arg::with_name("full")
                                     .help("get full list (not only sites)")
                                     .short("f")
                                     .long("full")))
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

    // Configure client
    let client = Client::new(host);

    match matches.subcommand() {
        ("user", user_sub_matches) => {
            match user_sub_matches.unwrap().subcommand() {
                ("create", user_create_sub_matches) => {
                    // Get requested email and password (safe to unwrap because are a required fields)
                    let user_create_sub_matches = user_create_sub_matches.unwrap();
                    let auth = Auth {
                        email: user_create_sub_matches.value_of("email").unwrap().to_string(),
                        password: user_create_sub_matches.value_of("password").unwrap().to_string()
                    };
                    trace!("Parsed new user options: {:?}", auth);
                    info!("Creating new user");
                    match client.create_user(&auth).await {
                        Ok(()) => println!("New user created successfully"),
                        Err(err) => {
                            println!("{}", err);
                            process::exit(0x0100);
                        }
                    }
                },
                ("password", user_password_sub_matches) => {
                    // Get requested old and new password (safe to unwrap because are a required fields)
                    let user_password_sub_matches = user_password_sub_matches.unwrap();
                    let change = ChangeUserPassword {
                        current_password: user_password_sub_matches.value_of("old").unwrap().to_string(),
                        new_password: user_password_sub_matches.value_of("new").unwrap().to_string()
                    };
                    trace!("Parsed change password options: {:?}", change);
                    // Perform auth and get token
                    let token = auth(&client, matches.value_of("username"), matches.value_of("password")).await;
                    info!("Performing password change");
                    match client.change_user_password(token.access, &change).await {
                        Ok(()) => println!("Password changed successfully"),
                        Err(err) => {
                            println!("{}", err);
                            process::exit(0x0100);
                        }
                    }
                },
                _ => unreachable!()
            };
        },
        ("password", password_sub_matches) => {
            match password_sub_matches.unwrap().subcommand() {
                ("add", password_add_sub_matches) => {
                    let new_password = parse_password_matches(password_add_sub_matches.unwrap());
                    trace!("Parsed site options: {:?}", new_password);
                    // Perform auth and get token
                    let token = auth(&client, matches.value_of("username"), matches.value_of("password")).await;
                    info!("Creating new password");
                    match client.post_password(token.access, &new_password).await {
                        Ok(()) => println!("New password created successfully"),
                        Err(err) => {
                            println!("{}", err);
                            process::exit(0x0100);
                        }
                    }
                },
                ("delete", password_delete_sub_matches) => {
                    // Get id (safe to unwrap because is a required field)
                    let id = password_delete_sub_matches.unwrap().value_of("id").unwrap().to_string();
                    trace!("Parsed site ID: {}", id);
                    // Perform auth and get token
                    let token = auth(&client, matches.value_of("username"), matches.value_of("password")).await;
                    info!("Deleting password {}", id);
                    match client.delete_password(token.access, id).await {
                        Ok(()) => println!("Password deleted successfully"),
                        Err(err) => {
                            println!("{}", err);
                            process::exit(0x0100);
                        }
                    }
                },
                ("list", password_list_sub_matches) => {
                    // Get the password list
                    let mut passwords = get_passwords(&client, matches.value_of("username"), matches.value_of("password")).await;
                    info!("Returning password list");
                    // Check if the password list is empty
                    if passwords.results.len() == 0 {
                        println!("The password list is empty");
                    } else {
                        // Sort passwords alphabetically by site
                        passwords.results.sort_by_key(|k| k.site.clone());
                        if password_list_sub_matches.unwrap().is_present("full") {
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
                    }
                },
                ("show", password_show_sub_matches) => {
                    // Get requested password (safe to unwrap because is a required field)
                    let site = password_show_sub_matches.unwrap().value_of("site").unwrap();
                    // Get the password list
                    let passwords = get_passwords(&client, matches.value_of("username"), matches.value_of("password")).await;
                    debug!("Looking for site {} in password list", site);
                    match passwords.results.iter().find(|&s| s.site == site) {
                        Some(password) => {
                            info!("Returning password settings");
                            print_site(password);
                        },
                        None => println!("Site '{}' not found in password list", site)
                    };
                },
                ("update", password_update_sub_matches) => {
                    // Get id (safe to unwrap because is a required field)
                    let id = password_update_sub_matches.unwrap().value_of("id").unwrap().to_string();
                    trace!("Parsed site ID: {}", id);
                    let new_password = parse_password_matches(password_update_sub_matches.unwrap());
                    trace!("Parsed site options: {:?}", new_password);
                    // Perform auth and get token
                    let token = auth(&client, matches.value_of("username"), matches.value_of("password")).await;
                    info!("Updating password {}", id);
                    match client.put_password(token.access, id, &new_password).await {
                        Ok(()) => println!("Password updated successfully"),
                        Err(err) => {
                            println!("{}", err);
                            process::exit(0x0100);
                        }
                    }
                },
                _ => unreachable!()
            };
        },
        _ => unreachable!()
    };
}
