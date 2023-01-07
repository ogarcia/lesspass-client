//
// lesspass-client
// Copyright (C) 2021-2023 Óscar García Amor <ogarcia@connectical.com>
// Distributed under terms of the GNU GPLv3 license.
//

#[macro_use]
extern crate log;
extern crate clap;
extern crate xdg;
use clap::{command, value_parser, Arg, ArgAction, ArgMatches, Command};
use env_logger::Builder;
use log::LevelFilter;
use reqwest::Url;
use xdg::BaseDirectories;
use lesspass_client::{NewPassword, Password, Passwords, Token, Client};

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
    let lower = matches.get_flag("lowercase");
    let upper = matches.get_flag("uppercase");
    let numbers = matches.get_flag("numbers");
    let symbols = matches.get_flag("symbols");
    if lower && upper && numbers && symbols {
        println!("Not all character sets can be excluded");
        process::exit(0x0100);
    }
    let length: u8 = *matches.get_one("length").unwrap_or(&16);
    let counter: u32 = *matches.get_one("counter").unwrap_or(&1);
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
        site: matches.get_one::<String>("site").unwrap().to_string(),
        login: matches.get_one::<String>("login").unwrap().to_string(),
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

async fn auth(client: &Client, user: Option<&String>, pass: Option<&String>) -> Token {
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


async fn get_passwords(client: &Client, user: Option<&String>, pass: Option<&String>) -> Passwords {
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

    let matches = command!()
        .subcommand_required(true)
        .arg_required_else_help(true)
        .after_help(r#"EXAMPLES:
    Get the password list specifying the server and without token cached:
      lesspass-client -s http://localhost:8000 -u user@sample.com -p passwd password list

    Show a password:
      lesspass-client password show sample.site.com

    Add a new password:
      lesspass-client password add sample.site.com user@site.com

    Update a existing password (you need the ID from password show command):
      lesspass-client password update eed5950b-97f2-4ba9-bf09-7784b6c7e5a2 new.url.com new@email.com"#)
        .arg(Arg::new("host")
             .short('s')
             .long("server")
             .env("LESSPASS_HOST")
             .default_value("https://api.lesspass.com")
             .help("URL of LessPass server"))
        .arg(Arg::new("username")
             .short('u')
             .long("user")
             .env("LESSPASS_USER")
             .help("Username for auth on the LessPass server"))
        .arg(Arg::new("password")
             .short('p')
             .long("password")
             .env("LESSPASS_PASS")
             .help("Password for auth on the LessPass server"))
        .arg(Arg::new("verbosity")
             .short('v')
             .long("verbose")
             .action(ArgAction::Count)
             .help("Sets the level of verbosity"))
        .subcommand(Command::new("user")
                    .about("user related commands")
                    .subcommand_required(true)
                    .arg_required_else_help(true)
                    .subcommand(Command::new("create")
                                .about("create new user")
                                .arg_required_else_help(true)
                                .arg(Arg::new("email")
                                     .help("login email")
                                     .required(true))
                                .arg(Arg::new("password")
                                     .help("login password")
                                     .required(true)))
                    .subcommand(Command::new("password")
                                .about("change your user password")
                                .arg_required_else_help(true)
                                .arg(Arg::new("old")
                                     .help("old password")
                                     .required(true))
                                .arg(Arg::new("new")
                                     .help("new password")
                                     .required(true))))
        .subcommand(Command::new("password")
                    .about("password related commands")
                    .subcommand_required(true)
                    .arg_required_else_help(true)
                    .subcommand(Command::new("add")
                                .about("add new password")
                                .arg_required_else_help(true)
                                .arg(Arg::new("site")
                                     .help("target website")
                                     .required(true))
                                .arg(Arg::new("login")
                                     .help("site username")
                                     .required(true))
                                .arg(Arg::new("lowercase")
                                     .help("exclude lowercase characters")
                                     .short('L')
                                     .long("no-lower")
                                     .action(ArgAction::SetTrue))
                                .arg(Arg::new("uppercase")
                                     .help("exclude uppercase characters")
                                     .short('U')
                                     .long("no-upper")
                                     .action(ArgAction::SetTrue))
                                .arg(Arg::new("numbers")
                                     .help("exclude numbers")
                                     .short('N')
                                     .long("no-numbers")
                                     .action(ArgAction::SetTrue))
                                .arg(Arg::new("symbols")
                                     .help("exclude symbols")
                                     .short('S')
                                     .long("no-symbols")
                                     .action(ArgAction::SetTrue))
                                .arg(Arg::new("counter")
                                     .help("password counter [default: 1]")
                                     .short('c')
                                     .long("counter")
                                     .value_parser(value_parser!(u32)))
                                .arg(Arg::new("length")
                                     .help("length of the generated password [default: 16]")
                                     .short('l')
                                     .long("length")
                                     .value_parser(value_parser!(u8))))
                    .subcommand(Command::new("delete")
                                .about("delete existing password")
                                .arg_required_else_help(true)
                                .arg(Arg::new("id")
                                     .help("site id")
                                     .required(true)))
                    .subcommand(Command::new("list")
                                .about("list all passwords")
                                .arg(Arg::new("full")
                                     .help("get full list (not only sites)")
                                     .short('f')
                                     .long("full")
                                     .action(ArgAction::SetTrue))
                                .arg(Arg::new("id")
                                     .help("sort password list by id instead of site")
                                     .short('i')
                                     .long("id")
                                     .action(ArgAction::SetTrue)))
                    .subcommand(Command::new("show")
                                .about("show one password")
                                .arg_required_else_help(true)
                                .arg(Arg::new("id")
                                     .help("search by id instead of site")
                                     .short('i')
                                     .long("id")
                                     .action(ArgAction::SetTrue))
                                .arg(Arg::new("site")
                                     .help("target id or site")
                                     .required(true)))
                    .subcommand(Command::new("update")
                                .about("update existing password")
                                .arg_required_else_help(true)
                                .arg(Arg::new("id")
                                     .help("site id")
                                     .required(true))
                                .arg(Arg::new("site")
                                     .help("target website")
                                     .required(true))
                                .arg(Arg::new("login")
                                     .help("site username")
                                     .required(true))
                                .arg(Arg::new("lowercase")
                                     .help("exclude lowercase characters")
                                     .short('L')
                                     .long("no-lower")
                                     .action(ArgAction::SetTrue))
                                .arg(Arg::new("uppercase")
                                     .help("exclude uppercase characters")
                                     .short('U')
                                     .long("no-upper")
                                     .action(ArgAction::SetTrue))
                                .arg(Arg::new("numbers")
                                     .help("exclude numbers")
                                     .short('N')
                                     .long("no-numbers")
                                     .action(ArgAction::SetTrue))
                                .arg(Arg::new("symbols")
                                     .help("exclude symbols")
                                     .short('S')
                                     .long("no-symbols")
                                     .action(ArgAction::SetTrue))
                                .arg(Arg::new("counter")
                                     .help("password counter [default: 1]")
                                     .short('c')
                                     .long("counter")
                                     .value_parser(value_parser!(u32)))
                                .arg(Arg::new("length")
                                     .help("length of the generated password [default: 16]")
                                     .short('l')
                                     .long("length")
                                     .value_parser(value_parser!(u8)))))
        .get_matches();

    // Configure loglevel
    match matches.get_count("verbosity") {
        0 => Builder::new().filter_level(LevelFilter::Off).init(),
        1 => Builder::new().filter_level(LevelFilter::Info).init(),
        2 => Builder::new().filter_level(LevelFilter::Debug).init(),
        3 | _ => Builder::new().filter_level(LevelFilter::Trace).init()
    };

    // Is safe to unwrap because it have default value
    let host = matches.get_one::<String>("host").unwrap();

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
        Some(("user", user_sub_matches)) => {
            match user_sub_matches.subcommand() {
                Some(("create", user_create_sub_matches)) => {
                    // Get requested email and password (safe to unwrap because are a required fields)
                    let email = user_create_sub_matches.get_one::<String>("email").unwrap().to_string();
                    let password = user_create_sub_matches.get_one::<String>("password").unwrap().to_string();
                    trace!("Parsed new user options: '{}' '{}'", email, password);
                    info!("Creating new user");
                    match client.create_user(email, password).await {
                        Ok(()) => println!("New user created successfully"),
                        Err(err) => {
                            println!("{}", err);
                            process::exit(0x0100);
                        }
                    }
                },
                Some(("password", user_password_sub_matches)) => {
                    // Get requested old and new password (safe to unwrap because are a required fields)
                    let old = user_password_sub_matches.get_one::<String>("old").unwrap().to_string();
                    let new = user_password_sub_matches.get_one::<String>("new").unwrap().to_string();
                    trace!("Parsed change password options: '{}' '{}'", old, new);
                    // Perform auth and get token
                    let token = auth(&client, matches.get_one::<String>("username"), matches.get_one::<String>("password")).await;
                    info!("Performing password change");
                    match client.change_user_password(token.access, old, new).await {
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
        Some(("password", password_sub_matches)) => {
            match password_sub_matches.subcommand() {
                Some(("add", password_add_sub_matches)) => {
                    let new_password = parse_password_matches(password_add_sub_matches);
                    trace!("Parsed site options: {:?}", new_password);
                    // Perform auth and get token
                    let token = auth(&client, matches.get_one::<String>("username"), matches.get_one::<String>("password")).await;
                    info!("Creating new password");
                    match client.post_password(token.access, &new_password).await {
                        Ok(()) => println!("New password created successfully"),
                        Err(err) => {
                            println!("{}", err);
                            process::exit(0x0100);
                        }
                    }
                },
                Some(("delete", password_delete_sub_matches)) => {
                    // Get id (safe to unwrap because is a required field)
                    let id = password_delete_sub_matches.get_one::<String>("id").unwrap().to_string();
                    trace!("Parsed site ID: {}", id);
                    // Perform auth and get token
                    let token = auth(&client, matches.get_one::<String>("username"), matches.get_one::<String>("password")).await;
                    info!("Deleting password {}", id);
                    match client.delete_password(token.access, id).await {
                        Ok(()) => println!("Password deleted successfully"),
                        Err(err) => {
                            println!("{}", err);
                            process::exit(0x0100);
                        }
                    }
                },
                Some(("list", password_list_sub_matches)) => {
                    // Get the password list
                    let mut passwords = get_passwords(&client, matches.get_one::<String>("username"), matches.get_one::<String>("password")).await;
                    info!("Returning password list");
                    // Check if the password list is empty
                    if passwords.results.len() == 0 {
                        println!("The password list is empty");
                    } else {
                        if password_list_sub_matches.get_flag("id") {
                            // Sort passwords alphabetically by id
                            passwords.results.sort();
                        } else {
                            // Sort passwords alphabetically by site
                            passwords.results.sort_by_key(|k| k.site.clone());
                        }
                        if password_list_sub_matches.get_flag("full") {
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
                Some(("show", password_show_sub_matches)) => {
                    // Get requested password (safe to unwrap because is a required field)
                    let site = password_show_sub_matches.get_one::<String>("site").unwrap();
                    // Get the password list
                    let passwords = get_passwords(&client, matches.get_one::<String>("username"), matches.get_one::<String>("password")).await;
                    debug!("Looking for site {} in password list", site);
                    // Check if the requested password is an id or a site
                    let password = if password_show_sub_matches.get_flag("id") {
                        passwords.results.iter().find(|&s| s.id == *site)
                    } else {
                        passwords.results.iter().find(|&s| s.site == *site)
                    };
                    match password {
                        Some(password) => {
                            info!("Returning password settings");
                            print_site(password);
                        },
                        None => println!("Site '{}' not found in password list", site)
                    };
                },
                Some(("update", password_update_sub_matches)) => {
                    // Get id (safe to unwrap because is a required field)
                    let id = password_update_sub_matches.get_one::<String>("id").unwrap().to_string();
                    trace!("Parsed site ID: {}", id);
                    let new_password = parse_password_matches(password_update_sub_matches);
                    trace!("Parsed site options: {:?}", new_password);
                    // Perform auth and get token
                    let token = auth(&client, matches.get_one::<String>("username"), matches.get_one::<String>("password")).await;
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
