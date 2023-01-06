# lesspass-client

[![Made with Rust](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com)
[![Gluten Free](https://forthebadge.com/images/badges/gluten-free.svg)](https://forthebadge.com)
[![It works](https://forthebadge.com/images/badges/it-works-why.svg)](https://forthebadge.com)

A Rust client for [LessPass][lesspass] server API, library and CLI.

[lesspass]: https://github.com/lesspass/lesspass

## Installation

### From binary

Simply download latest release from [releases page][releases].

[releases]: https://github.com/ogarcia/lesspass-client/releases

### From source

#### Installing Rust

lesspass-client build has been tested with current Rust stable release
version 1.57.0. You can install Rust from your distribution package or use
[`rustup`](rustup).
```
rustup default stable
```

If you prefer, you can use the stable version only for install
lesspass-client.
```
rustup override set stable
```

[rustup]: https://rustup.rs/

#### Building lesspass-client

To build lesspass-client simply execute the following commands.
```sh
git clone https://github.com/ogarcia/lesspass-client.git
cd lesspass-client
cargo build --release
```

## Usage

Main command help.
```
USAGE:
    lesspass-client [FLAGS] [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v, --verbose    Sets the level of verbosity

OPTIONS:
    -s, --server <host>          URL of LessPass server [env: LESSPASS_HOST=]  [default: https://api.lesspass.com]
    -p, --password <password>    Password for auth on the LessPass server [env: LESSPASS_PASS=]
    -u, --user <username>        Username for auth on the LessPass server [env: LESSPASS_USER=]

SUBCOMMANDS:
    help        Prints this message or the help of the given subcommand(s)
    password    password related commands
    user        user related commands

EXAMPLES:
    Get the password list specifying the server and without token cached:
      lesspass-client -s http://localhost:8000 -u user@sample.com -p passwd password list

    Show a password:
      lesspass-client password show sample.site.com

    Add a new password:
      lesspass-client password add sample.site.com user@site.com

    Update a existing password (you need the ID from password show command):
      lesspass-client password update eed5950b-97f2-4ba9-bf09-7784b6c7e5a2 new.url.com new@email.com
```

In first time use you need to pass username and password to perform login.
After first run, lesspass-client stores the login token in your
`XDG_CACHE_HOME` directory and you can run commands without the need to pass
username and password again.

To pass configuration values you can use the CLI options or following
environment variables.

| Variable | Used for |
| --- | --- |
| LESSPASS_HOST | URL of API server (deafult https://api.lesspass.com) |
| LESSPASS_USER | Username (ex. user@example.com) |
| LESSPASS_PASS | Password |

Every command an subcommand has its own help, simply pass `-h` or `--help`
to see it.
