# lesspass-client

[![Made with Rust](https://forthebadge.com/images/badges/made-with-rust.svg)](https://www.rust-lang.org)
[![Gluten Free](https://forthebadge.com/images/badges/gluten-free.svg)](https://en.wikipedia.org/wiki/Gluten-free_diet)
[![It works](https://forthebadge.com/images/badges/it-works-why.svg)](https://youtu.be/dQw4w9WgXcQ)

A Rust client for [LessPass][lesspass] API server like [Rockpass][rockpass],
library and CLI.

If you are looking for a minimal implementation to only get the values from
the server see [rlpcli][rlpcli].

[lesspass]: https://github.com/lesspass/lesspass
[rockpass]: https://gitlab.com/ogarcia/rockpass
[rlpcli]: https://gitlab.com/ogarcia/rlpcli

## Library documentation

The library is published in [crates.io][crate] and its documentation is
detailed in [docs.rs][docs].

[crate]: https://crates.io/crates/lesspass-client
[docs]: https://docs.rs/lesspass-client/latest/lesspass_client/

## CLI Installation

### From binary

Simply download latest release from [releases page][releases].

[releases]: https://gitlab.com/ogarcia/lesspass-client/-/releases

### From source

#### Installing Rust

lesspass-client build has been tested with current Rust stable release
version. You can install Rust from your distribution package or use
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
git clone https://gitlab.com/ogarcia/lesspass-client.git
cd lesspass-client
cargo build --release
```

### Arch Linux package

lesspass-client is packaged in Arch Linux and can be downloaded from the
[AUR][aur].

[aur]: https://aur.archlinux.org/packages/lesspass-client

## Usage

Main command help.
```
LessPass server API client library and CLI written in Rust

Usage: lesspass-client [OPTIONS] <COMMAND>

Commands:
  user      User related commands
  password  Password related commands
  help      Print this message or the help of the given subcommand(s)

Options:
  -s, --server <host>                 URL of LessPass server [env: LESSPASS_HOST=] [default: https://api.lesspass.com]
  -u, --user <username>               Username for auth on the LessPass server [env: LESSPASS_USER=]
  -p, --password <password>           Password for auth on the LessPass server [env: LESSPASS_PASS=]
  -m, --master-password <masterpass>  Master password (only needed to print site passwords) [env: LESSPASS_MASTERPASS=]
  -v, --verbose...                    Sets the level of verbosity
  -h, --help                          Print help information
  -V, --version                       Print version information

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
| LESSPASS_MASTERPASS | Master password (only needed to print site passwords) |

Every command an subcommand has its own help, simply pass `-h` or `--help`
to see it.

### How to get the API password

By default the API password is not in plain text but it is encrypted with
LessPass itself as another access password. This prevents the password from
being sent unencrypted.

The following parameters are used to calculate the password to be sent.
- Site: `lesspass.com`
- Login: The email address you use to authenticate.
- Master password: The password you use to authenticate.
- Options: Default. This means all options checked, size 16 and counter 1.

For example, if to authenticate against the API server we use as user
`test@example.com` and as password `123456`, this would generate a password
`Kd*k5i63iN$^z)?V` that is the one we must use as `LESSPASS_PASS`.

You can do this with lesspass-client itself.
```sh
$ lesspass-client -m 123456 password build lesspass.com test@example.com
Kd*k5i63iN$^z)?V
```
