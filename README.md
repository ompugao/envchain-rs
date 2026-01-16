# envchain-rs

A Rust port of [sorah/envchain](https://github.com/sorah/envchain) — set environment variables with D-Bus secret service (Linux).

## What?

Secrets for common computing environments, such as `AWS_SECRET_ACCESS_KEY`, are often set as environment variables.

A common practice is to set them in shell initialization files such as `.bashrc` and `.zshrc`. Putting these secrets on disk in this way is a grave risk.

`envchain` allows you to securely store credential environment variables in your system's secret vault, and set them as environment variables only when explicitly requested.

This Rust implementation supports **Linux only** via D-Bus Secret Service (gnome-keyring, KeePassXC, etc.).

> For macOS Keychain support, use the original [envchain](https://github.com/sorah/envchain).

## Requirements (Linux)

- D-Bus Secret Service compatible backend:
  - GNOME Keyring
  - KeePassXC
  - KDE Wallet (with Secret Service integration)

## Installation

### From Source

```bash
cargo build --release
cp target/release/envchain ~/.local/bin/
# or
sudo cp target/release/envchain /usr/local/bin/
```

## Usage

### Saving variables

Environment variables are stored within a specified *namespace*. You can set variables in a single command:

```bash
envchain --set NAMESPACE ENV [ENV ..]
```

You will be prompted to enter the values for each variable. For example, set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` within a namespace called `aws`:

```bash
$ envchain --set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
aws.AWS_ACCESS_KEY_ID: my-access-key
aws.AWS_SECRET_ACCESS_KEY: secret
```

### Execute commands with defined variables

```bash
$ env | grep AWS_ || echo "No AWS_ env vars"
No AWS_ env vars

$ envchain aws env | grep AWS_
AWS_ACCESS_KEY_ID=my-access-key
AWS_SECRET_ACCESS_KEY=secret

$ envchain aws s3cmd ls
⋮
```

You may specify multiple namespaces at once, separated by commas:

```bash
$ envchain aws,hubot env | grep -E 'AWS_|HUBOT_'
AWS_ACCESS_KEY_ID=my-access-key
AWS_SECRET_ACCESS_KEY=secret
HUBOT_HIPCHAT_PASSWORD=xxxx
```

### Options

#### `--set`, `-s`

Set environment variables in a namespace:

```bash
envchain --set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
```

#### `--noecho`, `-n`

Do not echo user input when setting variables:

```bash
$ envchain --set --noecho foo BAR
foo.BAR (noecho):
```

#### `--list`, `-l`

List all namespaces:

```bash
$ envchain --list
aws
hubot
```

List variables in a specific namespace:

```bash
$ envchain --list aws
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
```

List variables with their values:

```bash
$ envchain --list --show-value aws
AWS_ACCESS_KEY_ID=my-access-key
AWS_SECRET_ACCESS_KEY=secret
```

#### `--unset`

Remove variables from a namespace:

```bash
envchain --unset aws AWS_ACCESS_KEY_ID
```

## Differences from original envchain

- **Linux only**: This Rust port only supports D-Bus Secret Service. For macOS, use the original C implementation.
- **Additional features**:
  - `--unset` to remove stored variables
  - `--list NAMESPACE` to list variables within a namespace
  - `--list --show-value NAMESPACE` to display variable values

## Credits

- Original [envchain](https://github.com/sorah/envchain) by [Sorah Fukumori](https://github.com/sorah) and [eagletmt](https://github.com/eagletmt)

## License

MIT License
