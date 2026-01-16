# envchain-rs

A Rust port of [sorah/envchain](https://github.com/sorah/envchain) — set environment variables securely using your system's secret storage.

## What?

Secrets for common computing environments, such as `AWS_SECRET_ACCESS_KEY`, are often set as environment variables.

A common practice is to set them in shell initialization files such as `.bashrc` and `.zshrc`. Putting these secrets on disk in this way is a grave risk.

`envchain` allows you to securely store credential environment variables in your system's secret vault, and set them as environment variables only when explicitly requested.

This Rust implementation supports multiple backends:
- **macOS Keychain** - native keychain integration (default on macOS), compatible with original envchain
- **D-Bus Secret Service** - gnome-keyring, KeePassXC, etc. (default on Linux)
- **Age encryption** - portable, works without system keyring (ideal for WSL, headless servers, containers)

## Requirements

### macOS Keychain Backend (default on macOS)
- macOS 10.12 or later
- Compatible with secrets stored by the original [sorah/envchain](https://github.com/sorah/envchain)

### D-Bus Secret Service Backend (default on Linux)
- D-Bus Secret Service compatible backend:
  - GNOME Keyring
  - KeePassXC
  - KDE Wallet (with Secret Service integration)

### Age Backend (portable)
- No external dependencies required
- Supports SSH keys (Ed25519, RSA) or native age identities
- Works in WSL, headless servers, containers

## Installation

### From Source

```bash
cargo build --release
cp target/release/envchain ~/.local/bin/
# or
sudo cp target/release/envchain /usr/local/bin/
```

### Feature Flags

```bash
# Build with only age backend (minimal dependencies)
cargo build --release --no-default-features --features age-backend

# Build with only keychain backend (macOS)
cargo build --release --no-default-features --features keychain-backend

# Build with only secret-service backend (Linux)
cargo build --release --no-default-features --features secret-service-backend
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

### Backend Selection

#### `--backend <type>`

Select the storage backend:
- `keychain` - macOS Keychain (default on macOS)
- `secret-service` - D-Bus Secret Service (default on Linux)
- `age` - Age-encrypted file storage (portable)

```bash
# Use age backend
envchain --backend age --set aws AWS_ACCESS_KEY_ID

# Use secret-service backend explicitly
envchain --backend secret-service --set aws AWS_ACCESS_KEY_ID
```

#### `--age-identity <path>`

Specify the age identity file (SSH private key or age identity):

```bash
envchain --backend age --age-identity ~/.ssh/id_ed25519 --set aws AWS_ACCESS_KEY_ID
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ENVCHAIN_BACKEND` | Default backend (`keychain`, `secret-service`, or `age`) |
| `ENVCHAIN_AGE_IDENTITY` | Path to age identity file for age backend |

## macOS Keychain Backend

The keychain backend stores secrets in the macOS Keychain with service names prefixed by `envchain-`, making it fully compatible with secrets stored by the original [sorah/envchain](https://github.com/sorah/envchain).

```bash
# On macOS, keychain is the default
envchain --set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
envchain aws aws s3 ls

# Or explicitly select keychain backend
envchain --backend keychain --set aws AWS_ACCESS_KEY_ID
```

## Age Backend Details

The age backend stores secrets in `~/.config/envchain/secrets.age` encrypted with [age](https://age-encryption.org/).

### Using SSH Keys

You can use your existing SSH keys:

```bash
# Use existing SSH key
export ENVCHAIN_BACKEND=age
export ENVCHAIN_AGE_IDENTITY=~/.ssh/id_ed25519

envchain --set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
envchain aws aws s3 ls
```

Or generate a dedicated key:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/envchain_key -N ""
export ENVCHAIN_AGE_IDENTITY=~/.ssh/envchain_key
```

### Using Native Age Identity

If no identity is specified, a native age identity is auto-generated at `~/.config/envchain/identity.txt`.

```bash
export ENVCHAIN_BACKEND=age
envchain --set aws AWS_ACCESS_KEY_ID  # Auto-generates identity on first use
```

### Passphrase Handling

**Important**: The age crate does not support ssh-agent. If your SSH key has a passphrase:
- You'll be prompted for the passphrase each time
- Consider using an unencrypted SSH key dedicated to envchain
- Or use a native age identity (no passphrase by default)

## Differences from original envchain

- **Cross-platform**: Supports macOS (Keychain), Linux (D-Bus Secret Service), and portable age encryption
- **macOS Keychain compatibility**: Uses the same service name format (`envchain-*`) as the original implementation
- **Additional features**:
  - `--unset` to remove stored variables
  - `--list NAMESPACE` to list variables within a namespace
  - `--list --show-value NAMESPACE` to display variable values
  - `--backend` to select storage backend
  - Age backend for portable, D-Bus-free operation

## Credits

- Original [envchain](https://github.com/sorah/envchain) by [Sorah Fukumori](https://github.com/sorah) and [eagletmt](https://github.com/eagletmt)

## License

MIT License
