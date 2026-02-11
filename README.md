# envchain-rs

A Rust port of [sorah/envchain](https://github.com/sorah/envchain) — set environment variables with D-Bus secret service (Linux), age-encrypted files, or Windows Credential Manager.

## What?

Secrets for common computing environments, such as `AWS_SECRET_ACCESS_KEY`, are often set as environment variables.

A common practice is to set them in shell initialization files such as `.bashrc` and `.zshrc`. Putting these secrets on disk in this way is a grave risk.

`envchain` allows you to securely store credential environment variables in your system's secret vault, and set them as environment variables only when explicitly requested.

This Rust implementation supports:
- **Linux**: D-Bus Secret Service (gnome-keyring, KeePassXC, etc.) - default
- **Windows/WSL2**: Windows Credential Manager
- **Cross-platform**: Age encryption - portable, works without platform-specific backends

> For macOS Keychain support, use the original [envchain](https://github.com/sorah/envchain).

## Requirements

### D-Bus Secret Service Backend (default)
- D-Bus Secret Service compatible backend:
  - GNOME Keyring
  - KeePassXC
  - KDE Wallet (with Secret Service integration)

### Age Backend (portable)
- No external dependencies required
- Supports SSH keys (Ed25519, RSA) or native age identities
- Works in WSL, headless servers, containers

### Windows Credential Manager Backend
- Native Windows credential storage
- Works on both Windows and WSL2
- No additional setup required on Windows systems

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
# Build with only age backend (no D-Bus dependency)
cargo build --release --no-default-features --features age-backend

# Build with only secret-service backend
cargo build --release --no-default-features --features secret-service-backend

# Build with Windows Credential Manager backend (Windows/WSL2 only)
cargo build --release --no-default-features --features windows-credential-manager
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
- `secret-service` (default on Linux) - D-Bus Secret Service
- `age` - Age-encrypted file storage
- `wincred` - Windows Credential Manager (Windows/WSL2)

```bash
# Use age backend
envchain --backend age --set aws AWS_ACCESS_KEY_ID

# Use secret-service backend explicitly
envchain --backend secret-service --set aws AWS_ACCESS_KEY_ID

# Use Windows Credential Manager (on Windows/WSL2)
envchain --backend wincred --set aws AWS_ACCESS_KEY_ID
```

#### `--age-identity <path>`

Specify the age identity file (SSH private key or age identity):

```bash
envchain --backend age --age-identity ~/.ssh/id_ed25519 --set aws AWS_ACCESS_KEY_ID
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ENVCHAIN_BACKEND` | Default backend (`secret-service`, `age`, or `wincred`) |
| `ENVCHAIN_AGE_IDENTITY` | Path to age identity file for age backend |

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

## Windows Credential Manager Backend

The Windows Credential Manager backend provides native credential storage on Windows and WSL2.

### Usage on Windows

```bash
# Build with Windows backend
cargo build --release --no-default-features --features windows-credential-manager

# Use it
envchain --backend wincred --set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
envchain aws aws s3 ls
```

### Usage on WSL2

The Windows backend works seamlessly from WSL2, storing credentials in the Windows Credential Manager:

```bash
# Set backend to wincred
export ENVCHAIN_BACKEND=wincred

# Credentials are stored in Windows Credential Manager
envchain --set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

# Access from WSL2
envchain aws aws s3 ls
```

Credentials are stored with target names like `envchain:aws:AWS_ACCESS_KEY_ID` and can be viewed in Windows Credential Manager (Control Panel → Credential Manager → Windows Credentials).

## Differences from original envchain

- **Cross-platform backends**: Supports Linux (D-Bus Secret Service), Windows/WSL2 (Credential Manager), and portable age encryption
- **Additional features**:
  - `--unset` to remove stored variables
  - `--list NAMESPACE` to list variables within a namespace
  - `--list --show-value NAMESPACE` to display variable values
  - `--backend` to select storage backend
  - Age backend for portable, platform-independent operation
  - Windows Credential Manager for native Windows/WSL2 support

## Credits

- Original [envchain](https://github.com/sorah/envchain) by [Sorah Fukumori](https://github.com/sorah) and [eagletmt](https://github.com/eagletmt)

## License

MIT License
