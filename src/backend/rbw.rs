//! Bitwarden backend via the `rbw` CLI.
//!
//! Secrets are stored as `KEY=VALUE` lines in the notes field of one Bitwarden
//! entry per namespace, grouped in a folder (default `envchain`, overridable via
//! `ENVCHAIN_RBW_FOLDER` or the `--rbw-folder` flag). Auth (unlock/login) is
//! handled by `rbw` itself; we ensure the vault is unlocked before each command.

use super::{Backend, EnvKey, EnvValue, Namespace};
use std::collections::HashMap;
use std::io::Write as _;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

const DEFAULT_FOLDER: &str = "envchain";
const FOLDER_ENV: &str = "ENVCHAIN_RBW_FOLDER";

// ── JSON shapes returned by `rbw list --raw` and `rbw get --raw` ─────────────

#[derive(Debug, serde::Deserialize)]
struct ListItem {
    name: String,
    folder: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct RbwItem {
    /// Entry type: "Login", "Note", etc.
    #[serde(rename = "type")]
    item_type: Option<String>,
    notes: Option<String>,
}

pub struct RbwBackend {
    folder: String,
}

impl RbwBackend {
    pub fn new(folder: Option<String>) -> Result<Self, String> {
        let folder = folder
            .or_else(|| std::env::var(FOLDER_ENV).ok())
            .unwrap_or_else(|| DEFAULT_FOLDER.to_string());
        validate_identifier(&folder, "folder")?;
        Ok(Self { folder })
    }
}

impl Backend for RbwBackend {
    fn list_namespaces(&self) -> Result<Vec<Namespace>, String> {
        ensure_unlocked()?;

        let mut cmd = Command::new("rbw");
        cmd.args(["list", "--raw"]);
        set_rbw_tty(&mut cmd);
        let output = cmd
            .output()
            .map_err(|e| format!("failed to run `rbw list`: {e}"))?;

        check_status("rbw list", &output)?;

        let items: Vec<ListItem> = serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("failed to parse `rbw list --raw` output: {e}"))?;

        let mut names: Vec<Namespace> = items
            .into_iter()
            .filter(|i| i.folder.as_deref().unwrap_or("") == self.folder)
            .map(|i| i.name)
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    fn list_secrets(&self, namespace: &str) -> Result<HashMap<EnvKey, EnvValue>, String> {
        validate_identifier(namespace, "namespace")?;
        ensure_unlocked()?;
        match get_item_raw(namespace, &self.folder)? {
            Some(item) => Ok(item.notes.as_deref().map(parse).unwrap_or_default()),
            None => Ok(HashMap::new()),
        }
    }

    fn set_secret(&mut self, namespace: &str, key: &str, value: &str) -> Result<(), String> {
        validate_identifier(namespace, "namespace")?;
        validate_identifier(key, "key")?;
        ensure_unlocked()?;
        match get_item_raw(namespace, &self.folder)? {
            Some(item) => {
                let is_secure_note = item.item_type.as_deref() == Some("Note");
                let notes = Zeroizing::new(update(&item.notes.unwrap_or_default(), key, value));
                edit_item(namespace, &self.folder, &notes, is_secure_note)
            }
            None => {
                let mut map = HashMap::new();
                map.insert(key.to_string(), value.to_string());
                let notes = Zeroizing::new(serialize(&map));
                create_item(namespace, &self.folder, &notes)
            }
        }
    }

    fn delete_secret(&mut self, namespace: &str, key: &str) -> Result<(), String> {
        validate_identifier(namespace, "namespace")?;
        validate_identifier(key, "key")?;
        ensure_unlocked()?;
        match get_item_raw(namespace, &self.folder)? {
            None => {
                eprintln!("WARNING: namespace `{namespace}` not found");
                Ok(())
            }
            Some(item) => {
                let is_secure_note = item.item_type.as_deref() == Some("Note");
                match remove(&item.notes.unwrap_or_default(), key) {
                    None => {
                        eprintln!("WARNING: key `{key}` not found in namespace `{namespace}`");
                        Ok(())
                    }
                    Some(updated) => {
                        if parse(&updated).is_empty() {
                            delete_item(namespace, &self.folder)
                        } else {
                            edit_item(
                                namespace,
                                &self.folder,
                                &Zeroizing::new(updated),
                                is_secure_note,
                            )
                        }
                    }
                }
            }
        }
    }
}

// ── rbw subprocess helpers ──────────────────────────────────────────────────

/// Core `rbw get` subprocess call. Returns `None` if the item does not exist.
fn get_item_raw(name: &str, folder: &str) -> Result<Option<RbwItem>, String> {
    let mut cmd = Command::new("rbw");
    cmd.args(["get", "--raw", "--folder", folder, name]);
    set_rbw_tty(&mut cmd);
    let output = cmd
        .output()
        .map_err(|e| format!("failed to run `rbw get`: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("no entry found")
            || stderr.contains("no items found")
            || stderr.contains("Entry not found")
        {
            return Ok(None);
        }
        return Err(format!(
            "`rbw get` failed ({}): {}",
            output.status,
            stderr.trim()
        ));
    }

    let item: RbwItem = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("failed to parse `rbw get --raw` output: {e}"))?;

    Ok(Some(item))
}

/// Create a new entry (Login type) with `notes_content` in the given folder.
///
/// `rbw add` always creates a Login entry. When stdin is piped (not a TTY),
/// rbw reads the editor content directly from stdin. Format: first line =
/// password (empty), rest = notes.
fn create_item(name: &str, folder: &str, notes_content: &str) -> Result<(), String> {
    // Prepend empty line so rbw's parse_editor treats it as an empty password.
    let stdin_content = format!("\n{notes_content}\n");
    pipe_to_rbw(&["add", "--folder", folder, name], &stdin_content)
}

/// Edit an existing entry, replacing its notes with `notes_content`.
///
/// For Login entries (created by `create_item`): pipe `\n<content>` so the
/// first line (password) stays empty. For SecureNote entries: rbw internally
/// prepends `\n` before parsing, so pipe the content directly.
fn edit_item(
    name: &str,
    folder: &str,
    notes_content: &str,
    is_secure_note: bool,
) -> Result<(), String> {
    let stdin_content = if is_secure_note {
        format!("{notes_content}\n")
    } else {
        format!("\n{notes_content}\n")
    };
    pipe_to_rbw(&["edit", "--folder", folder, name], &stdin_content)
}

/// Delete an entry by name and folder.
fn delete_item(name: &str, folder: &str) -> Result<(), String> {
    ensure_unlocked()?;

    let mut cmd = Command::new("rbw");
    cmd.args(["remove", "--folder", folder, name]);
    set_rbw_tty(&mut cmd);
    let output = cmd
        .output()
        .map_err(|e| format!("failed to run `rbw remove`: {e}"))?;
    check_status("rbw remove", &output)
}

/// Ensure the rbw vault is unlocked before running commands. This triggers
/// `rbw unlock` (and pinentry) up front, so that subsequent rbw commands don't
/// need to prompt — avoiding TTY conflicts with piped stdin/stdout.
fn ensure_unlocked() -> Result<(), String> {
    let mut cmd = Command::new("rbw");
    cmd.args(["unlocked"]);
    set_rbw_tty(&mut cmd);
    let output = cmd
        .output()
        .map_err(|e| format!("failed to run `rbw unlocked`: {e}"))?;
    if !output.status.success() {
        // Not unlocked — run `rbw unlock` which will invoke pinentry.
        let mut cmd = Command::new("rbw");
        cmd.args(["unlock"]);
        set_rbw_tty(&mut cmd);
        let status = cmd
            .status()
            .map_err(|e| format!("failed to run `rbw unlock`: {e}"))?;
        if !status.success() {
            return Err(format!("`rbw unlock` failed ({status})"));
        }
    }
    Ok(())
}

/// Pass the real TTY device path (e.g. `/dev/pts/3`) so that the rbw-agent
/// daemon — which has no controlling terminal — can tell pinentry which TTY to
/// use. `/dev/tty` would only work inside the current process tree; the agent
/// needs an absolute device path.
fn set_rbw_tty(cmd: &mut Command) {
    if let Some(tty) = real_tty_path() {
        cmd.env("RBW_TTY", tty);
    }
}

/// Resolve the real TTY device path from stderr (fd 2), falling back to stdin
/// (fd 0) and then `/dev/tty` if the real path cannot be determined.
fn real_tty_path() -> Option<std::ffi::OsString> {
    // Try stderr first (stdout may be piped), then stdin.
    for fd in ["2", "0"] {
        let link = format!("/proc/self/fd/{fd}");
        if let Ok(path) = std::fs::read_link(&link) {
            if path.to_string_lossy().starts_with("/dev/") {
                return Some(path.into_os_string());
            }
        }
    }
    // Last resort: /dev/tty (works if caller has a ctty).
    if std::path::Path::new("/dev/tty").exists() {
        return Some("/dev/tty".into());
    }
    None
}

/// Run an rbw command with the given args, piping `stdin_content` to its stdin.
/// rbw's `edit::edit()` detects a non-TTY stdin and reads from it directly.
fn pipe_to_rbw(args: &[&str], stdin_content: &str) -> Result<(), String> {
    ensure_unlocked()?;

    let mut cmd = Command::new("rbw");
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    set_rbw_tty(&mut cmd);

    let mut child = cmd.spawn().map_err(|e| format!("failed to spawn rbw: {e}"))?;

    child
        .stdin
        .take()
        .ok_or_else(|| "failed to open rbw stdin".to_string())?
        .write_all(stdin_content.as_bytes())
        .map_err(|e| format!("failed to write to rbw stdin: {e}"))?;

    let status = child
        .wait()
        .map_err(|e| format!("failed to wait for rbw: {e}"))?;
    if !status.success() {
        return Err(format!("rbw exited with status {status}"));
    }
    Ok(())
}

/// Convert a failed `Command` output into an error message.
fn check_status(cmd: &str, output: &std::process::Output) -> Result<(), String> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "`{}` failed ({}): {}",
            cmd,
            output.status,
            stderr.trim()
        ));
    }
    Ok(())
}

/// Reject values that could be misinterpreted as `rbw` flags or that contain
/// characters unsafe to pass as CLI arguments.
///
/// Rules:
/// - Must not be empty.
/// - Must not start with `-` (would be parsed as a flag by rbw).
/// - Must not contain a null byte (undefined behaviour in argv).
/// - Must not contain a comma (keeps namespaces compatible with envchain's
///   comma-separated exec mode).
fn validate_identifier(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.starts_with('-') {
        return Err(format!("{label} must not start with '-': {value:?}"));
    }
    if value.contains('\0') {
        return Err(format!("{label} must not contain null bytes"));
    }
    if value.contains(',') {
        return Err(format!("{label} must not contain commas: {value:?}"));
    }
    Ok(())
}

// ── notes-field KEY=VALUE store helpers ─────────────────────────────────────

/// Return `true` if `key` is a valid POSIX environment-variable name:
/// `[A-Za-z_][A-Za-z0-9_]*` with no null bytes.
fn is_valid_env_key(key: &str) -> bool {
    if key.is_empty() || key.contains('\0') {
        return false;
    }
    let mut chars = key.chars();
    let first = chars.next().unwrap();
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse note content into a map of env-var key → value.
/// - Splits on the **first** `=` only (values may contain `=`).
/// - Trims whitespace from both the key and the value.
/// - Skips blank lines and lines starting with `#`.
/// - Skips and warns about lines whose key is not a valid POSIX env-var name.
fn parse(notes: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in notes.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            if is_valid_env_key(k) {
                map.insert(k.to_string(), v.to_string());
            } else {
                eprintln!("WARNING: skipping line with invalid env-var key: {line:?}");
            }
        }
    }
    map
}

/// Serialize a map into sorted `KEY=VALUE` lines.
fn serialize(pairs: &HashMap<String, String>) -> String {
    let mut keys: Vec<&String> = pairs.keys().collect();
    keys.sort();
    keys.iter()
        .map(|k| format!("{}={}", k, pairs[*k]))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Upsert a single key in existing note content, preserving other lines.
fn update(existing: &str, key: &str, value: &str) -> String {
    let mut pairs = parse(existing);
    pairs.insert(key.to_string(), value.to_string());
    serialize(&pairs)
}

/// Remove a single key from existing note content, preserving other lines.
/// Returns `None` if the key was not present.
fn remove(existing: &str, key: &str) -> Option<String> {
    let mut pairs = parse(existing);
    pairs.remove(key)?;
    Some(serialize(&pairs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let m = parse("A=1\nB=hello=world\n");
        assert_eq!(m["A"], "1");
        assert_eq!(m["B"], "hello=world");
    }

    #[test]
    fn parse_skips_comments_and_blanks() {
        let m = parse("# comment\n\nA=1\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m["A"], "1");
    }

    #[test]
    fn parse_skips_empty_key() {
        let m = parse("=value\nA=1\n");
        assert!(!m.contains_key(""), "empty key must be rejected");
        assert_eq!(m["A"], "1");
    }

    #[test]
    fn parse_skips_null_byte_in_key() {
        let m = parse("KEY\x00INJECTED=value\nA=1\n");
        assert_eq!(m.len(), 1, "key with null byte must be rejected");
        assert_eq!(m["A"], "1");
    }

    #[test]
    fn parse_rejects_invalid_key_names() {
        let m = parse("1STARTS_WITH_DIGIT=x\nKEY WITH SPACE=y\nVALID=z\n");
        assert!(!m.contains_key("1STARTS_WITH_DIGIT"));
        assert!(!m.contains_key("KEY WITH SPACE"));
        assert_eq!(m["VALID"], "z");
    }

    #[test]
    fn parse_trims_key_and_value() {
        let m = parse("KEY  =  value  \n");
        assert!(
            !m.contains_key("KEY  "),
            "trailing spaces in key must be trimmed"
        );
        assert_eq!(m["KEY"], "value");
    }

    #[test]
    fn roundtrip() {
        let original = "A=1\nB=2\n";
        let m = parse(original);
        let s = serialize(&m);
        assert_eq!(s, "A=1\nB=2");
    }

    #[test]
    fn update_existing() {
        let s = update("A=1\nB=2", "A", "99");
        let m = parse(&s);
        assert_eq!(m["A"], "99");
        assert_eq!(m["B"], "2");
    }

    #[test]
    fn remove_key() {
        let s = remove("A=1\nB=2", "A").unwrap();
        let m = parse(&s);
        assert!(!m.contains_key("A"));
        assert_eq!(m["B"], "2");
    }

    #[test]
    fn remove_missing_returns_none() {
        assert!(remove("A=1", "MISSING").is_none());
    }
}
