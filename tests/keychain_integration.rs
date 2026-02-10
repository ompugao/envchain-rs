//! Integration tests for keychain backend
//!
//! These tests verify the keychain backend works correctly when invoked
//! through the CLI, ensuring end-to-end functionality.
//!
//! # Platform Requirements
//!
//! **These tests ONLY run on macOS** with the keychain-backend feature.
//! On Linux/WSL/other platforms, these tests are completely skipped (0 tests run).
//! In CI, they run on macOS runners (macos-latest, macos-14) to verify keychain support.

#![cfg(all(target_os = "macos", feature = "keychain-backend"))]

use std::process::Command;

const TEST_NAMESPACE: &str = "envchain-integration-test";

fn envchain_binary() -> String {
    std::env::var("CARGO_BIN_EXE_envchain")
        .unwrap_or_else(|_| "target/release/envchain".to_string())
}

fn cleanup() {
    // Clean up any leftover test data
    let _ = Command::new(envchain_binary())
        .args(&[
            "--backend",
            "keychain",
            "--unset",
            TEST_NAMESPACE,
            "TEST_KEY1",
        ])
        .output();
    let _ = Command::new(envchain_binary())
        .args(&[
            "--backend",
            "keychain",
            "--unset",
            TEST_NAMESPACE,
            "TEST_KEY2",
        ])
        .output();
}

#[test]
fn test_cli_set_and_list() {
    cleanup();

    // Set a secret via CLI (using echo to provide input)
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo 'test-value-1' | {} --backend keychain --set {} TEST_KEY1",
            envchain_binary(),
            TEST_NAMESPACE
        ))
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "Set command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List secrets in the namespace
    let output = Command::new(envchain_binary())
        .args(&["--backend", "keychain", "--list", TEST_NAMESPACE])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("TEST_KEY1"),
        "Expected TEST_KEY1 in output: {}",
        stdout
    );

    cleanup();
}

#[test]
fn test_cli_set_and_execute() {
    cleanup();

    // Set a secret
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo 'secret-value' | {} --backend keychain --set {} TEST_KEY2",
            envchain_binary(),
            TEST_NAMESPACE
        ))
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());

    // Execute a command with the secret
    let output = Command::new(envchain_binary())
        .args(&[
            "--backend",
            "keychain",
            TEST_NAMESPACE,
            "sh",
            "-c",
            "echo $TEST_KEY2",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("secret-value"),
        "Expected secret-value in output: {}",
        stdout
    );

    cleanup();
}

#[test]
fn test_cli_list_with_show_value() {
    cleanup();

    // Set a secret
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo 'visible-value' | {} --backend keychain --set {} TEST_KEY1",
            envchain_binary(),
            TEST_NAMESPACE
        ))
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());

    // List with --show-value
    let output = Command::new(envchain_binary())
        .args(&[
            "--backend",
            "keychain",
            "--list",
            "--show-value",
            TEST_NAMESPACE,
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("TEST_KEY1=visible-value"),
        "Expected TEST_KEY1=visible-value in output: {}",
        stdout
    );

    cleanup();
}

#[test]
fn test_cli_unset() {
    cleanup();

    // Set a secret
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo 'temp-value' | {} --backend keychain --set {} TEST_KEY1",
            envchain_binary(),
            TEST_NAMESPACE
        ))
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());

    // Verify it exists
    let output = Command::new(envchain_binary())
        .args(&["--backend", "keychain", "--list", TEST_NAMESPACE])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("TEST_KEY1"));

    // Unset it
    let output = Command::new(envchain_binary())
        .args(&[
            "--backend",
            "keychain",
            "--unset",
            TEST_NAMESPACE,
            "TEST_KEY1",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "Unset command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify it's gone
    let output = Command::new(envchain_binary())
        .args(&["--backend", "keychain", "--list", TEST_NAMESPACE])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("TEST_KEY1="));

    cleanup();
}

#[test]
fn test_cli_multiple_namespaces() {
    cleanup();
    let namespace2 = "envchain-integration-test2";

    // Set secrets in two namespaces
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo 'ns1-value' | {} --backend keychain --set {} NS1_KEY",
            envchain_binary(),
            TEST_NAMESPACE
        ))
        .output();

    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo 'ns2-value' | {} --backend keychain --set {} NS2_KEY",
            envchain_binary(),
            namespace2
        ))
        .output();

    // Execute with both namespaces
    let output = Command::new(envchain_binary())
        .args(&[
            "--backend",
            "keychain",
            &format!("{},{}", TEST_NAMESPACE, namespace2),
            "sh",
            "-c",
            "echo $NS1_KEY:$NS2_KEY",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ns1-value:ns2-value"),
        "Expected both values in output: {}",
        stdout
    );

    // Cleanup both namespaces
    let _ = Command::new(envchain_binary())
        .args(&["--backend", "keychain", "--unset", namespace2, "NS2_KEY"])
        .output();
    cleanup();
}

#[test]
fn test_cli_list_namespaces() {
    cleanup();

    // Set a secret to create the namespace
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo 'value' | {} --backend keychain --set {} KEY",
            envchain_binary(),
            TEST_NAMESPACE
        ))
        .output();

    // List all namespaces
    let output = Command::new(envchain_binary())
        .args(&["--backend", "keychain", "--list"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(TEST_NAMESPACE),
        "Expected {} in namespaces: {}",
        TEST_NAMESPACE,
        stdout
    );

    cleanup();
}
