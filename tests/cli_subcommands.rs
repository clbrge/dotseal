#![cfg(unix)]

use dotseal::encode_key;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn dotseal_bin() -> &'static str {
    env!("CARGO_BIN_EXE_dotseal")
}

fn write_key(dir: &tempfile::TempDir) -> PathBuf {
    let key: Vec<u8> = (0..32).collect();
    let key_file = dir.path().join("masterkey.production");
    fs::write(&key_file, format!("{}\n", encode_key(&key))).unwrap();
    key_file
}

// --- set ---

#[test]
fn set_seals_value_from_value_flag_and_writes_file() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_key(&dir);

    let output = Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("set")
        .arg(dir.path())
        .args(["API_KEY", "--value", "secret-value"])
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("API_KEY=enc:v1:"));

    let env = fs::read_to_string(dir.path().join(".env.production")).unwrap();
    assert!(env.contains("API_KEY=enc:v1:"));
}

#[test]
fn set_seals_value_from_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_key(&dir);

    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "printf 'piped-secret' | '{bin}' -s production --key-file '{kf}' set '{path}' API_KEY --stdin",
            bin = dotseal_bin(),
            kf = key_file.display(),
            path = dir.path().display(),
        ))
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn set_seals_value_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_key(&dir);
    let value_file = dir.path().join("value.txt");
    fs::write(&value_file, "from-file-secret\n").unwrap();

    let output = Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("set")
        .arg(dir.path())
        .arg("API_KEY")
        .arg("--file")
        .arg(&value_file)
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let env = fs::read_to_string(dir.path().join(".env.production")).unwrap();
    assert!(env.contains("API_KEY=enc:v1:"));
}

#[test]
fn set_rejects_invalid_env_name() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_key(&dir);

    let output = Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("set")
        .arg(dir.path())
        .args(["bad-name!", "--value", "x"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid env name"));
}

// --- get ---

#[test]
fn get_decrypts_named_value() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_key(&dir);

    Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("set")
        .arg(dir.path())
        .args(["API_KEY", "--value", "round-trip"])
        .status()
        .unwrap();

    let output = Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("get")
        .arg(dir.path())
        .arg("API_KEY")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim_end(), "round-trip");
}

#[test]
fn get_reports_missing_name() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_key(&dir);
    fs::write(dir.path().join(".env.production"), "OTHER=plain\n").unwrap();

    let output = Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("get")
        .arg(dir.path())
        .arg("ABSENT_KEY")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ABSENT_KEY not found"));
}

// --- init-key ---

#[test]
fn init_key_creates_key_file_with_private_mode() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("masterkey.production");

    let output = Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("init-key")
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let mode = fs::metadata(&key_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let printed_path = String::from_utf8(output.stdout).unwrap();
    assert!(printed_path.trim_end().ends_with("masterkey.production"));
}

#[test]
fn init_key_is_idempotent_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("masterkey.production");

    Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("init-key")
        .status()
        .unwrap();
    let first = fs::read_to_string(&key_file).unwrap();

    Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("init-key")
        .status()
        .unwrap();
    let second = fs::read_to_string(&key_file).unwrap();

    assert_eq!(first, second);
}

#[test]
fn init_key_force_overwrites_existing_key() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("masterkey.production");

    Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("init-key")
        .status()
        .unwrap();
    let first = fs::read_to_string(&key_file).unwrap();

    Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("init-key")
        .arg("--force")
        .status()
        .unwrap();
    let second = fs::read_to_string(&key_file).unwrap();

    assert_ne!(first, second);
}

// --- doctor ---

#[test]
fn doctor_reports_ok_for_clean_env_file() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_key(&dir);

    Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("set")
        .arg(dir.path())
        .args(["API_KEY", "--value", "doctor-secret"])
        .status()
        .unwrap();

    let output = Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("doctor")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("ok: checked 1 encrypted value"));
}

#[test]
fn doctor_reports_failures_in_all_mode() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_key(&dir);
    fs::write(
        dir.path().join(".env.production"),
        "BROKEN_SHORT=enc:v1:ICEi\nALSO_BROKEN=enc:v1:ZZZZ\n",
    )
    .unwrap();

    let output = Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("doctor")
        .arg(dir.path())
        .arg("--all")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("BROKEN_SHORT"));
    assert!(stderr.contains("ALSO_BROKEN"));
    assert!(stderr.contains("checked 2 encrypted value(s), 2 failed"));
}

#[test]
fn doctor_warns_on_duplicate_names() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_key(&dir);
    fs::write(
        dir.path().join(".env.production"),
        "API_KEY=first\nOTHER=plain\nAPI_KEY=second\n",
    )
    .unwrap();

    let output = Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("doctor")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("warning: duplicate name API_KEY"), "stderr: {stderr}");
}

// --- print-env ---

#[test]
fn print_env_emits_shell_quoted_decrypted_lines() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_key(&dir);

    Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("set")
        .arg(dir.path())
        .args(["API_KEY", "--value", "tricky 'value'"])
        .status()
        .unwrap();
    Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("set")
        .arg(dir.path())
        .args(["PLAIN", "--value", "ordinary"])
        .status()
        .unwrap();

    let output = Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("print-env")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    // shell-quoted: single quotes around value, internal `'` escaped as `'\''`
    assert!(stdout.contains("API_KEY='tricky '\\''value'\\'''"));
    assert!(stdout.contains("PLAIN='ordinary'"));
}

#[test]
fn print_env_emits_nothing_when_one_value_fails_to_decrypt() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_key(&dir);

    // OK_VALUE is a valid sealed value; BROKEN is corrupted.
    Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("set")
        .arg(dir.path())
        .args(["OK_VALUE", "--value", "ok-plaintext"])
        .status()
        .unwrap();
    let env_path = dir.path().join(".env.production");
    let mut env = fs::read_to_string(&env_path).unwrap();
    env.push_str("BROKEN=enc:v1:ICEi\n");
    fs::write(&env_path, env).unwrap();

    let output = Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("print-env")
        .arg(dir.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    // No partial plaintext leaked to stdout — buffer-then-emit invariant.
    assert!(output.stdout.is_empty(), "stdout was: {:?}", String::from_utf8_lossy(&output.stdout));
}

// --- key-cmd ---

#[test]
fn key_cmd_supplies_key_via_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let key: Vec<u8> = (0..32).collect();
    let key_b64 = encode_key(&key);

    // Seal with a normal key file first, then read using --key-cmd.
    let key_file = dir.path().join("masterkey.production");
    fs::write(&key_file, format!("{key_b64}\n")).unwrap();

    Command::new(dotseal_bin())
        .args(["-s", "production", "--key-file"])
        .arg(&key_file)
        .arg("set")
        .arg(dir.path())
        .args(["API_KEY", "--value", "via-cmd"])
        .status()
        .unwrap();

    let output = Command::new(dotseal_bin())
        .args(["-s", "production", "--key-cmd"])
        .arg(format!("printf '{key_b64}'"))
        .arg("get")
        .arg(dir.path())
        .arg("API_KEY")
        .output()
        .unwrap();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim_end(), "via-cmd");
}

#[test]
fn key_cmd_propagates_command_failure() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".env.production"), "API_KEY=enc:v1:abc\n").unwrap();

    let output = Command::new(dotseal_bin())
        .args(["-s", "production", "--key-cmd", "exit 7"])
        .arg("get")
        .arg(dir.path())
        .arg("API_KEY")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("key command exited"));
}

// --- key-path ---

#[test]
fn key_path_prints_resolved_default_path() {
    let dir = tempfile::tempdir().unwrap();

    let output = Command::new(dotseal_bin())
        .env("XDG_CONFIG_HOME", dir.path())
        .args(["-s", "production", "key-path"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let printed = String::from_utf8(output.stdout).unwrap();
    assert!(printed.trim_end().ends_with("dotseal/masterkey.production"));
}
