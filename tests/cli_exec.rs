#![cfg(unix)]

use dotseal::encode_key;
use std::fs;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const SEALED: &str = "enc:v1:ICEiIyQlJicoKSoroV_FAgnsN3h7EDerj53e0Qpsr2lTDYsfbYmoIQ";

fn dotseal_bin() -> &'static str {
    env!("CARGO_BIN_EXE_dotseal")
}

fn write_fixture(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let key: Vec<u8> = (0..32).collect();
    let key_file = dir.path().join("masterkey.production");
    fs::write(&key_file, format!("{}\n", encode_key(&key))).unwrap();
    fs::write(
        dir.path().join(".env.production"),
        format!("API_SUPER_KEY={SEALED}\nPLAIN=value\n"),
    )
    .unwrap();
    key_file
}

#[test]
fn exec_passes_decrypted_env_values() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_fixture(&dir);

    let status = Command::new(dotseal_bin())
        .arg("-s")
        .arg("production")
        .arg("--key-file")
        .arg(&key_file)
        .arg("exec")
        .arg(dir.path())
        .arg("sh")
        .arg("-c")
        .arg("test \"$API_SUPER_KEY\" = secret-value && test \"$PLAIN\" = value")
        .status()
        .unwrap();

    assert!(status.success());
}

#[test]
fn exec_returns_child_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_fixture(&dir);

    let status = Command::new(dotseal_bin())
        .arg("-s")
        .arg("production")
        .arg("--key-file")
        .arg(&key_file)
        .arg("exec")
        .arg(dir.path())
        .arg("sh")
        .arg("-c")
        .arg("exit 37")
        .status()
        .unwrap();

    assert_eq!(status.code(), Some(37));
}

#[test]
fn exec_uses_signal_exit_convention_for_child_signals() {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_fixture(&dir);

    let status = Command::new(dotseal_bin())
        .arg("-s")
        .arg("production")
        .arg("--key-file")
        .arg(&key_file)
        .arg("exec")
        .arg(dir.path())
        .arg("sh")
        .arg("-c")
        .arg("kill -TERM $$")
        .status()
        .unwrap();

    assert_eq!(status.code(), Some(128 + libc::SIGTERM));
}

fn exec_forwards_signal(signum: libc::c_int) {
    let dir = tempfile::tempdir().unwrap();
    let key_file = write_fixture(&dir);
    let ready_file = dir.path().join("ready");
    let child_pid_file = dir.path().join("child.pid");

    let trap_name = match signum {
        libc::SIGTERM => "TERM",
        libc::SIGINT => "INT",
        libc::SIGHUP => "HUP",
        other => panic!("unsupported test signal {other}"),
    };

    let mut child = Command::new(dotseal_bin())
        .arg("-s")
        .arg("production")
        .arg("--key-file")
        .arg(&key_file)
        .arg("exec")
        .arg(dir.path())
        .arg("sh")
        .arg("-c")
        .arg(format!(
            "trap 'exit 42' {trap_name}; echo $$ > \"$1\"; touch \"$2\"; while :; do sleep 1; done"
        ))
        .arg("sh")
        .arg(&child_pid_file)
        .arg(&ready_file)
        .spawn()
        .unwrap();

    wait_for_file(&ready_file);
    unsafe {
        libc::kill(child.id() as libc::pid_t, signum);
    }

    let status = wait_with_timeout(&mut child, Duration::from_secs(5));
    if let Ok(pid) = fs::read_to_string(&child_pid_file)
        .unwrap_or_default()
        .trim()
        .parse::<libc::pid_t>()
    {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }

    assert_eq!(status.code(), Some(42), "trap for {trap_name} did not run");
}

#[test]
fn exec_forwards_sigterm_to_child() {
    exec_forwards_signal(libc::SIGTERM);
}

#[test]
fn exec_forwards_sigint_to_child() {
    exec_forwards_signal(libc::SIGINT);
}

#[test]
fn exec_forwards_sighup_to_child() {
    exec_forwards_signal(libc::SIGHUP);
}

fn wait_for_file(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {}", path.display());
}

fn wait_with_timeout(child: &mut std::process::Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        thread::sleep(Duration::from_millis(20));
    }

    let _ = child.kill();
    let status = child.wait().unwrap();
    panic!("timed out waiting for dotseal exec, final status: {status:?}");
}
