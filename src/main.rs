const MAX_ENV_BYTES: u64 = 1 << 20;
const MAX_KEY_FILE_BYTES: u64 = 1 << 12;
const MAX_VALUE_FILE_BYTES: u64 = 1 << 20;

use clap::{Args, Parser, Subcommand};
use dotseal::{
    decrypt_value, encode_key, env_line_name, generate_key, is_encrypted_value, parse_env,
    parse_key, seal_value, validate_name, validate_scope, DEFAULT_SCOPE,
};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::mem::MaybeUninit;
#[cfg(unix)]
use std::ptr;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

#[derive(Parser, Debug)]
#[command(name = "dotseal", version, about = "Seal individual dotenv values")]
struct Cli {
    #[arg(short, long, global = true)]
    scope: Option<String>,

    #[arg(long, global = true)]
    key_file: Option<PathBuf>,

    #[arg(long, global = true)]
    key_cmd: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt or replace one dotenv value.
    Set(SetArgs),
    /// Decrypt and print one dotenv value.
    Get(NameAtPath),
    /// Print the key path that would be used for a scope.
    KeyPath,
    /// Create a scope key if it does not exist.
    InitKey {
        #[arg(long)]
        force: bool,
    },
    /// Check encrypted values in an env file can be parsed and decrypted.
    Doctor(DoctorArgs),
    /// Print decrypted dotenv lines for shell consumption.
    PrintEnv {
        path: PathBuf,
    },
    /// Run a command with decrypted env values.
    Exec(ExecArgs),
}

#[derive(Args, Debug)]
struct SetArgs {
    path: PathBuf,
    name: String,

    #[arg(
        long,
        conflicts_with_all = ["stdin", "value_file"],
        help = "Read plaintext from argv. WARNING: visible to other users via ps; prefer --stdin or --file"
    )]
    value: Option<String>,

    #[arg(
        long,
        conflicts_with_all = ["value", "value_file"],
        help = "Read plaintext from stdin"
    )]
    stdin: bool,

    #[arg(
        long = "file",
        conflicts_with_all = ["value", "stdin"],
        help = "Read plaintext from a file"
    )]
    value_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct NameAtPath {
    path: PathBuf,
    name: String,
}

#[derive(Args, Debug)]
struct DoctorArgs {
    path: PathBuf,

    /// Report every encrypted value failure instead of stopping at the first one.
    #[arg(long)]
    all: bool,
}

#[derive(Args, Debug)]
struct ExecArgs {
    path: PathBuf,

    #[arg(required = true, trailing_var_arg = true)]
    command: Vec<String>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("dotseal: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let scope = cli.scope.as_deref().unwrap_or(DEFAULT_SCOPE);
    validate_scope(scope).map_err(|err| err.to_string())?;

    match cli.command {
        Commands::Set(args) => {
            validate_name(&args.name).map_err(|err| err.to_string())?;
            let plaintext = read_plaintext(&args)?;
            let key = load_or_create_key(scope, cli.key_file.as_deref(), cli.key_cmd.as_deref())?;
            let sealed =
                seal_value(&plaintext, &key, scope, &args.name).map_err(|err| err.to_string())?;
            let env_file = resolve_env_file(&args.path, scope);
            upsert_env_value(&env_file, &args.name, &sealed)?;
            println!("{}={}", args.name, sealed);
            Ok(())
        }
        Commands::Get(args) => {
            validate_name(&args.name).map_err(|err| err.to_string())?;
            let key = load_key(scope, cli.key_file.as_deref(), cli.key_cmd.as_deref())
                .map_err(|err| err.to_string())?;
            let env_file = resolve_env_file(&args.path, scope);
            let value = read_env_value(&env_file, &args.name)?
                .ok_or_else(|| format!("{} not found in {}", args.name, env_file.display()))?;
            let plaintext =
                decrypt_value(&value, &key, scope, &args.name).map_err(|err| err.to_string())?;
            println!("{}", &*plaintext);
            Ok(())
        }
        Commands::KeyPath => {
            let path = cli
                .key_file
                .unwrap_or_else(|| default_key_path(scope));
            println!("{}", path.display());
            Ok(())
        }
        Commands::InitKey { force } => {
            if cli.key_cmd.is_some() {
                return Err("init-key cannot create a key from --key-cmd".to_string());
            }
            let secure_parent = cli.key_file.is_none();
            let path = cli
                .key_file
                .unwrap_or_else(|| default_key_path(scope));
            if path.exists() && !force {
                let content = read_capped(&path, MAX_KEY_FILE_BYTES)
                    .map_err(|err| format!("read key {}: {err}", path.display()))?;
                parse_key(content.trim())
                    .map_err(|err| format!("existing key {} is invalid: {err}", path.display()))?;
                println!("{}", path.display());
                return Ok(());
            }
            let key = generate_key();
            if force {
                write_key_file(&path, &key, secure_parent)?;
            } else {
                match create_key_file(&path, &key, secure_parent) {
                    Ok(()) => {}
                    Err(err) if err.kind == KeyWriteErrorKind::AlreadyExists => {
                        load_key_after_create_race(scope, &path)?;
                    }
                    Err(err) => return Err(err.to_string()),
                }
            }
            println!("{}", path.display());
            Ok(())
        }
        Commands::Doctor(args) => {
            let key = load_key(scope, cli.key_file.as_deref(), cli.key_cmd.as_deref())
                .map_err(|err| err.to_string())?;
            let env_file = resolve_env_file(&args.path, scope);
            let content = read_capped(&env_file, MAX_ENV_BYTES)
                .map_err(|err| format!("read {}: {err}", env_file.display()))?;
            for name in find_duplicate_names(&content) {
                eprintln!("warning: duplicate name {name} (last definition wins)");
            }
            match check_encrypted_values(&content, &key, scope, args.all) {
                Ok(checked) => {
                    println!("ok: checked {checked} encrypted value(s)");
                    Ok(())
                }
                Err(report) => {
                    for failure in &report.failures {
                        eprintln!("{}: {}", failure.name, failure.message);
                    }
                    Err(format!(
                        "checked {} encrypted value(s), {} failed",
                        report.checked,
                        report.failures.len()
                    ))
                }
            }
        }
        Commands::PrintEnv { path } => {
            let key = load_key(scope, cli.key_file.as_deref(), cli.key_cmd.as_deref())
                .map_err(|err| err.to_string())?;
            let env_file = resolve_env_file(&path, scope);
            let content = read_capped(&env_file, MAX_ENV_BYTES)
                .map_err(|err| format!("read {}: {err}", env_file.display()))?;
            let mut buffered = String::new();
            for (name, value) in parse_env(&content) {
                let decrypted =
                    decrypt_value(&value, &key, scope, &name).map_err(|err| err.to_string())?;
                buffered.push_str(&format!("{}={}\n", name, shell_quote(&decrypted)));
            }
            io::stdout()
                .write_all(buffered.as_bytes())
                .map_err(|err| format!("write stdout: {err}"))?;
            Ok(())
        }
        Commands::Exec(args) => {
            let key = load_key(scope, cli.key_file.as_deref(), cli.key_cmd.as_deref())
                .map_err(|err| err.to_string())?;
            let env_file = resolve_env_file(&args.path, scope);
            let content = read_capped(&env_file, MAX_ENV_BYTES)
                .map_err(|err| format!("read {}: {err}", env_file.display()))?;
            let mut command = Command::new(&args.command[0]);
            if args.command.len() > 1 {
                command.args(&args.command[1..]);
            }
            for (name, value) in parse_env(&content) {
                let decrypted =
                    decrypt_value(&value, &key, scope, &name).map_err(|err| err.to_string())?;
                command.env(&name, decrypted);
            }
            std::process::exit(run_exec_command(command, &args.command[0])?);
        }
    }
}

fn read_plaintext(args: &SetArgs) -> Result<String, String> {
    if let Some(value) = &args.value {
        return Ok(value.clone());
    }

    if args.stdin {
        let mut value = String::new();
        io::stdin()
            .read_to_string(&mut value)
            .map_err(|err| format!("read stdin: {err}"))?;
        return Ok(trim_one_trailing_newline(value));
    }

    if let Some(path) = &args.value_file {
        let value = read_capped(path, MAX_VALUE_FILE_BYTES)
            .map_err(|err| format!("read {}: {err}", path.display()))?;
        return Ok(trim_one_trailing_newline(value));
    }

    prompt_secret(&args.name)
}

fn prompt_secret(name: &str) -> Result<String, String> {
    #[cfg(windows)]
    {
        let _ = name;
        return Err(
            "interactive secret prompt is unsupported on Windows until Dotseal has a no-echo terminal reader; use --value, --stdin, or --file"
                .to_string(),
        );
    }

    #[cfg(not(windows))]
    {
        eprint!("{name}: ");
        io::stderr()
            .flush()
            .map_err(|err| format!("flush prompt: {err}"))?;

        #[cfg(unix)]
        let _guard = match TerminalEchoGuard::install(libc::STDIN_FILENO) {
            Ok(guard) => Some(guard),
            Err(err) if err.raw_os_error() == Some(libc::ENOTTY) => None,
            Err(err) => return Err(format!("disable terminal echo: {err}")),
        };

        let mut value = String::new();
        let read_result = io::stdin().read_line(&mut value);

        #[cfg(unix)]
        if _guard.is_some() {
            eprintln!();
        }

        read_result.map_err(|err| format!("read secret: {err}"))?;
        Ok(trim_one_trailing_newline(value))
    }
}

#[cfg(unix)]
static PROMPT_RESTORE_ACTIVE: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
static PROMPT_RESTORE_FD: AtomicI32 = AtomicI32::new(-1);
// SAFETY invariants for `PROMPT_RESTORE_TERMIOS`:
//
// 1. Writes happen exactly once per `TerminalEchoGuard::install`, *before*
//    `PROMPT_RESTORE_ACTIVE` is set to `true` with `Ordering::SeqCst`.
// 2. Reads happen only inside `restore_terminal_on_signal` and only when
//    `PROMPT_RESTORE_ACTIVE.load(SeqCst)` is `true`.
// 3. `TerminalEchoGuard` is owned by a single CLI invocation (the prompt
//    path is single-threaded) — concurrent installation is not supported.
// 4. The signal handler runs synchronously on the same thread that set
//    the static (delivery is to the process; raises are routed to the
//    main thread that initiated the prompt). The Acquire/Release ordering
//    on `PROMPT_RESTORE_ACTIVE` makes the prior write visible to the
//    handler.
//
// Together (1)+(2)+(4) make every observed read happen-after the write.
// (3) rules out concurrent writers. The combination is the standard
// "publish via atomic flag" pattern for `static mut` POD initialization.
#[cfg(unix)]
static mut PROMPT_RESTORE_TERMIOS: MaybeUninit<libc::termios> = MaybeUninit::uninit();
#[cfg(unix)]
static EXEC_CHILD_PID: AtomicI32 = AtomicI32::new(-1);

#[cfg(unix)]
struct TerminalEchoGuard {
    fd: libc::c_int,
    original: libc::termios,
    old_int: Option<libc::sigaction>,
    old_term: Option<libc::sigaction>,
    old_hup: Option<libc::sigaction>,
    restored: bool,
}

#[cfg(unix)]
impl TerminalEchoGuard {
    fn install(fd: libc::c_int) -> io::Result<Self> {
        // SAFETY: `libc::termios` is POD; zero-init is the documented
        // way to start with all fields unset before `tcgetattr` populates them.
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        // SAFETY: `fd` is the caller-supplied STDIN_FILENO; `&mut original`
        // points to a stack-local `termios` valid for the duration of the call.
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: invariant (1) — only writer; happens before the
        // SeqCst publish of `PROMPT_RESTORE_ACTIVE = true` below, so any
        // signal handler that sees `ACTIVE` also sees this write.
        unsafe {
            ptr::addr_of_mut!(PROMPT_RESTORE_TERMIOS).write(MaybeUninit::new(original));
        }
        PROMPT_RESTORE_FD.store(fd, Ordering::SeqCst);
        PROMPT_RESTORE_ACTIVE.store(true, Ordering::SeqCst);

        let mut guard = Self {
            fd,
            original,
            old_int: None,
            old_term: None,
            old_hup: None,
            restored: false,
        };

        guard.old_int = Some(install_restore_signal(libc::SIGINT)?);
        guard.old_term = Some(install_restore_signal(libc::SIGTERM)?);
        guard.old_hup = Some(install_restore_signal(libc::SIGHUP)?);

        let mut no_echo = original;
        no_echo.c_lflag &= !libc::ECHO;
        // SAFETY: `fd` is the same fd we just queried with `tcgetattr`;
        // `&no_echo` is a stack-local `termios` valid for the call.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &no_echo) } != 0 {
            let err = io::Error::last_os_error();
            guard.restore();
            return Err(err);
        }

        Ok(guard)
    }

    fn restore(&mut self) {
        if self.restored {
            return;
        }

        // SAFETY: `self.fd` and `self.original` were captured by `install`
        // and remain valid for the lifetime of `self`.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
        PROMPT_RESTORE_ACTIVE.store(false, Ordering::SeqCst);
        PROMPT_RESTORE_FD.store(-1, Ordering::SeqCst);

        // SAFETY: each `old` is a `sigaction` previously returned by an
        // `install_handler` call; restoring it is the documented inverse.
        unsafe {
            if let Some(old) = self.old_int.take() {
                libc::sigaction(libc::SIGINT, &old, ptr::null_mut());
            }
            if let Some(old) = self.old_term.take() {
                libc::sigaction(libc::SIGTERM, &old, ptr::null_mut());
            }
            if let Some(old) = self.old_hup.take() {
                libc::sigaction(libc::SIGHUP, &old, ptr::null_mut());
            }
        }

        self.restored = true;
    }
}

#[cfg(unix)]
impl Drop for TerminalEchoGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

#[cfg(unix)]
struct ExecSignalForwarder {
    old_int: Option<libc::sigaction>,
    old_term: Option<libc::sigaction>,
    old_hup: Option<libc::sigaction>,
}

#[cfg(unix)]
impl ExecSignalForwarder {
    fn install(pid: libc::pid_t) -> io::Result<Self> {
        EXEC_CHILD_PID.store(pid, Ordering::SeqCst);
        Ok(Self {
            old_int: Some(install_exec_signal(libc::SIGINT)?),
            old_term: Some(install_exec_signal(libc::SIGTERM)?),
            old_hup: Some(install_exec_signal(libc::SIGHUP)?),
        })
    }
}

#[cfg(unix)]
impl Drop for ExecSignalForwarder {
    fn drop(&mut self) {
        EXEC_CHILD_PID.store(-1, Ordering::SeqCst);
        // SAFETY: each `old` is a `sigaction` previously returned by an
        // `install_handler` call during `install`; restoring it is the
        // documented inverse and is required before the forwarder drops.
        unsafe {
            if let Some(old) = self.old_int.take() {
                libc::sigaction(libc::SIGINT, &old, ptr::null_mut());
            }
            if let Some(old) = self.old_term.take() {
                libc::sigaction(libc::SIGTERM, &old, ptr::null_mut());
            }
            if let Some(old) = self.old_hup.take() {
                libc::sigaction(libc::SIGHUP, &old, ptr::null_mut());
            }
        }
    }
}

#[cfg(unix)]
fn install_restore_signal(signum: libc::c_int) -> io::Result<libc::sigaction> {
    install_handler(signum, restore_terminal_on_signal)
}

#[cfg(unix)]
fn install_exec_signal(signum: libc::c_int) -> io::Result<libc::sigaction> {
    install_handler(signum, forward_signal_to_exec_child)
}

#[cfg(unix)]
fn install_handler(
    signum: libc::c_int,
    handler: extern "C" fn(libc::c_int),
) -> io::Result<libc::sigaction> {
    // SAFETY: `libc::sigaction` is POD; zero-init is the documented way to
    // start with all fields unset before populating mask/flags/handler.
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    // SAFETY: `sigemptyset` writes through the &mut reference; `&mut action.sa_mask`
    // is non-null and properly aligned because `action` lives on the stack.
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
    }
    action.sa_flags = libc::SA_RESTART;
    action.sa_sigaction = handler as libc::sighandler_t;

    let mut old = unsafe { std::mem::zeroed::<libc::sigaction>() };
    // SAFETY: `signum` is a constant SIG* value; both pointers reference
    // local `sigaction` values valid for the duration of the call.
    if unsafe { libc::sigaction(signum, &action, &mut old) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(old)
    }
}

#[cfg(unix)]
extern "C" fn restore_terminal_on_signal(signum: libc::c_int) {
    if PROMPT_RESTORE_ACTIVE.load(Ordering::SeqCst) {
        let fd = PROMPT_RESTORE_FD.load(Ordering::SeqCst);
        if fd >= 0 {
            // SAFETY: invariant (2)+(4) — `PROMPT_RESTORE_ACTIVE` was true,
            // so the install-time write to `PROMPT_RESTORE_TERMIOS` has
            // happened-before this read. `tcsetattr` is async-signal-safe.
            unsafe {
                let original = ptr::addr_of!(PROMPT_RESTORE_TERMIOS).cast::<libc::termios>();
                libc::tcsetattr(fd, libc::TCSANOW, original);
            }
        }
    }

    // SAFETY: `signal` and `raise` are both async-signal-safe per POSIX.
    // After restoring the default disposition we re-raise so the parent
    // shell observes the signal rather than the dotseal process swallowing it.
    unsafe {
        libc::signal(signum, libc::SIG_DFL);
        libc::raise(signum);
    }
}

#[cfg(unix)]
extern "C" fn forward_signal_to_exec_child(signum: libc::c_int) {
    let pid = EXEC_CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: `kill` is async-signal-safe per POSIX; `pid` was set by
        // `ExecSignalForwarder::install` after a successful `spawn`, so the
        // kernel still has the corresponding process slot allocated.
        unsafe {
            libc::kill(pid, signum);
        }
    }
}

fn trim_one_trailing_newline(mut value: String) -> String {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    value
}

fn load_or_create_key(
    scope: &str,
    key_file: Option<&Path>,
    key_cmd: Option<&str>,
) -> Result<Vec<u8>, String> {
    match load_key(scope, key_file, key_cmd) {
        Ok(key) => Ok(key),
        Err(err) if key_file.is_none() && key_cmd.is_none() && err.kind == KeyLoadErrorKind::NotFound => {
            let path = default_key_path(scope);
            let key = generate_key();
            match create_key_file(&path, &key, true) {
                Ok(()) => {
                    eprintln!("created key {}", path.display());
                    Ok(key)
                }
                Err(err) if err.kind == KeyWriteErrorKind::AlreadyExists => {
                    load_key_after_create_race(scope, &path)
                }
                Err(err) => Err(err.to_string()),
            }
        }
        Err(err) => Err(err.to_string()),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum KeyLoadErrorKind {
    NotFound,
    Other,
}

#[derive(Debug)]
struct KeyLoadError {
    kind: KeyLoadErrorKind,
    message: String,
}

impl std::fmt::Display for KeyLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn load_key(scope: &str, key_file: Option<&Path>, key_cmd: Option<&str>) -> Result<Vec<u8>, KeyLoadError> {
    if let Some(cmd) = key_cmd {
        let output = run_key_command(cmd).map_err(KeyLoadError::other)?;
        return parse_key(output.trim()).map_err(|err| KeyLoadError::other(err.to_string()));
    }

    let path = key_file
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_key_path(scope));
    let content = read_capped(&path, MAX_KEY_FILE_BYTES).map_err(|err| {
        let message = format!("read key {}: {err}", path.display());
        if err.kind() == io::ErrorKind::NotFound {
            KeyLoadError {
                kind: KeyLoadErrorKind::NotFound,
                message,
            }
        } else {
            KeyLoadError::other(message)
        }
    })?;
    parse_key(content.trim()).map_err(|err| KeyLoadError::other(err.to_string()))
}

impl KeyLoadError {
    fn other(message: String) -> Self {
        Self {
            kind: KeyLoadErrorKind::Other,
            message,
        }
    }
}

fn load_key_after_create_race(scope: &str, path: &Path) -> Result<Vec<u8>, String> {
    let mut last_error = None;
    for _ in 0..25 {
        match load_key(scope, Some(path), None) {
            Ok(key) => return Ok(key),
            Err(err) => {
                last_error = Some(err);
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    Err(last_error
        .map(|err| err.to_string())
        .unwrap_or_else(|| format!("read key {}: timed out", path.display())))
}

fn run_key_command(cmd: &str) -> Result<String, String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|err| format!("run key command: {err}"))?;
    if !output.status.success() {
        return Err(format!("key command exited with {}", output.status));
    }
    String::from_utf8(output.stdout).map_err(|err| format!("key command output is not utf8: {err}"))
}

#[derive(Debug, PartialEq, Eq)]
enum KeyWriteErrorKind {
    AlreadyExists,
    Other,
}

#[derive(Debug)]
struct KeyWriteError {
    kind: KeyWriteErrorKind,
    message: String,
}

impl std::fmt::Display for KeyWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl KeyWriteError {
    fn other(message: String) -> Self {
        Self {
            kind: KeyWriteErrorKind::Other,
            message,
        }
    }

    fn from_io(path: &Path, action: &str, err: io::Error) -> Self {
        let message = format!("{action} key {}: {err}", path.display());
        if err.kind() == io::ErrorKind::AlreadyExists {
            Self {
                kind: KeyWriteErrorKind::AlreadyExists,
                message,
            }
        } else {
            Self::other(message)
        }
    }
}

fn create_key_file(path: &Path, key: &[u8], secure_parent: bool) -> Result<(), KeyWriteError> {
    #[cfg(windows)]
    {
        let _ = key;
        let _ = secure_parent;
        return Err(windows_key_write_error(path));
    }

    #[cfg(not(windows))]
    {
        prepare_key_parent(path, secure_parent)?;
        let temp_path = temp_write_path(path);

        let result = (|| -> Result<(), KeyWriteError> {
            write_key_contents(&temp_path, key, true)?;
            fs::hard_link(&temp_path, path)
                .map_err(|err| KeyWriteError::from_io(path, "write", err))?;
            sync_parent_dir(path);
            Ok(())
        })();

        let _ = fs::remove_file(&temp_path);
        result
    }
}

fn write_key_file(path: &Path, key: &[u8], secure_parent: bool) -> Result<(), String> {
    write_key_file_inner(path, key, secure_parent).map_err(|err| err.to_string())
}

fn write_key_file_inner(path: &Path, key: &[u8], secure_parent: bool) -> Result<(), KeyWriteError> {
    #[cfg(windows)]
    {
        let _ = key;
        let _ = secure_parent;
        return Err(windows_key_write_error(path));
    }

    #[cfg(not(windows))]
    {
        prepare_key_parent(path, secure_parent)?;
        write_key_contents(path, key, false)?;
        sync_parent_dir(path);
        Ok(())
    }
}

fn prepare_key_parent(path: &Path, secure_parent: bool) -> Result<(), KeyWriteError> {
    if let Some(parent) = path.parent() {
        if secure_parent {
            create_private_dir(parent)
                .map_err(|err| KeyWriteError::other(format!("create {}: {err}", parent.display())))?;
        } else {
            fs::create_dir_all(parent)
                .map_err(|err| KeyWriteError::other(format!("create {}: {err}", parent.display())))?;
        }
    }
    Ok(())
}

fn write_key_contents(path: &Path, key: &[u8], exclusive: bool) -> Result<(), KeyWriteError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.write(true).mode(0o600);
        if exclusive {
            options.create_new(true);
        } else {
            options.create(true).truncate(true);
        }
        let mut file = options
            .open(path)
            .map_err(|err| KeyWriteError::from_io(path, "write", err))?;
        file.write_all(format!("{}\n", encode_key(key)).as_bytes())
            .map_err(|err| KeyWriteError::from_io(path, "write", err))?;
        file.sync_all()
            .map_err(|err| KeyWriteError::from_io(path, "sync", err))?;
    }

    #[cfg(not(unix))]
    {
        let mut options = fs::OpenOptions::new();
        options.write(true);
        if exclusive {
            options.create_new(true);
        } else {
            options.create(true).truncate(true);
        }
        let mut file = options
            .open(path)
            .map_err(|err| KeyWriteError::from_io(path, "write", err))?;
        file.write_all(format!("{}\n", encode_key(key)).as_bytes())
            .map_err(|err| KeyWriteError::from_io(path, "write", err))?;
        file.sync_all()
            .map_err(|err| KeyWriteError::from_io(path, "sync", err))?;
    }

    Ok(())
}

fn sync_parent_dir(path: &Path) {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
}

#[cfg(windows)]
fn windows_key_write_error(path: &Path) -> KeyWriteError {
    KeyWriteError::other(format!(
        "write key {}: Windows key-file creation is not supported until Dotseal can set current-user-only ACLs; use --key-cmd or an externally protected --key-file",
        path.display()
    ))
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    builder.mode(0o700);
    builder.create(path)?;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

fn default_key_path(scope: &str) -> PathBuf {
    config_home()
        .join("dotseal")
        .join(format!("masterkey.{scope}"))
}

fn config_home() -> PathBuf {
    if let Ok(dir) = env::var("XDG_CONFIG_HOME") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home).join(".config");
    }
    PathBuf::from(".config")
}

fn resolve_env_file(path: &Path, scope: &str) -> PathBuf {
    let treat_as_dir = if path.is_dir() {
        true
    } else if path.exists() {
        false
    } else {
        // Non-existing path: a basename like `.env` or `.env.production` is
        // a deliberate env-file target; anything else is a project directory
        // we'll create the env file inside of.
        !looks_like_env_file(path)
    };
    if treat_as_dir {
        if scope == DEFAULT_SCOPE {
            path.join(".env")
        } else {
            path.join(format!(".env.{scope}"))
        }
    } else {
        path.to_path_buf()
    }
}

fn looks_like_env_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == ".env" || name.starts_with(".env."))
        .unwrap_or(false)
}

fn upsert_env_value(env_file: &Path, name: &str, value: &str) -> Result<(), String> {
    if let Some(parent) = env_file.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }

    let lock_path = env_lock_path(env_file);
    let _lock = EnvFileLock::acquire(&lock_path)
        .map_err(|err| format!("lock {}: {err}", lock_path.display()))?;

    let content = match read_capped(env_file, MAX_ENV_BYTES) {
        Ok(content) => content,
        Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(format!("read {}: {err}", env_file.display())),
    };

    let mut found = false;
    let mut out = Vec::new();
    for line in content.lines() {
        if env_line_name(line).as_deref() == Some(name) {
            out.push(upserted_env_line(line, name, value));
            found = true;
        } else {
            out.push(line.to_string());
        }
    }
    if !found {
        out.push(format!("{name}={value}"));
    }

    let mut next = out.join("\n");
    next.push('\n');
    atomic_write(env_file, next.as_bytes())
        .map_err(|err| format!("write {}: {err}", env_file.display()))
}

fn env_lock_path(env_file: &Path) -> PathBuf {
    let mut file_name = env_file
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "env".into());
    file_name.push(".lock");
    env_file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(file_name)
}

struct EnvFileLock {
    _file: fs::File,
}

impl EnvFileLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        lock_file_exclusive(&file)?;
        Ok(Self { _file: file })
    }
}

#[cfg(any(unix, windows))]
impl Drop for EnvFileLock {
    fn drop(&mut self) {
        let _ = unlock_file(&self._file);
    }
}

#[cfg(unix)]
fn lock_file_exclusive(file: &fs::File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    loop {
        // SAFETY: `file.as_raw_fd()` returns a valid fd owned by `file`,
        // which outlives this call. `LOCK_EX` is a documented libc constant.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(unix)]
fn unlock_file(file: &fs::File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: as `lock_file_exclusive` above — `file` owns the fd for the
    // duration of the call, and `LOCK_UN` is the documented release flag.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn lock_file_exclusive(file: &fs::File) -> io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    let mut overlapped = WindowsOverlapped::default();
    // SAFETY: `file.as_raw_handle()` is a valid HANDLE owned by `file`;
    // `&mut overlapped` is a stack-local OVERLAPPED valid for the call.
    let result = unsafe {
        LockFileEx(
            file.as_raw_handle() as *mut c_void,
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn unlock_file(file: &fs::File) -> io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    let mut overlapped = WindowsOverlapped::default();
    // SAFETY: same constraints as `LockFileEx` above.
    let result = unsafe {
        UnlockFileEx(
            file.as_raw_handle() as *mut c_void,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x00000002;

#[cfg(windows)]
#[repr(C)]
struct WindowsOverlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    h_event: *mut std::ffi::c_void,
}

#[cfg(windows)]
impl Default for WindowsOverlapped {
    fn default() -> Self {
        Self {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: std::ptr::null_mut(),
        }
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LockFileEx(
        h_file: *mut std::ffi::c_void,
        dw_flags: u32,
        dw_reserved: u32,
        n_number_of_bytes_to_lock_low: u32,
        n_number_of_bytes_to_lock_high: u32,
        lp_overlapped: *mut WindowsOverlapped,
    ) -> i32;

    fn UnlockFileEx(
        h_file: *mut std::ffi::c_void,
        dw_reserved: u32,
        n_number_of_bytes_to_unlock_low: u32,
        n_number_of_bytes_to_unlock_high: u32,
        lp_overlapped: *mut WindowsOverlapped,
    ) -> i32;
}

#[cfg(not(any(unix, windows)))]
fn lock_file_exclusive(_file: &fs::File) -> io::Result<()> {
    Ok(())
}

fn upserted_env_line(line: &str, name: &str, value: &str) -> String {
    let trimmed = line.trim_start();
    let leading_len = line.len() - trimmed.len();
    let leading = &line[..leading_len];
    let (export_prefix, after_export) = match strip_export_prefix(trimmed) {
        Some(rest) => ("export ", rest),
        None => ("", trimmed),
    };
    let comment = trailing_comment_from(after_export);
    format!("{leading}{export_prefix}{name}={value}{comment}")
}

fn trailing_comment_from(line: &str) -> String {
    let Some(eq) = line.find('=') else {
        return String::new();
    };
    let after_eq = &line[eq + 1..];
    let value_start = after_eq.trim_start_matches([' ', '\t']);

    let after_value = if let Some(rest) = value_start.strip_prefix('"') {
        match find_double_quote_end(rest) {
            Some(end) => &rest[end + 1..],
            None => return String::new(),
        }
    } else if let Some(rest) = value_start.strip_prefix('\'') {
        match rest.find('\'') {
            Some(end) => &rest[end + 1..],
            None => return String::new(),
        }
    } else {
        return unquoted_trailing_comment(value_start);
    };

    if after_value
        .chars()
        .next()
        .is_some_and(|c| c == ' ' || c == '\t')
        && after_value.trim_start_matches([' ', '\t']).starts_with('#')
    {
        after_value.to_string()
    } else {
        String::new()
    }
}

fn find_double_quote_end(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn unquoted_trailing_comment(value_start: &str) -> String {
    let bytes = value_start.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b' ' || bytes[i] == b'\t' {
            let ws_start = i;
            while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'#' {
                return value_start[ws_start..].to_string();
            }
        } else {
            i += 1;
        }
    }
    String::new()
}

fn read_env_value(env_file: &Path, name: &str) -> Result<Option<String>, String> {
    let content = read_capped(env_file, MAX_ENV_BYTES)
        .map_err(|err| format!("read {}: {err}", env_file.display()))?;
    Ok(parse_env(&content).shift_remove(name))
}

#[derive(Debug)]
struct DoctorFailure {
    name: String,
    message: String,
}

#[derive(Debug)]
struct DoctorReport {
    checked: usize,
    failures: Vec<DoctorFailure>,
}

fn check_encrypted_values(
    content: &str,
    key: &[u8],
    scope: &str,
    all: bool,
) -> Result<usize, DoctorReport> {
    let mut report = DoctorReport {
        checked: 0,
        failures: Vec::new(),
    };

    for (name, value) in parse_env(content) {
        if !is_encrypted_value(&value) {
            continue;
        }
        report.checked += 1;
        if let Err(err) = decrypt_value(&value, key, scope, &name) {
            report.failures.push(DoctorFailure {
                name,
                message: err.to_string(),
            });
            if !all {
                return Err(report);
            }
        }
    }

    if report.failures.is_empty() {
        Ok(report.checked)
    } else {
        Err(report)
    }
}

fn run_exec_command(mut command: Command, display_name: &str) -> Result<i32, String> {
    #[cfg(unix)]
    let _forwarder = ExecSignalForwarder::install(-1)
        .map_err(|err| format!("install signal forwarding for {display_name}: {err}"))?;

    let mut child = command
        .spawn()
        .map_err(|err| format!("run {display_name}: {err}"))?;

    #[cfg(unix)]
    EXEC_CHILD_PID.store(child.id() as libc::pid_t, Ordering::SeqCst);

    let status = child
        .wait()
        .map_err(|err| format!("wait for {display_name}: {err}"))?;
    Ok(child_exit_code(status))
}

fn child_exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }

    1
}

struct TempFileGuard {
    path: PathBuf,
    persisted: bool,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, persisted: false }
    }

    fn persist(mut self) {
        self.persisted = true;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if !self.persisted {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temp_path = temp_write_path(path);
    #[cfg(unix)]
    let target_mode = env_file_mode(path)?;

    let guard = TempFileGuard::new(temp_path.clone());

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(target_mode);
    }
    let mut file = options.open(&temp_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(target_mode))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp_path, path)?;
    guard.persist();

    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

#[cfg(unix)]
fn env_file_mode(path: &Path) -> io::Result<u32> {
    use std::os::unix::fs::PermissionsExt;

    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.permissions().mode() & 0o777),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(0o600),
        Err(err) => Err(err),
    }
}

fn temp_write_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("env");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nanos))
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn read_capped(path: &Path, max_bytes: u64) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut buf = String::new();
    let read = file.take(max_bytes + 1).read_to_string(&mut buf)?;
    if read as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds {max_bytes} byte cap"),
        ));
    }
    Ok(buf)
}

fn find_duplicate_names(content: &str) -> Vec<String> {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    let mut duplicates: Vec<String> = Vec::new();
    let mut already_reported: HashSet<String> = HashSet::new();
    for line in content.lines() {
        if let Some(name) = env_line_name(line) {
            if !seen.insert(name.clone()) && already_reported.insert(name.clone()) {
                duplicates.push(name);
            }
        }
    }
    duplicates
}

fn strip_export_prefix(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("export")?;
    let mut chars = rest.chars();
    let first = chars.next()?;
    if first == ' ' || first == '\t' {
        let trimmed_count = first.len_utf8()
            + rest[first.len_utf8()..]
                .chars()
                .take_while(|c| *c == ' ' || *c == '\t')
                .map(|c| c.len_utf8())
                .sum::<usize>();
        Some(&rest[trimmed_count..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = env::var_os(key);
            env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => env::set_var(self.key, value),
                None => env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn env_upsert_replaces_existing_name() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".env");
        fs::write(&file, "A=1\nAPI_KEY=old\nB=2\n").unwrap();
        upsert_env_value(&file, "API_KEY", "new").unwrap();
        let content = fs::read_to_string(file).unwrap();
        assert_eq!(content, "A=1\nAPI_KEY=new\nB=2\n");
    }

    #[test]
    fn env_upsert_preserves_comments_and_export_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".env");
        fs::write(
            &file,
            "# keep this\nexport API_KEY=old\n  export OTHER_KEY=old\nPLAIN=value\n",
        )
        .unwrap();

        upsert_env_value(&file, "API_KEY", "new").unwrap();
        upsert_env_value(&file, "OTHER_KEY", "newer").unwrap();

        let content = fs::read_to_string(file).unwrap();
        assert_eq!(
            content,
            "# keep this\nexport API_KEY=new\n  export OTHER_KEY=newer\nPLAIN=value\n"
        );
    }

    #[test]
    fn env_upsert_preserves_trailing_comment() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".env");
        fs::write(
            &file,
            "API_KEY=old # rotated 2026-01-15\nQUOTED=\"hello\" # tag\nNORMAL=plain\n",
        )
        .unwrap();

        upsert_env_value(&file, "API_KEY", "enc:v1:newvalue").unwrap();
        upsert_env_value(&file, "QUOTED", "enc:v1:other").unwrap();
        upsert_env_value(&file, "NORMAL", "enc:v1:third").unwrap();

        let content = fs::read_to_string(&file).unwrap();
        assert_eq!(
            content,
            "API_KEY=enc:v1:newvalue # rotated 2026-01-15\nQUOTED=enc:v1:other # tag\nNORMAL=enc:v1:third\n"
        );
    }

    #[test]
    fn env_upsert_does_not_treat_hash_in_value_as_comment() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".env");
        fs::write(&file, "PASS=hash#tag\n").unwrap();

        upsert_env_value(&file, "PASS", "enc:v1:new").unwrap();

        let content = fs::read_to_string(&file).unwrap();
        assert_eq!(content, "PASS=enc:v1:new\n");
    }

    #[test]
    fn env_upsert_uses_same_dir_temp_file_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".env.production");

        upsert_env_value(&file, "API_KEY", "new").unwrap();

        assert_eq!(fs::read_to_string(&file).unwrap(), "API_KEY=new\n");
        let temp_files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(temp_files.is_empty(), "left temp files: {temp_files:?}");
    }

    #[test]
    fn concurrent_env_upserts_preserve_all_names() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".env.production");
        let workers = 32;
        let barrier = Arc::new(Barrier::new(workers));
        let handles: Vec<_> = (0..workers)
            .map(|idx| {
                let file = file.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    upsert_env_value(
                        &file,
                        &format!("API_KEY_{idx}"),
                        &format!("value_{idx}"),
                    )
                    .unwrap();
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let env = parse_env(&fs::read_to_string(&file).unwrap());
        assert_eq!(env.len(), workers);
        for idx in 0..workers {
            assert_eq!(
                env.get(&format!("API_KEY_{idx}")),
                Some(&format!("value_{idx}"))
            );
        }
    }

    #[test]
    fn env_lock_path_is_sibling() {
        assert_eq!(
            env_lock_path(Path::new("/tmp/project/.env.production")),
            PathBuf::from("/tmp/project/.env.production.lock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn env_upsert_preserves_existing_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".env.production");
        fs::write(&file, "API_KEY=old\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();

        upsert_env_value(&file, "API_KEY", "new").unwrap();

        let file_mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o640);
        assert_eq!(fs::read_to_string(&file).unwrap(), "API_KEY=new\n");
    }

    #[cfg(unix)]
    #[test]
    fn env_upsert_creates_new_file_private_by_default() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".env.production");

        upsert_env_value(&file, "API_KEY", "new").unwrap();

        let file_mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
    }

    #[test]
    fn temp_write_path_stays_next_to_target() {
        let path = Path::new("/tmp/project/.env.production");
        let temp = temp_write_path(path);
        assert_eq!(temp.parent().unwrap(), Path::new("/tmp/project"));
        assert!(temp.file_name().unwrap().to_string_lossy().starts_with("..env.production."));
    }

    #[test]
    fn resolve_env_file_treats_existing_file_as_env_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("custom.env");
        fs::write(&file, "K=v\n").unwrap();
        assert_eq!(resolve_env_file(&file, "production"), file);
    }

    #[test]
    fn resolve_env_file_treats_existing_directory_as_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = resolve_env_file(dir.path(), "production");
        assert_eq!(result, dir.path().join(".env.production"));
    }

    #[test]
    fn resolve_env_file_accepts_directory_or_file_path() {
        assert_eq!(
            resolve_env_file(Path::new("/tmp/project"), "production"),
            PathBuf::from("/tmp/project/.env.production")
        );
        assert_eq!(
            resolve_env_file(Path::new("/tmp/project/.env"), DEFAULT_SCOPE),
            PathBuf::from("/tmp/project/.env")
        );
        assert_eq!(
            resolve_env_file(Path::new("/tmp/project/.env.production"), "production"),
            PathBuf::from("/tmp/project/.env.production")
        );
    }

    #[test]
    fn shell_quote_handles_single_quotes() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn doctor_all_collects_every_failure() {
        let key: Vec<u8> = (0..32).collect();
        let sealed = "enc:v1:ICEiIyQlJicoKSoroV_FAgnsN3h7EDerj53e0Qpsr2lTDYsfbYmoIQ";
        let content = format!("BROKEN_SHORT=enc:v1:ICEi\nBROKEN_NAME={sealed}\n");

        let first = check_encrypted_values(&content, &key, "production", false).unwrap_err();
        assert_eq!(first.checked, 1);
        assert_eq!(first.failures.len(), 1);

        let all = check_encrypted_values(&content, &key, "production", true).unwrap_err();
        assert_eq!(all.checked, 2);
        assert_eq!(all.failures.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn child_exit_code_uses_signal_convention() {
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg("kill -TERM $$")
            .status()
            .unwrap();

        assert_eq!(child_exit_code(status), 128 + libc::SIGTERM);
    }

    #[cfg(windows)]
    #[test]
    fn windows_prompt_is_not_echoed() {
        let err = prompt_secret("SECRET").unwrap_err();
        assert!(err.contains("interactive secret prompt is unsupported on Windows"));
    }

    #[test]
    fn load_or_create_key_does_not_overwrite_corrupt_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("masterkey.production");
        fs::write(&key_file, "not-a-valid-key\n").unwrap();

        let err = load_or_create_key("production", Some(&key_file), None).unwrap_err();
        assert!(err.contains("parse base64url key"));
        assert_eq!(fs::read_to_string(&key_file).unwrap(), "not-a-valid-key\n");
    }

    #[test]
    fn load_or_create_key_only_auto_creates_missing_default_key() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _xdg = EnvVarGuard::set("XDG_CONFIG_HOME", dir.path());

        let key = load_or_create_key("production", None, None).unwrap();
        assert_eq!(key.len(), dotseal::KEY_LEN);
        assert!(dir.path().join("dotseal/masterkey.production").exists());
    }

    #[test]
    fn exclusive_key_create_does_not_overwrite_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("masterkey.production");
        let first_key = [1u8; dotseal::KEY_LEN];
        let second_key = [2u8; dotseal::KEY_LEN];

        create_key_file(&key_file, &first_key, false).unwrap();
        let err = create_key_file(&key_file, &second_key, false).unwrap_err();

        assert_eq!(err.kind, KeyWriteErrorKind::AlreadyExists);
        let content = fs::read_to_string(&key_file).unwrap();
        assert_eq!(parse_key(content.trim()).unwrap(), first_key);
    }

    #[test]
    fn concurrent_default_key_creation_converges_on_one_key() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _xdg = EnvVarGuard::set("XDG_CONFIG_HOME", dir.path());

        let workers = 24;
        let barrier = Arc::new(Barrier::new(workers));
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    load_or_create_key("production", None, None).unwrap()
                })
            })
            .collect();

        let keys: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        let persisted = fs::read_to_string(dir.path().join("dotseal/masterkey.production")).unwrap();
        let persisted = parse_key(persisted.trim()).unwrap();
        assert!(keys.iter().all(|key| key == &persisted));
    }

    #[cfg(unix)]
    #[test]
    fn default_key_directory_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = env_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _xdg = EnvVarGuard::set("XDG_CONFIG_HOME", dir.path());

        load_or_create_key("production", None, None).unwrap();
        let metadata = fs::metadata(dir.path().join("dotseal")).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn explicit_key_parent_permissions_are_not_changed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_dir = dir.path().join("keys");
        fs::create_dir_all(&key_dir).unwrap();
        fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o755)).unwrap();

        let key = generate_key();
        write_key_file(&key_dir.join("masterkey.production"), &key, false).unwrap();

        let metadata = fs::metadata(&key_dir).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o755);
    }

    #[cfg(windows)]
    #[test]
    fn windows_key_file_creation_is_unsupported_without_acl_hardening() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_key();

        let err = write_key_file(&dir.path().join("masterkey.production"), &key, true)
            .unwrap_err();

        assert!(err.contains("Windows key-file creation is not supported"));
        assert!(!dir.path().join("masterkey.production").exists());
    }

    #[test]
    fn load_or_create_key_does_not_overwrite_corrupt_default_key() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _xdg = EnvVarGuard::set("XDG_CONFIG_HOME", dir.path());
        let key_file = dir.path().join("dotseal/masterkey.production");
        fs::create_dir_all(key_file.parent().unwrap()).unwrap();
        fs::write(&key_file, "not-a-valid-key\n").unwrap();

        let err = load_or_create_key("production", None, None).unwrap_err();
        assert!(err.contains("parse base64url key"));
        assert_eq!(fs::read_to_string(&key_file).unwrap(), "not-a-valid-key\n");
    }

    #[test]
    fn existing_key_validation_rejects_corrupt_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("masterkey.production");
        fs::write(&key_file, "not-a-valid-key\n").unwrap();
        let content = fs::read_to_string(&key_file).unwrap();
        let err = parse_key(content.trim()).unwrap_err();
        assert!(err.to_string().contains("parse base64url key"));
    }

    #[test]
    fn key_command_ignores_shell_env() {
        let _guard = env_lock().lock().unwrap();
        let _shell = EnvVarGuard::set("SHELL", "/bin/false");

        assert_eq!(run_key_command("printf ok").unwrap(), "ok");
    }

    #[test]
    fn set_value_help_warns_about_argv_exposure() {
        use clap::CommandFactory;

        let mut command = Cli::command();
        let set = command.find_subcommand_mut("set").unwrap();
        let mut help = Vec::new();
        set.write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();

        assert!(help.contains("WARNING: visible to other users via ps"));
        assert!(help.contains("prefer --stdin or --file"));
    }
}
