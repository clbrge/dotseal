# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the `0.x.y` caveat: while `version < 1.0.0`, minor bumps may include
breaking changes (and will be called out under **Changed** with a note).

The envelope format version (`enc:v1:`) is independent of the release
version — see `FORMAT.md` § Versioning. Bumping the envelope version is a
coordinated breaking change across all loaders.

## [Unreleased]

## [0.1.0] - 2026-05-07

Initial public release. Per-value AES-256-GCM sealing for dotenv files,
plus decrypt-only loaders for JS, Deno, Python, and Go.

### Added

#### Format and crypto

- `enc:v1:<base64url>` envelope: 12-byte random nonce ‖ AES-256-GCM
  ciphertext ‖ 16-byte tag. AAD binds each ciphertext to its
  `(scope, name)` tuple so moving a value between names or scopes fails
  decryption.
- 32-byte symmetric master key per scope. Default location
  `$XDG_CONFIG_HOME/dotseal/masterkey.<scope>` (mode `0600`,
  parent dir `0700` on Unix).

#### CLI (`dotseal`)

- Subcommands: `set`, `get`, `init-key`, `key-path`, `doctor`,
  `print-env`, `exec`. Stdout/stderr contract documented in `CLI.md`.
- Three plaintext input forms for `set`: `--value <SECRET>` (visible to
  `ps`, with a help-text warning), `--stdin`, `--file <PATH>`. Default
  is no-echo terminal prompt.
- `--key-cmd '<sh>'` reads the master key from a shell command's stdout
  — usable with 1Password CLI, `pass(1)`, `secret-tool`, etc.
- `dotseal exec` forwards SIGINT, SIGTERM, SIGHUP to the child;
  exit-code passthrough with `128 + signal` convention on signaled exit.
- `dotseal doctor --all` re-decrypts every encrypted entry, surfaces
  duplicate-name warnings, and reports per-failure detail.
- `dotseal print-env` buffers all decrypted values before emitting so a
  mid-iteration decrypt failure cannot leak partial plaintext.

#### Loaders

- Rust crate (`dotseal`): full seal/decrypt API. Returns plaintext as
  `Plaintext` (= `Zeroizing<String>`) so secrets are zeroed on drop.
- JS / npm (`dotseal-env`): decrypt-only, including `decryptValue`,
  `decryptEnv`, `decryptTree`, `parseEnv`, `parseEnvValue`, `parseKey`.
- Deno / JSR (`@dotseal/env`): same surface as JS, web-crypto backed.
- Python / PyPI (`dotseal-env`): same surface, `cryptography` backed.
- Go (`packages/go/dotseal`): `DecryptValue`, `DecryptEnv`, `ParseEnv`,
  `ParseKey`. Tree decryption deferred to caller code.
- POSIX shell helpers (`packages/shell/dotseal.sh`): thin wrappers over
  the CLI for `dotseal_load` / `dotseal_exec`.

#### Loader API parity

- All loaders export `VERSION`, `DEFAULT_SCOPE`, `NONCE_LEN`, `KEY_LEN`,
  `isSafeEnvName` / `is_safe_env_name` / `IsSafeEnvName`, and
  `isValidScope` / `is_valid_scope` / `IsValidScope`.
- AAD construction is byte-identical across all five implementations.
- Cross-language test corpus at `test-vectors/v1.json` (6 accept + 14
  reject vectors) is consumed verbatim by every loader.
- `decryptTree` AAD paths are JSON-encoded per segment so that
  `{"a.b": x}` and `{"a": {"b": x}}` produce distinct AAD strings (no
  path-collision aliasing).

#### Hardening

- Plaintext UTF-8 strictness in every loader (web-crypto `fatal: true`,
  Python `bytes.decode("utf-8")`, Go `utf8.Valid`).
- Strict base64url payload validation in JS/Deno (matches Rust/Go/Python
  rejection behavior).
- Decrypt-side `\n`/`\r` rejection in `scope` and `name` blocks the AAD
  injection class of bug while leaving `decryptTree` dotted paths usable.
- Atomic env-file writes (temp + fsync + rename + dir fsync + RAII
  cleanup of the temp file on panic).
- Env-file reads capped at 1 MiB; key-file reads at 4 KiB; value-file
  reads at 1 MiB.
- File locking on `dotseal set` (`flock` on Unix, `LockFileEx` on
  Windows) prevents concurrent-write data loss.
- Key-file create uses `O_EXCL` + falls back to loading the winner's
  key on race, so concurrent `init-key` from multiple shells converges.
- Existing env-file permissions are preserved on rewrite (atomic write
  reads the prior mode and applies it to the temp file).
- Signal-forwarder is installed before `Command::spawn` to close the
  pre-forwarder signal window; PID is updated atomically post-spawn.
- Error messages Debug-format (`{:?}`) the `scope`/`name` slot to
  escape attacker-controlled control characters (log-poisoning hardening).

#### Dotenv parsing

- Standard de-facto semantics: `#` outside quotes is a comment when at
  value-start or preceded by whitespace; `#` inside quotes is literal;
  trailing whitespace stripped from unquoted values.
- UTF-8 BOM stripped at file start.
- `export` keyword followed by space *or* tab is recognised.
- Iteration order matches insertion order in Rust (`IndexMap`),
  JS/Deno/Python (native object/dict insertion order), with Go documented
  as map-randomized per language idiom.
- `dotseal doctor` warns on duplicate names (last-wins behavior is
  preserved but no longer silent).

#### Documentation and tooling

- `README.md` — quick start, when-to-use / when-not-to-use, 9 worked
  use cases (encrypted backup, per-secret rotation, multi-environment,
  CI/CD, systemd, coding-agent sandboxing, password-manager-backed
  keys, validation, migration).
- `FORMAT.md` — envelope, algorithm, AAD invariant, charsets, limits,
  canonicality, dotenv parsing, plaintext memory hygiene, iteration
  order, versioning policy.
- `CLI.md` — exit codes, stdout/stderr contract, output format
  stability, signal forwarding, key/path resolution.
- `RELEASING.md` — pre-publish checklist, per-artifact publish flow,
  sigstore signing recipe, SBOM via `cargo-cyclonedx`, coordinated-bump
  policy.
- `test-vectors/README.md` — minimum loader test set.
- `deny.toml` (cargo-deny config: license allow-list, wildcards denied,
  yanked denied, sources whitelisted to crates.io).
- `rustfmt.toml`. Loader linters configured (ESLint flat config for JS,
  `[tool.ruff]` for Python, `lint` block in `deno.json`).
- 72 Rust tests (19 lib + 26 main + 6 cli_exec + 17 cli_subcommands +
  4 proptests × 256 cases). 39 JS tests. Cross-language vector roundtrip
  via `scripts/cross-language-roundtrip.mjs` with auto-skip for
  toolchains not on `PATH`.

[Unreleased]: https://github.com/clbrge/dotseal/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/clbrge/dotseal/releases/tag/v0.1.0
