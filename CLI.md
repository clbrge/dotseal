# Dotseal CLI Contract

This document is the stability contract for the `dotseal` command-line
binary. Output, exit codes, and option semantics described here are part of
the public API and follow semver: breaking changes require a major version
bump.

## Subcommands

```
dotseal [-s <scope>] [--key-file <path>] [--key-cmd <cmd>] <subcommand> [args]
```

| Subcommand | Purpose |
|---|---|
| `set <path> <name> [--value VAL | --stdin | --file PATH]` | Encrypt a single value and write it to the env file at the given path. |
| `get <path> <name>` | Decrypt a single value and print it on stdout. |
| `key-path` | Print the key file path that would be used for the active scope. |
| `init-key [--force]` | Create a scope key. Idempotent unless `--force`. |
| `doctor <path> [--all]` | Verify all encrypted entries decrypt. With `--all`, report every failure. |
| `print-env <path>` | Decrypt the env file and emit shell-quoted assignments. |
| `exec <path> <command> [args...]` | Run `command` with the decrypted env file applied as process env. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Subcommand succeeded. |
| `1` | Subcommand failed: invalid input, decryption error, file IO error, etc. The error message is on stderr. |
| `128 + N` | (`exec` only) The child terminated by signal `N` (e.g. `128 + SIGTERM = 143`). Mirrors the standard shell convention. |
| `<child-exit-code>` | (`exec` only) When the child exits normally, dotseal forwards its exit code unchanged. |

The CLI never panics on user-controlled input. A panic indicates a dotseal
bug and should be reported.

## stdout vs. stderr

| Stream | Carries | Stable? |
|---|---|---|
| `stdout` | Subcommand data output: a sealed `name=enc:v1:...` line from `set`, the plaintext from `get`, the resolved key path from `key-path` and `init-key`, the `name=value` lines from `print-env`, the success summary `ok: checked N encrypted value(s)` from `doctor`. | Yes — this format is the contract. |
| `stderr` | Diagnostics: error messages prefixed with `dotseal:`, `doctor` per-failure lines (`<NAME>: <message>`), `doctor` duplicate-name warnings (`warning: duplicate name <NAME> ...`), `set --value` ps-warning (in help text). | Stable in *meaning* but not in exact wording — callers MUST NOT regex-match for substring stability. |

## Output format stability

These output forms are part of the contract:

- **`set` stdout** ends with a single `\n`-terminated line:
  `<NAME>=enc:v1:<base64url-no-padding>`. The line is exactly the bytes
  written into the env file for that variable.
- **`get` stdout** is the decrypted plaintext followed by a single `\n`. If
  the plaintext itself contains newlines, they are emitted verbatim (no
  wrapping, no quoting). The trailing `\n` is added by `println!` and is
  not part of the secret.
- **`key-path` stdout** is the absolute resolved key path followed by a
  single `\n`.
- **`init-key` stdout** is the resolved key path followed by a single `\n`,
  emitted whether the key was created or already existed. Use exit code
  `0` to confirm idempotence.
- **`print-env` stdout** is one `name='shell-quoted-value'\n` per variable,
  in env-file order. Single quotes are the only quoting form used; embedded
  `'` characters are escaped as `'\''` (POSIX-portable). The output is safe
  to `eval` in `sh`/`bash`/`dash`/`zsh`.
- **`exec` stdout/stderr** are passed through unchanged from the child.
  dotseal only writes to its own stderr if it fails to spawn the child.
- **`doctor` stdout** is exactly one line on success: `ok: checked N
  encrypted value(s)`. Failure lines and warnings go to stderr; the final
  exit code reflects whether any check failed.

## Signals (`exec`)

`dotseal exec` installs a signal forwarder before spawning the child. SIGINT,
SIGTERM, and SIGHUP delivered to the dotseal process are forwarded to the
child by `kill(child_pid, signum)`. Other signals are not forwarded and
follow default disposition.

The forwarder is installed *before* `spawn` (with the child PID set to a
sentinel `-1` until spawn returns), so a signal arriving in the brief
`spawn`/`install` window is harmlessly absorbed by dotseal rather than
orphaning the child.

## Argv exposure

`--value <secret>` makes the secret visible to other users of the host via
`/proc/<pid>/cmdline` (Linux) or `ps` output. Use `--stdin` (read plaintext
from a pipe) or `--file <path>` (read plaintext from a file with the
appropriate mode) to avoid exposure. The CLI help text carries this warning;
the warning text is documented but not regex-stable.

## Key resolution

Precedence, highest to lowest:

1. `--key-cmd <cmd>` — run `sh -c '<cmd>'` and read 32-byte base64url or
   64-char hex master key from stdout. Fails if the command exits non-zero.
2. `--key-file <path>` — read the master key from `<path>`.
3. `$XDG_CONFIG_HOME/dotseal/masterkey.<scope>` (or
   `~/.config/dotseal/masterkey.<scope>` if `XDG_CONFIG_HOME` is unset).

Inputs to `parse_key` accept either base64url (with or without `=` padding)
or 64-character hex. Other formats are rejected.

## Path resolution (`<path>` arg)

For subcommands that take a path:

- If `path` exists and is a directory, dotseal joins `<path>/.env.<scope>`
  (or `<path>/.env` when `scope == "default"`).
- If `path` exists and is a file, dotseal uses it as the env file directly.
- If `path` does not exist, dotseal uses the basename heuristic: `.env` and
  `.env.*` filenames are treated as env-file targets; anything else is
  treated as a directory to be created.

## Versioning

This contract follows the dotseal release version (semver). The `enc:v1:`
envelope version is independent — see `FORMAT.md`. Output stability covers
the documented format only; hand-parsing dotseal's stderr is unsupported
and may break across patch releases.
