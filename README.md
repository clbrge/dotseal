# dotseal

Seal individual values in `.env` files with scoped local keys.

```bash
dotseal set . API_SUPER_KEY
dotseal set . -s prod API_SUPER_KEY
dotseal get . -s prod API_SUPER_KEY
dotseal doctor . -s prod
dotseal -s prod exec . npm run deploy
```

`dotseal set` prompts without terminal echo when no plaintext source is
provided. For non-interactive use, prefer stdin or a file:

```bash
printf '%s' "$API_SUPER_KEY" | dotseal set . -s prod API_SUPER_KEY --stdin
dotseal set . -s prod API_SUPER_KEY --file /run/secrets/api_super_key
```

`dotseal set --value ...` is supported for convenience, but the plaintext is
visible through argv (`ps`, shell history, sudo/audit logs, and similar tooling).

No scope writes to `.env` and uses the `default` key. A scope writes to
`.env.<scope>` and uses `masterkey.<scope>`.

```dotenv
API_SUPER_KEY=enc:v1:...
```

By default keys are stored under:

```txt
~/.config/dotseal/masterkey.default
~/.config/dotseal/masterkey.prod
```

Automatic key-file creation is currently hardened on Unix only. On Windows,
use `--key-cmd` or provide an externally protected `--key-file` until Dotseal
sets current-user-only DACLs itself.

Use `--key-file` or `--key-cmd` to override key loading:

```bash
dotseal set . -s prod API_SUPER_KEY \
  --key-cmd "secret-tool lookup app dotseal scope prod"
```

`--key-cmd` reads the command's stdout as UTF-8 text and trims surrounding
whitespace before parsing the key.

`dotseal` protects values at rest in dotenv files. It does not hide a secret
from a process that can read both the encrypted file and the matching master
key.

## When dotseal fits

Good fit when you want to:

- back up a `.env.production` to a sync service (iCloud, Dropbox, a NAS,
  a 1Password attachment) without keeping plaintext in that channel
- distribute `.env.production` to teammates via channels you wouldn't
  trust with plaintext (chat, S3, an internal artifact store)
- protect values at rest on a deployment host where the binary needs them
  but other tenants on the host shouldn't see them
- rotate a single secret without re-encrypting everything around it
- run a binary with decrypted secrets via `dotseal exec` without writing
  the plaintext to disk
- mix encrypted and plaintext values in the same env file (`PORT=3000`
  stays plain; only sensitive values are sealed)
- give a sandboxed process access to a project tree without granting it
  the means to decrypt those secrets (see § Coding-agent sandboxing)

Not a fit for:

- centrally-managed secret distribution to fleets (use Vault, AWS Secrets
  Manager, Doppler, Infisical)
- per-user / per-role access control on individual values — dotseal is a
  symmetric scheme, anyone with the master key can read every sealed value
  in that scope

> **Not a substitute for `.gitignore`.** Encryption does not make `.env.*`
> safe to commit. Master-key compromise — leaked from a teammate's
> password manager, a stolen laptop, an over-shared vault — makes every
> past commit retroactively decryptable, and git's append-only history
> means rotating the key cannot rescind a leaked blob already in the log.
> Treat encrypted `.env` files the same as plaintext ones for source
> control: keep them out. Dotseal is for *moving* and *storing* the file,
> not for shipping it through history.

## Use cases

### 1. Encrypted backup of `.env`

You want your `.env.production` to survive a laptop loss without keeping
a plaintext copy in iCloud, Dropbox, or a shared drive.

```bash
dotseal -s production init-key
dotseal -s production set . OPENAI_API_KEY      # prompts; no echo
dotseal -s production set . STRIPE_SECRET_KEY
dotseal -s production set . DATABASE_URL --stdin <<< "postgres://..."
```

The resulting file:

```env
NODE_ENV=production
PORT=3000
OPENAI_API_KEY=enc:v1:Cy2Wxt...
STRIPE_SECRET_KEY=enc:v1:Y8q4dK...
DATABASE_URL=enc:v1:mAk9p4...
```

This file is now safe to drop into iCloud Drive / Dropbox / a NAS / a
1Password attachment. The master key file
(`~/.config/dotseal/masterkey.production`) does **not** go through the
same channel — back it up to your password manager separately.

Recover on a new machine:

```bash
# 1. Restore the master key (from password manager, gpg-encrypted backup, etc.)
install -m 0600 /path/to/recovered/masterkey.production \
  ~/.config/dotseal/masterkey.production

# 2. The synced .env.production is already in place — just run.
dotseal -s production exec . npm run start
```

The encrypted file by itself reveals variable names and value lengths
(approximately, via the encoded ciphertext length) but not the values.

### 2. Per-secret rotation

A vendor leaks an API key — rotate it without touching anything else:

```bash
dotseal -s production set . STRIPE_SECRET_KEY --stdin < new-stripe.key
dotseal -s production doctor . --all
```

`doctor --all` re-decrypts every encrypted entry and reports failures one
by one. It also warns on duplicate names.

### 3. Multi-environment setup

```bash
dotseal -s development init-key
dotseal -s staging     init-key
dotseal -s production  init-key   # only on the prod machine
```

Each scope writes to its own `.env.<scope>` and uses its own master key.
The AAD binding means a value sealed under `staging` cannot be decrypted
with the `production` key — even if a developer accidentally swaps files.

Pick at runtime:

```bash
dotseal -s "$NODE_ENV" exec . node server.js
```

### 4. CI/CD: decrypt-on-deploy

```yaml
# .github/workflows/deploy.yml
- name: Deploy
  env:
    DOTSEAL_KEY: ${{ secrets.DOTSEAL_PRODUCTION_KEY }}
  run: |
    dotseal -s production --key-cmd 'printf "%s" "$DOTSEAL_KEY"' \
      exec . ./scripts/deploy.sh
```

`--key-cmd` reads the master key from a shell command's stdout — the key
never lands in a file.

### 5. systemd unit with sealed env

```ini
[Service]
ExecStart=/usr/local/bin/dotseal -s production \
  --key-file /etc/dotseal/masterkey.production \
  exec /etc/myapp /usr/local/bin/myapp
User=myapp
```

`dotseal exec` forwards SIGINT, SIGTERM, SIGHUP to the child, so
`systemctl stop myapp` propagates correctly. Plaintext lives only in the
process's env page — never on disk.

### 6. Coding-agent sandboxing

You're running a coding agent (Claude Code, Cursor, an LLM-driven CI bot)
inside a sandbox over a project that contains `.env.production`. The
sandbox profile already restricts the agent to the project tree.

Because the master key file lives **outside** the project tree (default
`~/.config/dotseal/masterkey.<scope>`), the agent reads the encrypted
values but cannot decrypt them. There's nothing to move, nothing to
re-key, nothing to mask in source.

To revoke an agent's access to a scope:

```bash
# firejail: blacklist the dotseal config dir
firejail --blacklist=~/.config/dotseal --whitelist=~/projects/myapp \
  claude-code

# bubblewrap: simply don't bind ~/.config/dotseal into the sandbox
bwrap --ro-bind ~/projects/myapp /work \
      --bind /tmp /tmp \
      --proc /proc --dev /dev \
      claude-code

# Apple Seatbelt / sandbox-exec: omit ~/.config/dotseal from the
# allow-list of readable paths.
```

To grant an agent access to a *specific* scope while denying others, point
it at one explicit key file rather than letting it scan the default
location:

```bash
dotseal -s staging \
  --key-file ~/.config/dotseal/masterkey.staging \
  exec . claude-code
```

Inside the sandbox, only the `staging` key is reachable; `production`
remains opaque even though `.env.production` is in the project tree.

Per-scope blacklist/whitelist is a path-policy concern, not a dotseal one
— that's the point. You don't have to rearrange your repo to revoke.

### 7. Local dev: master key from a password manager

Don't keep a long-lived key file on your laptop. Pull on demand:

```bash
# 1Password CLI
dotseal -s production --key-cmd 'op item get "dotseal prod" --format json | jq -r .fields.key.value' \
  exec . npm run start

# pass(1)
dotseal -s production --key-cmd 'pass dotseal/production' exec . npm run start
```

If the manager prompts for a touch / unlock, you'll get one prompt per
`dotseal` invocation.

### 8. Validation in an existing toolchain

Detect malformed sealed values at boot, even outside the dotseal load
path:

```js
// Node: from 'dotseal-env'; Deno: from '@dotseal/env' (JSR).
import { isEncryptedValue, isSafeEnvName } from 'dotseal-env'

for (const [name, value] of Object.entries(process.env)) {
  if (!isSafeEnvName(name)) continue
  if (isEncryptedValue(value)) {
    throw new Error(`refusing to start: ${name} is sealed but no scope was supplied`)
  }
}
```

`isEncryptedValue`, `isSafeEnvName`, `isValidScope` are pure predicates
exported by every loader.

### 9. Migration from a plaintext `.env`

```bash
dotseal init-key
for var in OPENAI_API_KEY STRIPE_SECRET_KEY DATABASE_URL; do
  current=$(grep -E "^${var}=" .env | cut -d= -f2-)
  dotseal set . "$var" --stdin <<< "$current"
done
dotseal doctor . --all
```

Plaintext entries stay plaintext until you `set` on them. Migration is
incremental — one secret per PR is fine.

## Packages

This repo intentionally keeps the CLI and runtime loaders separate:

```txt
dotseal                 Rust CLI and Rust loader crate
dotseal-env             JavaScript loader primitives (npm)
dotseal-env             Python loader primitives (PyPI)
@dotseal/env            Deno loader primitives (JSR)
dotseal-go              Go loader primitives
packages/shell          POSIX shell helpers over the dotseal CLI
```

The loaders decrypt the same `enc:v1:<payload>` envelope and do not implement
project-specific config merging.

Rust usage:

```rust
use dotseal::{decrypt_env, parse_env, parse_key};

let key = parse_key("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")?;
let env = parse_env("API_SUPER_KEY=enc:v1:...\n");
let decrypted = decrypt_env(&env, &key, "prod")?;
```

Shell usage:

```sh
. ./packages/shell/dotseal.sh
dotseal_load . prod
dotseal_exec . prod npm run deploy
```

`dotseal print-env` emits shell-quoted assignments. It is useful but should be
treated as sensitive output. Prefer `dotseal exec` when possible.

## Format

See [FORMAT.md](./FORMAT.md).
