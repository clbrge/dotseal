# Dotseal Format

Dotseal encrypts individual dotenv values. It does not define a full config
system and it does not manage a central vault.

## Envelope

```txt
enc:v1:<payload>
```

- `enc` marks the value as encrypted.
- `v1` is the envelope version (see [Versioning](#versioning) below).
- `<payload>` is canonical base64url without padding. Decoders accept optional
  `=` padding for compatibility with third-party sealers.

The decoded payload is:

```txt
12 byte nonce || AES-GCM ciphertext+tag
```

The decoded payload MUST be at least 13 bytes (12 nonce + at least 1
ciphertext byte before the 16-byte AES-GCM tag) to be considered well-formed.
Loaders reject anything shorter as `payload_too_short`.

Plaintext bytes MUST be valid UTF-8. Loaders reject authenticated plaintext
that cannot be decoded as UTF-8.

The master key is 32 random bytes, stored as base64url without padding by the
default file key provider. Loaders accept optional `=` padding when parsing
base64url keys.

### Canonicality

Producers (the Rust seal API) MUST emit the payload as base64url **without
padding**. The exact alphabet is RFC 4648 §5 (URL- and filename-safe):
`A-Z`, `a-z`, `0-9`, `-`, `_`. Decoders accept either canonical form (no
padding) or the same payload with one or two `=` characters appended for
compatibility with third-party sealers, but a non-canonical envelope is not
guaranteed to round-trip byte-for-byte through dotseal CLI re-writes.

Sealed values contain only `:` as a separator before the payload. Decoders
MUST split on the **first two** `:` characters (yielding `enc`, `v1`,
`<payload>`). Any additional `:` characters MUST be treated as part of the
payload (which today is base64url and therefore can never contain `:`, but
forward-compatible parsing is preserved for future versions).

### Limits

| Field | Max | Encoding |
|---|---|---|
| Plaintext | runtime-bounded by available memory | UTF-8 bytes |
| `scope` | 256 bytes | charset below |
| `name` | 256 bytes | charset below |
| Master key | 32 bytes | binary |
| Envelope payload (decoded) | runtime-bounded | nonce ‖ ciphertext ‖ tag |

The 256-byte caps on `scope` and `name` are recommendations: loaders SHOULD
NOT impose hard caps below 256 bytes, and producers SHOULD treat names longer
than 256 bytes as a probable misuse. dotseal CLI env-file reads are capped at
1 MiB by default (see `MAX_ENV_BYTES`).

### Charsets

- **`name`** (env variable name): MUST match `[A-Za-z_][A-Za-z0-9_]*`. This
  is the dotseal CLI / dotenv convention.
- **`scope`** (CLI / sealing time): MUST match `[A-Za-z0-9_.-]+`.
- **`name`** at decryption time (loader `decryptValue` and `decryptTree`):
  MAY contain any characters EXCEPT `\n` and `\r` — tree-path leaves use
  dotted segments and JSON-encoded keys (see "decryptTree paths" below).
- **`scope`** at decryption time: MAY contain any characters EXCEPT `\n` and
  `\r`. The seal-side restriction is stricter; the decrypt side relaxes it
  because callers may pass scopes that survived through other systems.

The only AAD-breaking characters are `\n` (which would create a fake AAD line)
and `\r` (which some parsers normalize to `\n`). Everything else is fine
inside an AAD field.

### decryptTree paths

When a loader's `decryptTree(value, { scope, key })` walks a JSON-shaped tree
and reaches an encrypted leaf, the AAD `name` is constructed from the path
that led to that leaf. Each path segment is JSON-encoded (via
`JSON.stringify`) before being joined with `.`:

- `{a: {b: <enc>}}` → AAD name = `"a"."b"`
- `{"a.b": <enc>}` → AAD name = `"a.b"`
- `{list: [<enc>, <enc>]}` → AAD names = `"list".0`, `"list".1`

The two object shapes above produce different AAD strings, so a value sealed
for one shape cannot be decrypted in the other. This is intentional and
prevents the path-collision aliasing class of bugs.

## Algorithm

- Cipher: AES-256-GCM.
- Nonce: 96-bit random nonce per encryption.
- Key: 32 bytes.
- Encoding: canonical base64url without padding.

Additional authenticated data binds the ciphertext to both the dotenv variable
name and the caller-provided scope:

```txt
dotseal:v1
scope=<scope>
name=<NAME>
```

Each line is terminated by `\n`, including the trailing `name=<NAME>\n`. The
exact byte sequence is:

```
"dotseal:v1\nscope=" + <scope> + "\nname=" + <NAME> + "\n"
```

**AAD invariant**: `<scope>` and `<NAME>` MUST NOT contain `\n` or `\r`. This
is what prevents an attacker from constructing two `(scope, name)` pairs that
serialize to the same AAD bytes (e.g. `scope="prod\nname=ADMIN"` colliding
with the legitimate `name=ADMIN` line). Both seal-side and decrypt-side
validators enforce this; see the [Charsets](#charsets) section below for the
full per-side rules.

Moving an encrypted value between names or scopes must fail decryption.

## Versioning

The envelope version (`v1` today) is independent from the dotseal **release**
version. A loader at dotseal 1.7.0 may still speak only envelope `v1`; a
future release that introduces envelope `v2` does not retire `v1`.

### Loader behavior

- A loader MUST reject any envelope whose version it does not implement.
  Today that means accepting `v1` and rejecting everything else with an
  `unsupported_version` error.
- A loader MUST treat unknown future versions (`v2`, `v3`, ...) the same as
  malformed input — never as a fall-through to `v1` semantics. There is no
  "best effort" decode of a higher version.
- A loader SHOULD include the rejected version string in its error so
  operators can diagnose mid-rollout mismatches without exposing key
  material.

### Compatibility windows

When a new envelope version (`v2`) ships:

1. Rust seal-side gains the ability to **emit** `v2` behind an opt-in flag.
2. All four loaders gain the ability to **decrypt** `v2` in the same
   coordinated release (see `RELEASING.md`).
3. The default seal version remains `v1` for at least one minor release
   after every loader supports `v2`. This gives operators a window to update
   their decryption fleet before encryption begins to require it.
4. After the deprecation window, the default seal version flips to `v2`.
   Loaders continue accepting `v1` for at least one major release after
   that — old envelopes already on disk decrypt indefinitely.

### Algorithm agility

`v1` is hard-pinned to AES-256-GCM with 96-bit nonces. There is no in-band
algorithm negotiation — the version *is* the algorithm. Replacing the cipher
or the AAD construction is what triggers a `v2`.

The intent is that envelope versions stay rare and meaningful. Bug fixes,
documentation changes, and additive loader API surface do not change the
envelope version.

### Multi-version support

Loaders MAY accept multiple envelope versions simultaneously. The Rust
crate's public API takes the version-bearing envelope string as input and
dispatches internally; callers do not pre-declare which version they expect.

A loader that accepts multiple versions MUST treat them as a strict OR — a
ciphertext valid under `v1` MUST NOT be re-binding-attempted under `v2` if
its `enc:v1:` prefix says otherwise.

## Default Key Path

Without overrides, scope keys live under the user config directory:

```txt
$XDG_CONFIG_HOME/dotseal/masterkey.<scope>
```

If `XDG_CONFIG_HOME` is unset:

```txt
$HOME/.config/dotseal/masterkey.<scope>
```

On Unix, the CLI creates the default `dotseal` key directory with `0700`
permissions and writes key files with `0600` permissions.

On Windows, Dotseal currently refuses to create key files because private DACL
creation is not implemented. Use `--key-cmd` or an externally protected
`--key-file` on Windows.

## Dotenv parsing

Dotseal's `parse_env` follows the de-facto convention shared by `dotenv`,
`python-dotenv`, `godotenv`, and Ruby `dotenv`:

- Lines beginning with `#` (after optional leading whitespace) are comments.
- A leading `export` keyword followed by space or tab is stripped.
- A UTF-8 BOM at file start is stripped.
- Names must match `[A-Za-z_][A-Za-z0-9_]*`.

For values:

- A leading `"` enters a double-quoted value; the value runs to the next
  unescaped `"`. Backslash escapes `\n`, `\r`, `\t`, `\"`, `\\` are honored.
- A leading `'` enters a single-quoted value; the value runs to the next `'`.
  No escape processing.
- Otherwise the value is unquoted: it ends at the first `#` that is at the
  start of the value or preceded by space/tab. A `#` not preceded by
  whitespace (e.g. `pass#word`) is part of the value.
- Trailing whitespace is stripped from unquoted values. Whitespace inside
  quoted values is preserved verbatim.

Plaintext bytes MUST be valid UTF-8 (see Envelope above). To put a literal
unquoted-`#`-with-leading-whitespace into a value, quote the value.

### Plaintext memory hygiene

The Rust crate returns decrypted plaintext as `Plaintext` (alias for
`Zeroizing<String>`). The buffer is overwritten with zeros when dropped, so
the secret does not linger in heap memory after the caller releases it. This
matters under core-dump or swap-recovery threat models.

Loaders in JS, Deno, Python, and Go cannot offer the same guarantee — those
runtimes do not give portable access to the underlying string allocation.
Callers in those languages should treat decrypted secrets as visible to any
post-mortem inspection of the process.

### Iteration order

`parse_env` preserves the order names appear in the source file. Duplicate
names collapse to the last value, keeping the position of the first
occurrence. This matches the behavior of npm `dotenv`, `python-dotenv`, and
the Deno loader.

The Go loader returns `map[string]string` and therefore does NOT preserve
order — iteration order is randomized per Go's map semantics. This is
documented per-loader divergence; callers that need ordering on Go should
re-parse from the source file directly.
