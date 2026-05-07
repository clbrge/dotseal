# Test vectors

`v1.json` is the shared cross-language test corpus for dotseal envelope v1. Every
loader (Rust, JS, Deno, Python, Go) MUST run both arrays verbatim:

- `cases[]`: each entry's `sealed` MUST decrypt to `plaintext` under
  `(key, scope, name)`. Loaders also assert that `encode_key` /
  `seal_value_with_nonce` reproduce `sealed` byte-for-byte (Rust only — loaders
  are decrypt-only).
- `rejects[]`: each entry's `sealed` MUST be rejected by `decryptValue` under
  `(key, scope, name)`. Loaders match on rejection only — error message text
  is intentionally unspecified.

## Minimum loader test set (T-L1)

Every loader is expected to ship at least:

1. The `cases` accept loop (one test per vector entry).
2. The `rejects` reject loop (one test per vector entry).
3. Padded base64url key acceptance (`AAA…AA=` style).
4. Padded base64url payload acceptance (only when emitted by third-party sealers).
5. Plaintext UTF-8 strictness (decoders MUST reject non-UTF-8 plaintext).
6. `parseEnv` / `parse_env` happy path on a simple `KEY=value` file.
7. `parseEnv` BOM-strip on first line.
8. `parseEnv` `export\tNAME=val` and `export   NAME=val` accepted.
9. `parseEnv` inline `#` strips trailing comment from unquoted values; quoted
   values keep `#` literal.
10. `decryptTree` happy path on a nested object and array (loaders that ship it).

Cross-language coverage is exercised by `scripts/cross-language-roundtrip.mjs`,
which runs every `cases` and `rejects` entry through every loader.

## Generating new vectors

Use `cargo run --example gen_vectors` to print bit-flip / version-downgrade
variants of the primary `production_secret` vector. Add per-vector `sha256` if
fixture corruption becomes a concern.
