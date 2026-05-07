# Releasing dotseal

This document is the release checklist for dotseal — the Rust crate, the CLI
binary, and the four loader packages (JS, Deno, Python, Go).

## Versioning

Dotseal pins a single version number across all artifacts. The format envelope
(`enc:v1:`) follows its own version axis documented in `FORMAT.md`. A loader
release SHOULD NOT change envelope semantics; envelope changes (e.g. `v2`) are
gated on a coordinated multi-loader bump.

## Pre-publish checklist

Run from a clean checkout on `main`:

```bash
# 1. Test gates
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo fmt --check
(cd packages/js && node --test)
# (Run go test, deno test, python tests when toolchains are present.)

# 2. Cross-language vector roundtrip
node scripts/cross-language-roundtrip.mjs

# 3. Supply-chain audit
cargo install cargo-deny --locked  # one-time
cargo deny check
cargo audit                         # advisories only

# 4. Generate SBOM
cargo install cargo-cyclonedx --locked  # one-time
cargo cyclonedx --format json --output-pattern dist/dotseal.sbom.json

# 5. Bump version everywhere (single source of truth: Cargo.toml)
# Mirror to packages/{js,python,deno}/* manifest files.
```

## Publishing

### Rust crate

```bash
cargo publish --locked
```

### Binary releases (GitHub)

Build per-target binaries and sign with sigstore `cosign`:

```bash
for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
              x86_64-apple-darwin   aarch64-apple-darwin; do
    cargo build --release --target "$target" --locked
    cosign sign-blob --yes \
        "target/$target/release/dotseal" \
        --output-signature "dist/dotseal-$target.sig" \
        --output-certificate "dist/dotseal-$target.pem"
done

gh release create "v$(version)" dist/* --notes-file CHANGELOG.md
```

### npm (`dotseal-env`)

```bash
cd packages/js
# CI runs this with --provenance and OIDC trusted publishing.
npm publish --provenance --access public
```

### PyPI (`dotseal-env`)

Use PyPI Trusted Publishing (OIDC) — no long-lived API tokens. Configure in
the project settings on pypi.org once, then GitHub Actions publishes from a
restricted environment.

### JSR (Deno)

```bash
cd packages/deno
deno publish
```

### Go (`packages/go/dotseal`)

Go has no central registry — consumers reference the module path directly.
Tag the release in git so `go get github.com/clbrge/dotseal/packages/go@vX.Y.Z`
resolves.

## Post-publish

- Verify `cargo install dotseal --locked` works against crates.io.
- Verify `npm install dotseal-env` works against npm.
- Verify `deno add @dotseal/env` works against JSR.
- Verify `pip install dotseal-env` works against PyPI.
- Verify `go get github.com/clbrge/dotseal/packages/go@vX.Y.Z` works.
- Run `scripts/cross-language-roundtrip.mjs` against the published artifacts
  (set `DOTSEAL_BIN` to the installed binary).

## Coordinated breaking changes

When the format envelope or a loader's public API changes incompatibly:

1. Open an RFC issue describing the change. Include before/after AAD if
   relevant.
2. Bump the format version in `FORMAT.md` and `lib.rs::VERSION`.
3. Land changes in a single PR across all four loaders.
4. Bump every package's major version simultaneously.
5. Add a tested-pair compatibility matrix to this file under "Tested pairs".

## Cross-version compatibility

Dotseal artifacts ship in lockstep — all six (Rust crate, CLI binary, JS,
Deno, Python, Go) carry the same release version. The pre-publish checklist
above ensures they were built from the same commit, so the matrix below is
trivially "every artifact at version X.Y.Z is compatible with every other
artifact at X.Y.Z".

What "compatible" means:

- **Envelope round-trip**: a value sealed by the Rust CLI at version X.Y.Z
  decrypts byte-for-byte under any X.Y.Z loader.
- **Test-vector parity**: every loader at version X.Y.Z accepts the same
  `cases[]` and rejects the same `rejects[]` from `test-vectors/v1.json`.
- **Cross-loader migration**: a JS loader at X.Y.Z and a Python loader at
  the same X.Y.Z see identical results for every accept and reject vector
  (verified by `scripts/cross-language-roundtrip.mjs`).

What's NOT guaranteed across versions:

- The CLI's stderr wording (see `CLI.md` — error messages may rephrase).
- Loader public API surface beyond what `FORMAT.md` documents (helpers,
  constants, internal types are subject to semver of the loader package).

The "Tested pairs" matrix below is populated at release time. Each row
captures a release that has been smoke-tested against the prior loader
generation. Cross-major-version cells are filled in only when a deliberate
compatibility test has been run (e.g. validating that loaders at 1.x can
still decrypt envelopes sealed by a 0.x CLI).

## Tested pairs

| dotseal version | format envelope | notes |
|---|---|---|
| 0.1.x | v1 | initial release |

## Notes on outstanding hardening

- `cargo-deny` is configured (`deny.toml`) but not yet wired into CI — see
  T-L3 in `FINDINGS.md`.
- SBOM generation and binary signing flow are documented above but require
  a release CI workflow to be reproducible. Until that lands, the local
  invocations are the source of truth.
- The RustCrypto coordinated bump (`aes-gcm 0.11` / `rand_core 0.9` /
  `getrandom 0.3`) is tracked as D-L3 / D-I2 — pending upstream.
