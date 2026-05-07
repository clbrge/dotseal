# @dotseal/env (Deno)

Decrypt-only loader for the dotseal envelope format. See the [repository
README](../../README.md) and [`FORMAT.md`](../../FORMAT.md) for the cross-language
spec.

## Requirements

- **Deno ≥ 1.40** — the loader uses `crypto.subtle.importKey('AES-GCM')` and
  `TextDecoder({ fatal: true })`, both of which are stable in 1.40+.
- Permissions: none required for `decryptValue` / `decryptEnv` /
  `decryptTree` / `parseEnv`. Reading `.env` files from disk is the caller's
  responsibility.

## Install

```ts
import { decryptValue, decryptEnv, parseEnv } from "jsr:@dotseal/env";
```

## Notes

- Decrypt-only. Sealing is done via the `dotseal` CLI (Rust crate).
- Plaintext memory zeroize is not available in Deno's runtime — see the
  per-language divergence in `FORMAT.md`.

## License

Dual-licensed under MIT or Apache-2.0 at your option — see the included
`LICENSE-MIT` and `LICENSE-APACHE` files. The JSR metadata field reports
only `MIT` because JSR accepts a single SPDX identifier per package; the
project's licensing is unchanged.
