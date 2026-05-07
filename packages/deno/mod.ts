export const VERSION = "v1";
export const NONCE_LEN = 12;
export const KEY_LEN = 32;
export const DEFAULT_SCOPE = "default";

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+={0,2}$/;
const SCOPE_SEAL_PATTERN = /^[A-Za-z0-9_.\-]+$/;
const AAD_INJECTION = /[\n\r]/;

export function isSafeEnvName(name: unknown): boolean {
  return typeof name === "string" &&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) &&
    name !== "__proto__" &&
    name !== "constructor" &&
    name !== "prototype";
}

export function isValidScope(scope: unknown): boolean {
  return typeof scope === "string" && SCOPE_SEAL_PATTERN.test(scope);
}

export function isEncryptedValue(value: unknown): value is string {
  return typeof value === "string" && value.startsWith("enc:");
}

export function parseKey(raw: string | Uint8Array): Uint8Array {
  // Already-parsed 32-byte raw key — mirrors JS's `Buffer.isBuffer(key) ? key : parseKey(key)`
  // shortcut so callers can hand back a previously-parsed key without
  // round-tripping through UTF-8 and base64.
  if (raw instanceof Uint8Array && raw.length === KEY_LEN) {
    return raw;
  }
  const text = typeof raw === "string" ? raw.trim() : new TextDecoder().decode(raw).trim();
  if (/^[0-9a-fA-F]{64}$/.test(text)) {
    const out = new Uint8Array(KEY_LEN);
    for (let i = 0; i < KEY_LEN; i++) {
      out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }
  const key = base64UrlDecode(text);
  if (key.length !== KEY_LEN) {
    throw new Error(`dotseal key must decode to ${KEY_LEN} bytes`);
  }
  return key;
}

export async function decryptValue(
  value: string,
  options: { key: string | Uint8Array; scope: string; name: string },
): Promise<string> {
  if (!isEncryptedValue(value)) return value;
  const { key, scope, name } = options;
  if (!scope) throw new Error("dotseal decryptValue requires scope");
  if (!name) throw new Error("dotseal decryptValue requires name");
  if (AAD_INJECTION.test(name)) throw new Error("dotseal decryptValue: invalid name");
  if (AAD_INJECTION.test(scope)) throw new Error("dotseal decryptValue: invalid scope");

  const first = value.indexOf(":");
  const second = first >= 0 ? value.indexOf(":", first + 1) : -1;
  if (first < 0 || second < 0) {
    throw new Error("unsupported dotseal value");
  }
  const marker = value.slice(0, first);
  const version = value.slice(first + 1, second);
  const payloadText = value.slice(second + 1);
  if (marker !== "enc" || version !== VERSION) {
    throw new Error("unsupported dotseal value");
  }
  if (!BASE64URL_PATTERN.test(payloadText)) {
    throw new Error(`dotseal value for ${name} has invalid base64url payload`);
  }

  const payload = base64UrlDecode(payloadText);
  if (payload.length <= NONCE_LEN) {
    throw new Error(`dotseal value for ${name} is too short`);
  }
  const nonce = payload.slice(0, NONCE_LEN);
  const ciphertext = payload.slice(NONCE_LEN);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    parseKey(key),
    "AES-GCM",
    false,
    ["decrypt"],
  );
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: new TextEncoder().encode(aad(scope, name)),
      tagLength: 128,
    },
    cryptoKey,
    ciphertext,
  );
  return UTF8_DECODER.decode(plaintext);
}

export async function decryptEnv(
  env: Record<string, string>,
  options: { key: string | Uint8Array; scope: string },
): Promise<Record<string, string>> {
  const out: Record<string, string> = Object.create(null);
  for (const [name, value] of Object.entries(env)) {
    out[name] = await decryptValue(value, { ...options, name });
  }
  return out;
}

export async function decryptTree(
  value: unknown,
  options: { key: string | Uint8Array; scope: string; path?: string },
): Promise<unknown> {
  if (isEncryptedValue(value)) {
    if (!options.path) throw new Error("dotseal decryptTree requires a path for encrypted values");
    return decryptValue(value, {
      key: options.key,
      scope: options.scope,
      name: options.path,
    });
  }
  if (Array.isArray(value)) {
    return Promise.all(value.map((entry, index) => decryptTree(entry, {
      ...options,
      path: appendPathSegment(options.path, index),
    })));
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = Object.create(null);
    for (const [name, entry] of Object.entries(value)) {
      out[name] = await decryptTree(entry, {
        ...options,
        path: appendPathSegment(options.path, name),
      });
    }
    return out;
  }
  return value;
}

function appendPathSegment(existing: string | undefined, segment: string | number): string {
  const encoded = JSON.stringify(segment);
  return existing ? `${existing}.${encoded}` : encoded;
}

export function parseEnv(content: string): Record<string, string> {
  const env: Record<string, string> = Object.create(null);
  let text = content;
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.replace(/^[\s\ufeff]+/, "");
    if (!trimmed || trimmed.startsWith("#")) continue;
    const rest = stripExportPrefix(trimmed) ?? trimmed;
    const index = rest.indexOf("=");
    if (index === -1) continue;
    const name = rest.slice(0, index).trim();
    if (isSafeEnvName(name)) {
      env[name] = parseEnvValue(rest.slice(index + 1));
    }
  }
  return env;
}

function stripExportPrefix(line: string): string | null {
  if (!line.startsWith("export")) return null;
  const after = line.slice(6);
  if (after.length === 0) return null;
  const ch = after[0];
  if (ch !== " " && ch !== "\t") return null;
  let i = 0;
  while (i < after.length && (after[i] === " " || after[i] === "\t")) i++;
  return after.slice(i);
}

export function parseEnvValue(raw: string): string {
  const trimmedStart = raw.replace(/^[\s\ufeff]+/, "");
  if (trimmedStart.startsWith('"')) {
    const rest = trimmedStart.slice(1);
    const end = findDoubleQuoteEnd(rest);
    if (end !== -1) return unescapeDoubleQuoted(rest.slice(0, end));
  } else if (trimmedStart.startsWith("'")) {
    const end = trimmedStart.indexOf("'", 1);
    if (end !== -1) return trimmedStart.slice(1, end);
  }
  return stripInlineComment(trimmedStart).replace(/[\s]+$/, "");
}

function stripInlineComment(value: string): string {
  for (let i = 0; i < value.length; i++) {
    if (value[i] === "#" && (i === 0 || value[i - 1] === " " || value[i - 1] === "\t")) {
      return value.slice(0, i);
    }
  }
  return value;
}

function findDoubleQuoteEnd(rest: string): number {
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === "\\" && i + 1 < rest.length) { i++; continue; }
    if (rest[i] === '"') return i;
  }
  return -1;
}

// AAD binding: `dotseal:v1\nscope=<scope>\nname=<NAME>\n`. See FORMAT.md
// § Algorithm. `scope` and `name` MUST be validated against the AAD-injection
// charset (no \n/\r) before reaching this — `decryptValue` does that above.
function aad(scope: string, name: string): string {
  return `dotseal:${VERSION}\nscope=${scope}\nname=${name}\n`;
}

function unescapeDoubleQuoted(value: string): string {
  let out = "";
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (ch !== "\\") {
      out += ch;
      continue;
    }
    const next = value[++i];
    if (next === undefined) {
      out += "\\";
    } else if (next === "n") {
      out += "\n";
    } else if (next === "r") {
      out += "\r";
    } else if (next === "t") {
      out += "\t";
    } else if (next === '"' || next === "\\") {
      out += next;
    } else {
      out += `\\${next}`;
    }
  }
  return out;
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
