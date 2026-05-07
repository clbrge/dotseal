import crypto from 'node:crypto'

export const VERSION = 'v1'
export const NONCE_LEN = 12
export const KEY_LEN = 32
export const DEFAULT_SCOPE = 'default'

const GCM_TAG_LEN = 16
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true })
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+={0,2}$/
const SCOPE_SEAL_PATTERN = /^[A-Za-z0-9_.\-]+$/
const AAD_INJECTION = /[\n\r]/

export const isSafeEnvName = (name) => (
  /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) &&
  name !== '__proto__' &&
  name !== 'constructor' &&
  name !== 'prototype'
)

export const isValidScope = (scope) => (
  typeof scope === 'string' && SCOPE_SEAL_PATTERN.test(scope)
)

export const isEncryptedValue = (value) => (
  typeof value === 'string' && value.startsWith('enc:')
)

export const parseKey = (raw) => {
  const text = Buffer.isBuffer(raw) ? raw.toString('utf8').trim() : String(raw).trim()
  if (/^[0-9a-fA-F]{64}$/.test(text)) {
    return Buffer.from(text, 'hex')
  }
  const key = Buffer.from(text, 'base64url')
  if (key.length !== KEY_LEN) {
    throw new Error(`dotseal key must decode to ${KEY_LEN} bytes`)
  }
  return key
}

export const decryptValue = (value, { key, scope, name }) => {
  if (!isEncryptedValue(value)) return value
  if (!name) throw new Error('dotseal decryptValue requires name')
  if (!scope) throw new Error('dotseal decryptValue requires scope')
  if (AAD_INJECTION.test(name)) throw new Error('dotseal decryptValue: invalid name')
  if (AAD_INJECTION.test(scope)) throw new Error('dotseal decryptValue: invalid scope')

  const first = value.indexOf(':')
  const second = first >= 0 ? value.indexOf(':', first + 1) : -1
  if (first < 0 || second < 0) {
    throw new Error('unsupported dotseal value')
  }
  const marker = value.slice(0, first)
  const version = value.slice(first + 1, second)
  const payloadText = value.slice(second + 1)
  if (marker !== 'enc' || version !== VERSION) {
    throw new Error('unsupported dotseal value')
  }
  if (!BASE64URL_PATTERN.test(payloadText)) {
    throw new Error(`dotseal value for ${name} has invalid base64url payload`)
  }

  const payload = Buffer.from(payloadText, 'base64url')
  if (payload.length <= NONCE_LEN) {
    throw new Error(`dotseal value for ${name} is too short`)
  }
  const nonce = payload.subarray(0, NONCE_LEN)
  const encrypted = payload.subarray(NONCE_LEN)
  const ciphertext = encrypted.subarray(0, encrypted.length - GCM_TAG_LEN)
  const tag = encrypted.subarray(encrypted.length - GCM_TAG_LEN)

  const cipherKey = Buffer.isBuffer(key) ? key : parseKey(key)
  const decipher = crypto.createDecipheriv('aes-256-gcm', cipherKey, nonce)
  decipher.setAAD(Buffer.from(aad(scope, name)))
  decipher.setAuthTag(tag)
  return UTF8_DECODER.decode(Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]))
}

export const decryptEnv = (env, { key, scope }) => {
  const out = Object.create(null)
  for (const [name, value] of Object.entries(env)) {
    out[name] = decryptValue(value, { key, scope, name })
  }
  return out
}

export const decryptTree = (value, { key, scope, path = '' }) => {
  if (isEncryptedValue(value)) {
    if (!path) throw new Error('dotseal decryptTree requires a path for encrypted values')
    return decryptValue(value, { key, scope, name: path })
  }
  if (Array.isArray(value)) {
    return value.map((entry, index) => decryptTree(entry, {
      key,
      scope,
      path: appendPathSegment(path, index)
    }))
  }
  if (value && typeof value === 'object') {
    const out = Object.create(null)
    for (const [name, entry] of Object.entries(value)) {
      out[name] = decryptTree(entry, {
        key,
        scope,
        path: appendPathSegment(path, name)
      })
    }
    return out
  }
  return value
}

const appendPathSegment = (existing, segment) => {
  const encoded = JSON.stringify(segment)
  return existing ? `${existing}.${encoded}` : encoded
}

export const parseEnv = (content) => {
  const env = Object.create(null)
  let text = String(content)
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1)
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.replace(/^[\s\ufeff]+/, '')
    if (!trimmed || trimmed.startsWith('#')) continue
    const rest = stripExportPrefix(trimmed) ?? trimmed
    const index = rest.indexOf('=')
    if (index === -1) continue
    const name = rest.slice(0, index).trim()
    if (!isSafeEnvName(name)) continue
    env[name] = parseEnvValue(rest.slice(index + 1))
  }
  return env
}

const stripExportPrefix = (line) => {
  if (!line.startsWith('export')) return null
  const after = line.slice(6)
  if (after.length === 0) return null
  const ch = after[0]
  if (ch !== ' ' && ch !== '\t') return null
  let i = 0
  while (i < after.length && (after[i] === ' ' || after[i] === '\t')) i++
  return after.slice(i)
}

export const parseEnvValue = (raw) => {
  const trimmedStart = String(raw).replace(/^[\s\ufeff]+/, '')
  if (trimmedStart.startsWith('"')) {
    const rest = trimmedStart.slice(1)
    const end = findDoubleQuoteEnd(rest)
    if (end !== -1) return unescapeDoubleQuoted(rest.slice(0, end))
  } else if (trimmedStart.startsWith("'")) {
    const end = trimmedStart.indexOf("'", 1)
    if (end !== -1) return trimmedStart.slice(1, end)
  }
  return stripInlineComment(trimmedStart).replace(/[\s]+$/, '')
}

const stripInlineComment = (value) => {
  for (let i = 0; i < value.length; i++) {
    if (value[i] === '#' && (i === 0 || value[i - 1] === ' ' || value[i - 1] === '\t')) {
      return value.slice(0, i)
    }
  }
  return value
}

const findDoubleQuoteEnd = (rest) => {
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '\\' && i + 1 < rest.length) { i++; continue }
    if (rest[i] === '"') return i
  }
  return -1
}

const unescapeDoubleQuoted = (value) => {
  let out = ''
  for (let i = 0; i < value.length; i++) {
    const ch = value[i]
    if (ch !== '\\') {
      out += ch
      continue
    }
    const next = value[++i]
    if (next === undefined) {
      out += '\\'
    } else if (next === 'n') {
      out += '\n'
    } else if (next === 'r') {
      out += '\r'
    } else if (next === 't') {
      out += '\t'
    } else if (next === '"' || next === '\\') {
      out += next
    } else {
      out += `\\${next}`
    }
  }
  return out
}

// AAD binding: `dotseal:v1\nscope=<scope>\nname=<NAME>\n`. See FORMAT.md
// § Algorithm. `scope` and `name` MUST be validated against the AAD-injection
// charset (no \n/\r) before reaching this — `decryptValue` does that above.
const aad = (scope, name) => `dotseal:${VERSION}\nscope=${scope}\nname=${name}\n`
