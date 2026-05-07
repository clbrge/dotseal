import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  DEFAULT_SCOPE,
  KEY_LEN,
  NONCE_LEN,
  VERSION,
  decryptEnv,
  decryptTree,
  decryptValue,
  isSafeEnvName,
  isValidScope,
  parseEnv,
  parseKey,
} from '../src/index.js'

const sealForTest = (plaintext, key, scope, name) => {
  const aad = Buffer.from(`dotseal:v1\nscope=${scope}\nname=${name}\n`)
  const nonce = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', parseKey(key), nonce)
  cipher.setAAD(aad)
  const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()])
  const tag = cipher.getAuthTag()
  return `enc:v1:${Buffer.concat([nonce, encrypted, tag]).toString('base64url')}`
}

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../../test-vectors/v1.json'), 'utf8'))
const primary = vectors.cases[0]

for (const vector of vectors.cases) {
  test(`decrypts v1 test vector: ${vector.id}`, () => {
    const key = parseKey(vectors.key)
    assert.equal(decryptValue(vector.sealed, {
      key,
      scope: vector.scope,
      name: vector.name
    }), vector.plaintext)
  })
}

for (const vector of vectors.rejects) {
  test(`rejects v1 test vector: ${vector.id}`, () => {
    assert.throws(() => decryptValue(vector.sealed, {
      key: vectors.key,
      scope: vector.scope,
      name: vector.name
    }))
  })
}

test('accepts padded base64url key and payload', () => {
  const key = parseKey(`${vectors.key}=`)
  assert.equal(decryptValue(`${primary.sealed}==`, {
    key,
    scope: primary.scope,
    name: primary.name
  }), primary.plaintext)
})

test('parses and decrypts env objects', () => {
  const env = parseEnv(`${primary.name}=${primary.sealed}\nPLAIN=value\n`)
  assert.deepEqual({ ...decryptEnv(env, {
    key: vectors.key,
    scope: primary.scope
  }) }, {
    [primary.name]: primary.plaintext,
    PLAIN: 'value'
  })
})

test('parses quoted dotenv values', () => {
  const env = parseEnv('PLAIN= value \nDOUBLE=" hello world "\nSINGLE=\' keep spaces \'\nESCAPED="line\\nnext\\t\\"q\\""\n')
  assert.deepEqual({ ...env }, {
    PLAIN: 'value',
    DOUBLE: ' hello world ',
    SINGLE: ' keep spaces ',
    ESCAPED: 'line\nnext\t"q"'
  })
})

test('parseEnv denies prototype pollution keys', () => {
  const env = parseEnv('__proto__=x\nconstructor=y\nprototype=z\nSAFE=value\n')
  assert.equal(Object.getPrototypeOf(env), null)
  assert.deepEqual(Object.keys(env), ['SAFE'])
  assert.equal(env.SAFE, 'value')
})

test('exports loader-API constants per FORMAT.md', () => {
  assert.equal(VERSION, 'v1')
  assert.equal(DEFAULT_SCOPE, 'default')
  assert.equal(NONCE_LEN, 12)
  assert.equal(KEY_LEN, 32)
})

test('isSafeEnvName matches FORMAT.md regex and rejects reserved keys', () => {
  assert.equal(isSafeEnvName('FOO_BAR'), true)
  assert.equal(isSafeEnvName('_private'), true)
  assert.equal(isSafeEnvName('123FOO'), false)
  assert.equal(isSafeEnvName('__proto__'), false)
  assert.equal(isSafeEnvName('constructor'), false)
})

test('isValidScope matches seal-side regex', () => {
  assert.equal(isValidScope('production'), true)
  assert.equal(isValidScope('staging-eu.1'), true)
  assert.equal(isValidScope('bad scope'), false)
  assert.equal(isValidScope('bad\nscope'), false)
})

test('parseEnv preserves file insertion order', () => {
  const env = parseEnv('ZEBRA=z\nALPHA=a\nMIDDLE=m\n')
  assert.deepEqual(Object.keys(env), ['ZEBRA', 'ALPHA', 'MIDDLE'])
})

test('parseEnv strips UTF-8 BOM from first line', () => {
  const env = parseEnv('\ufeffFIRST=kept\nSECOND=also\n')
  assert.equal(env.FIRST, 'kept')
  assert.equal(env.SECOND, 'also')
})

test('parseEnv accepts tab and multi-space after export', () => {
  const env = parseEnv('export\tTABBED=val\nexport   PADDED=padded\nNORMAL=ok\n')
  assert.equal(env.TABBED, 'val')
  assert.equal(env.PADDED, 'padded')
  assert.equal(env.NORMAL, 'ok')
})

test('decryptValue rejects invalid scope and name characters', () => {
  assert.throws(() => decryptValue(primary.sealed, {
    key: vectors.key,
    scope: 'prod\nname=ADMIN',
    name: primary.name
  }), /invalid scope/)
  assert.throws(() => decryptValue(primary.sealed, {
    key: vectors.key,
    scope: primary.scope,
    name: 'ADMIN\nname=API_KEY'
  }), /invalid name/)
})

test('parseEnv strips inline comments from unquoted values', () => {
  const env = parseEnv('PLAIN=value # tail\nNOSPACE=foo#bar\nLEADING=  spaced   # tail\nEMPTYISH=#all comment\n')
  assert.equal(env.PLAIN, 'value')
  assert.equal(env.NOSPACE, 'foo#bar')
  assert.equal(env.LEADING, 'spaced')
  assert.equal(env.EMPTYISH, '')
})

test('parseEnv keeps # literal inside quoted values', () => {
  const env = parseEnv('DOUBLE="with # inside" # tail\nSINGLE=\'also # literal\' # tail\n')
  assert.equal(env.DOUBLE, 'with # inside')
  assert.equal(env.SINGLE, 'also # literal')
})

test('decryptTree decrypts nested object leaves with JSON-encoded path AAD', () => {
  const sealedAB = sealForTest('leaf-ab', vectors.key, 'production', '"a"."b"')
  const sealedAC = sealForTest('leaf-ac', vectors.key, 'production', '"a"."c"')
  const out = decryptTree(
    { a: { b: sealedAB, c: sealedAC } },
    { key: vectors.key, scope: 'production' }
  )
  assert.deepEqual({ ...out, a: { ...out.a } }, { a: { b: 'leaf-ab', c: 'leaf-ac' } })
})

test('decryptTree handles arrays with numeric-index path AAD', () => {
  const sealed0 = sealForTest('zero', vectors.key, 'production', '"list".0')
  const sealed1 = sealForTest('one', vectors.key, 'production', '"list".1')
  const out = decryptTree(
    { list: [sealed0, sealed1] },
    { key: vectors.key, scope: 'production' }
  )
  assert.deepEqual([...out.list], ['zero', 'one'])
})

test('decryptTree leaves non-encrypted scalars unchanged', () => {
  const out = decryptTree(
    { kept: 'plain', n: 42, b: true, nil: null },
    { key: vectors.key, scope: 'production' }
  )
  assert.equal(out.kept, 'plain')
  assert.equal(out.n, 42)
  assert.equal(out.b, true)
  assert.equal(out.nil, null)
})

test('decryptTree refuses an encrypted leaf at root with no path', () => {
  const sealed = sealForTest('orphan', vectors.key, 'production', 'whatever')
  assert.throws(() => decryptTree(sealed, { key: vectors.key, scope: 'production' }),
    /requires a path/)
})

test('decryptTree path encoding: aliased shapes produce DIFFERENT AAD paths', () => {
  // {"a.b": x} → path "\"a.b\"" ; {"a":{"b":x}} → path "\"a\".\"b\""
  const sealedFlat = sealForTest('flat', vectors.key, 'production', '"a.b"')
  const sealedNested = sealForTest('nested', vectors.key, 'production', '"a"."b"')
  const flat = decryptTree({ 'a.b': sealedFlat }, { key: vectors.key, scope: 'production' })
  const nested = decryptTree({ a: { b: sealedNested } }, { key: vectors.key, scope: 'production' })
  assert.equal(flat['a.b'], 'flat')
  assert.equal(nested.a.b, 'nested')
  // A flat-path-sealed value MUST NOT decrypt at the nested location.
  assert.throws(() =>
    decryptTree({ a: { b: sealedFlat } }, { key: vectors.key, scope: 'production' }))
  // And vice versa.
  assert.throws(() =>
    decryptTree({ 'a.b': sealedNested }, { key: vectors.key, scope: 'production' }))
})

test('decryptValue rejects payload with non-base64url characters', () => {
  assert.throws(() => decryptValue('enc:v1:****invalid****', {
    key: vectors.key,
    scope: primary.scope,
    name: primary.name
  }), /invalid base64url/)
})
