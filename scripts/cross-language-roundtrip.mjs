import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const vectors = JSON.parse(fs.readFileSync(path.join(repo, 'test-vectors/v1.json'), 'utf8'))
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dotseal-cross-'))

const explicitSkip = new Set(
  (process.env.DOTSEAL_SKIP ?? '').split(',').map((s) => s.trim()).filter(Boolean)
)

const TOOLCHAINS = {
  js: { check: () => true },
  python: { check: () => hasBinary('python3') },
  go: { check: () => hasBinary('go') },
  deno: { check: () => hasBinary('deno') },
}

const autoSkip = new Set()
for (const [lang, { check }] of Object.entries(TOOLCHAINS)) {
  if (explicitSkip.has(lang)) continue
  if (!check()) autoSkip.add(lang)
}

if (autoSkip.size > 0) {
  console.warn(`cross-language: auto-skipping ${[...autoSkip].join(', ')} (toolchain not on PATH)`)
}

const want = (lang) => !explicitSkip.has(lang) && !autoSkip.has(lang)

let jsLoaderPromise
let goDir
let denoScriptPath

try {
  await runVectorCases()
  await runRejectCases()
  await runFreshSealRoundtrip()
  const ran = Object.keys(TOOLCHAINS).filter(want)
  console.log(`cross-language vectors ok (${ran.join(', ')})`)
} finally {
  fs.rmSync(tmp, { recursive: true, force: true })
}

function hasBinary (name) {
  const result = spawnSync(process.platform === 'win32' ? 'where' : 'which', [name], {
    stdio: 'ignore',
  })
  return result.status === 0
}

async function runVectorCases () {
  for (const vector of vectors.cases) {
    const args = {
      keyText: vectors.key,
      scope: vector.scope,
      name: vector.name,
      sealed: vector.sealed,
      plaintext: vector.plaintext,
      label: `accept ${vector.id}`,
    }
    if (want('js')) await checkJavaScriptAccept(args)
    if (want('python')) checkPythonAccept(args)
    if (want('go')) checkGoAccept(args)
    if (want('deno')) checkDenoAccept(args)
  }
}

async function runRejectCases () {
  for (const vector of vectors.rejects) {
    const args = {
      keyText: vectors.key,
      scope: vector.scope,
      name: vector.name,
      sealed: vector.sealed,
      reason: vector.reason,
      label: `reject ${vector.id}`,
    }
    if (want('js')) await checkJavaScriptReject(args)
    if (want('python')) checkPythonReject(args)
    if (want('go')) checkGoReject(args)
    if (want('deno')) checkDenoReject(args)
  }
}

async function runFreshSealRoundtrip () {
  const bin = process.env.DOTSEAL_BIN ?? path.join(repo, 'target', 'debug', process.platform === 'win32' ? 'dotseal.exe' : 'dotseal')
  if (!process.env.DOTSEAL_BIN) {
    run('cargo', ['build', '--locked'], { cwd: repo })
  }
  const scope = 'roundtrip'
  const name = 'ROUNDTRIP_SECRET'
  const plaintext = `random:${crypto.randomBytes(16).toString('hex')}\nutf8: héllo 🌍`
  const key = crypto.randomBytes(32)
  const keyText = key.toString('base64url')
  const keyFile = path.join(tmp, 'masterkey.roundtrip')
  fs.writeFileSync(keyFile, `${keyText}\n`, { mode: 0o600 })

  const sealedOutput = run(bin, [
    '-s', scope, '--key-file', keyFile, 'set', tmp, name, '--value', plaintext,
  ]).stdout.trim()
  const sealed = sealedOutput.slice(sealedOutput.indexOf('=') + 1)
  const args = { keyText, scope, name, sealed, plaintext, label: `fresh-seal ${name}` }
  if (want('js')) await checkJavaScriptAccept(args)
  if (want('python')) checkPythonAccept(args)
  if (want('go')) checkGoAccept(args)
  if (want('deno')) checkDenoAccept(args)
}

function jsLoaderModule () {
  jsLoaderPromise ??= import(pathToFileURL(path.join(repo, 'packages/js/src/index.js')).href)
  return jsLoaderPromise
}

async function checkJavaScriptAccept ({ keyText, scope, name, sealed, plaintext, label }) {
  const loader = await jsLoaderModule()
  const got = loader.decryptValue(sealed, { key: keyText, scope, name })
  if (got !== plaintext) throw new Error(`[${label}] JS mismatch: ${JSON.stringify(got)}`)
}

async function checkJavaScriptReject ({ keyText, scope, name, sealed, label }) {
  const loader = await jsLoaderModule()
  let threw = false
  try {
    loader.decryptValue(sealed, { key: keyText, scope, name })
  } catch {
    threw = true
  }
  if (!threw) throw new Error(`[${label}] JS unexpectedly accepted`)
}

function pythonScript (mode) {
  if (mode === 'accept') {
    return `
import sys
from dotseal_env import decrypt_value
key, scope, name, sealed, plaintext = sys.argv[1:]
got = decrypt_value(sealed, key=key, scope=scope, name=name)
if got != plaintext:
    raise SystemExit(f"Python mismatch: {got!r}")
`
  }
  return `
import sys
from dotseal_env import decrypt_value
key, scope, name, sealed = sys.argv[1:]
try:
    decrypt_value(sealed, key=key, scope=scope, name=name)
except Exception:
    raise SystemExit(0)
raise SystemExit("Python unexpectedly accepted")
`
}

function checkPythonAccept ({ keyText, scope, name, sealed, plaintext, label }) {
  runWithLabel(label, 'python3', ['-c', pythonScript('accept'), keyText, scope, name, sealed, plaintext], {
    env: { ...process.env, PYTHONPATH: path.join(repo, 'packages/python') },
  })
}

function checkPythonReject ({ keyText, scope, name, sealed, label }) {
  runWithLabel(label, 'python3', ['-c', pythonScript('reject'), keyText, scope, name, sealed], {
    env: { ...process.env, PYTHONPATH: path.join(repo, 'packages/python') },
  })
}

function ensureGoModule () {
  if (goDir) return goDir
  goDir = path.join(tmp, 'go')
  fs.mkdirSync(goDir)
  fs.writeFileSync(path.join(goDir, 'go.mod'), `module dotseal-cross

go 1.22

require github.com/clbrge/dotseal/packages/go v0.0.0

replace github.com/clbrge/dotseal/packages/go => ${path.join(repo, 'packages/go')}
`)
  fs.writeFileSync(path.join(goDir, 'main.go'), `package main

import (
  "fmt"
  "os"

  "github.com/clbrge/dotseal/packages/go/dotseal"
)

func main() {
  mode := os.Args[1]
  key, err := dotseal.ParseKey(os.Args[2])
  if err != nil { panic(err) }
  got, derr := dotseal.DecryptValue(os.Args[5], key, os.Args[3], os.Args[4])
  if mode == "accept" {
    if derr != nil { panic(derr) }
    if got != os.Args[6] { panic(fmt.Sprintf("Go mismatch: %q", got)) }
  } else {
    if derr == nil { panic("Go unexpectedly accepted") }
  }
}
`)
  return goDir
}

function checkGoAccept ({ keyText, scope, name, sealed, plaintext, label }) {
  runWithLabel(label, 'go', ['run', '.', 'accept', keyText, scope, name, sealed, plaintext], { cwd: ensureGoModule() })
}

function checkGoReject ({ keyText, scope, name, sealed, label }) {
  runWithLabel(label, 'go', ['run', '.', 'reject', keyText, scope, name, sealed], { cwd: ensureGoModule() })
}

function denoScript () {
  const moduleUrl = pathToFileURL(path.join(repo, 'packages/deno/mod.ts')).href
  return `import { decryptValue } from ${JSON.stringify(moduleUrl)};

const [mode, key, scope, name, sealed, plaintext] = Deno.args;
if (mode === "accept") {
  const got = await decryptValue(sealed, { key, scope, name });
  if (got !== plaintext) throw new Error(\`Deno mismatch: \${JSON.stringify(got)}\`);
} else {
  let threw = false;
  try { await decryptValue(sealed, { key, scope, name }); } catch { threw = true; }
  if (!threw) throw new Error("Deno unexpectedly accepted");
}
`
}

function ensureDenoScript () {
  if (denoScriptPath) return denoScriptPath
  denoScriptPath = path.join(tmp, 'deno-vector.ts')
  fs.writeFileSync(denoScriptPath, denoScript())
  return denoScriptPath
}

function checkDenoAccept ({ keyText, scope, name, sealed, plaintext, label }) {
  runWithLabel(label, 'deno', ['run', '--allow-read', ensureDenoScript(), 'accept', keyText, scope, name, sealed, plaintext])
}

function checkDenoReject ({ keyText, scope, name, sealed, label }) {
  runWithLabel(label, 'deno', ['run', '--allow-read', ensureDenoScript(), 'reject', keyText, scope, name, sealed])
}

function runWithLabel (label, command, args, options = {}) {
  try {
    return run(command, args, options)
  } catch (err) {
    err.message = `[${label}] ${err.message}`
    throw err
  }
}

function run (command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repo,
    env: options.env ?? process.env,
    encoding: 'utf8',
  })
  if (result.error) {
    throw new Error(`${command} ${args.join(' ')} failed: ${result.error.message}`)
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with ${result.status}
stdout:
${result.stdout ?? ''}
stderr:
${result.stderr ?? ''}`)
  }
  return result
}
