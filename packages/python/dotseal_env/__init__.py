import base64
import json
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = "v1"
DEFAULT_SCOPE = "default"
NONCE_LEN = 12
KEY_LEN = 32

_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SCOPE_SEAL_PATTERN = re.compile(r"[A-Za-z0-9_.\-]+")
_AAD_INJECTION = re.compile(r"[\n\r]")
_RESERVED_ENV_NAMES = frozenset({"__proto__", "constructor", "prototype"})


def is_safe_env_name(name):
    return (
        isinstance(name, str)
        and bool(_NAME_PATTERN.fullmatch(name))
        and name not in _RESERVED_ENV_NAMES
    )


def is_valid_scope(scope):
    return isinstance(scope, str) and bool(_SCOPE_SEAL_PATTERN.fullmatch(scope))


def is_encrypted_value(value):
    return isinstance(value, str) and value.startswith("enc:")


def parse_key(raw):
    text = raw.decode("utf-8").strip() if isinstance(raw, bytes) else str(raw).strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return bytes.fromhex(text)
    padding = "=" * (-len(text) % 4)
    key = base64.urlsafe_b64decode(text + padding)
    if len(key) != KEY_LEN:
        raise ValueError(f"dotseal key must decode to {KEY_LEN} bytes")
    return key


def decrypt_value(value, *, key, scope, name):
    if not is_encrypted_value(value):
        return value
    if not scope:
        raise ValueError("dotseal decrypt_value requires scope")
    if not name:
        raise ValueError("dotseal decrypt_value requires name")
    if _AAD_INJECTION.search(name):
        raise ValueError("dotseal decrypt_value: invalid name")
    if _AAD_INJECTION.search(scope):
        raise ValueError("dotseal decrypt_value: invalid scope")

    parts = value.split(":", 2)
    if len(parts) != 3 or parts[0] != "enc" or parts[1] != VERSION:
        raise ValueError("unsupported dotseal value")

    payload = _b64url_decode(parts[2])
    if len(payload) <= NONCE_LEN:
        raise ValueError(f"dotseal value for {name} is too short")
    nonce = payload[:NONCE_LEN]
    ciphertext = payload[NONCE_LEN:]
    key_bytes = key if isinstance(key, bytes) else parse_key(key)
    plaintext = AESGCM(key_bytes).decrypt(nonce, ciphertext, _aad(scope, name))
    return plaintext.decode("utf-8")


def decrypt_env(env, *, key, scope):
    return {
        name: decrypt_value(value, key=key, scope=scope, name=name)
        for name, value in env.items()
    }


def decrypt_tree(value, *, key, scope, path=""):
    if is_encrypted_value(value):
        if not path:
            raise ValueError("dotseal decrypt_tree requires a path for encrypted values")
        return decrypt_value(value, key=key, scope=scope, name=path)
    if isinstance(value, list):
        return [
            decrypt_tree(entry, key=key, scope=scope, path=_append_path_segment(path, index))
            for index, entry in enumerate(value)
        ]
    if isinstance(value, dict):
        return {
            name: decrypt_tree(entry, key=key, scope=scope, path=_append_path_segment(path, name))
            for name, entry in value.items()
        }
    return value


def _append_path_segment(existing, segment):
    encoded = json.dumps(segment, ensure_ascii=False)
    return f"{existing}.{encoded}" if existing else encoded


def parse_env(content):
    env = {}
    text = str(content)
    if text.startswith("\ufeff"):
        text = text[1:]
    for line in text.splitlines():
        trimmed = line.lstrip(" \t\ufeff")
        if not trimmed or trimmed.startswith("#"):
            continue
        rest = _strip_export_prefix(trimmed) or trimmed
        if "=" not in rest:
            continue
        name, value = rest.split("=", 1)
        name = name.strip()
        if _NAME_PATTERN.fullmatch(name):
            env[name] = parse_env_value(value)
    return env


def _strip_export_prefix(line):
    if not line.startswith("export"):
        return None
    after = line[6:]
    if not after or after[0] not in (" ", "\t"):
        return None
    i = 0
    while i < len(after) and after[i] in (" ", "\t"):
        i += 1
    return after[i:]


def parse_env_value(raw):
    trimmed_start = str(raw).lstrip(" \t\r\n\ufeff")
    if trimmed_start.startswith('"'):
        rest = trimmed_start[1:]
        end = _find_double_quote_end(rest)
        if end != -1:
            return _unescape_double_quoted(rest[:end])
    elif trimmed_start.startswith("'"):
        end = trimmed_start.find("'", 1)
        if end != -1:
            return trimmed_start[1:end]
    return _strip_inline_comment(trimmed_start).rstrip(" \t\r\n")


def _strip_inline_comment(value):
    for i, ch in enumerate(value):
        if ch == "#" and (i == 0 or value[i - 1] in (" ", "\t")):
            return value[:i]
    return value


def _find_double_quote_end(rest):
    i = 0
    while i < len(rest):
        if rest[i] == "\\" and i + 1 < len(rest):
            i += 2
            continue
        if rest[i] == '"':
            return i
        i += 1
    return -1


def _aad(scope, name):
    # AAD binding: `dotseal:v1\nscope=<scope>\nname=<NAME>\n`. See FORMAT.md
    # § Algorithm. `scope` and `name` MUST be validated against the
    # AAD-injection charset (no \n/\r) before reaching this — `decrypt_value`
    # does that above.
    return f"dotseal:{VERSION}\nscope={scope}\nname={name}\n".encode("utf-8")


def _b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _unescape_double_quoted(value):
    out = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= len(value):
            out.append("\\")
            break
        nxt = value[i]
        if nxt == "n":
            out.append("\n")
        elif nxt == "r":
            out.append("\r")
        elif nxt == "t":
            out.append("\t")
        elif nxt in ['"', "\\"]:
            out.append(nxt)
        else:
            out.append("\\" + nxt)
        i += 1
    return "".join(out)
