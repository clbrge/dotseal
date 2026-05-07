import json
from pathlib import Path

import pytest

from dotseal_env import decrypt_env, decrypt_value, parse_env, parse_key


VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "test-vectors" / "v1.json").read_text()
)
PRIMARY = VECTORS["cases"][0]


def test_decrypts_v1_vectors():
    for vector in VECTORS["cases"]:
        assert decrypt_value(
            vector["sealed"],
            key=parse_key(VECTORS["key"]),
            scope=vector["scope"],
            name=vector["name"],
        ) == vector["plaintext"]


def test_rejects_invalid_vectors():
    key = parse_key(VECTORS["key"])
    for vector in VECTORS["rejects"]:
        with pytest.raises(Exception):
            decrypt_value(
                vector["sealed"],
                key=key,
                scope=vector["scope"],
                name=vector["name"],
            )


def test_accepts_padded_base64url_key_and_payload():
    assert decrypt_value(
        f"{PRIMARY['sealed']}==",
        key=parse_key(f"{VECTORS['key']}="),
        scope=PRIMARY["scope"],
        name=PRIMARY["name"],
    ) == PRIMARY["plaintext"]


def test_parses_and_decrypts_env_objects():
    env = parse_env(f"{PRIMARY['name']}={PRIMARY['sealed']}\nPLAIN=value\n")
    assert decrypt_env(env, key=VECTORS["key"], scope=PRIMARY["scope"]) == {
        PRIMARY["name"]: PRIMARY["plaintext"],
        "PLAIN": "value",
    }


def test_parses_quoted_dotenv_values():
    env = parse_env(
        "PLAIN= value \nDOUBLE=\" hello world \"\nSINGLE=' keep spaces '\nESCAPED=\"line\\nnext\\t\\\"q\\\"\"\n"
    )
    assert env == {
        "PLAIN": "value",
        "DOUBLE": " hello world ",
        "SINGLE": " keep spaces ",
        "ESCAPED": "line\nnext\t\"q\"",
    }
