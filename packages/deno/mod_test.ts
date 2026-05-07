import { decryptEnv, decryptValue, parseEnv, parseKey } from "./mod.ts";

type Vector = {
  id: string;
  scope: string;
  name: string;
  plaintext: string;
  sealed: string;
};

type VectorFile = {
  key: string;
  cases: Vector[];
  rejects: Vector[];
};

const vectors = JSON.parse(
  Deno.readTextFileSync(new URL("../../test-vectors/v1.json", import.meta.url)),
) as VectorFile;
const primary = vectors.cases[0];

for (const vector of vectors.cases) {
  Deno.test(`decrypts v1 test vector: ${vector.id}`, async () => {
    assertEquals(
      await decryptValue(vector.sealed, {
        key: parseKey(vectors.key),
        scope: vector.scope,
        name: vector.name,
      }),
      vector.plaintext,
    );
  });
}

for (const vector of vectors.rejects) {
  Deno.test(`rejects v1 test vector: ${vector.id}`, async () => {
    await assertRejects(() => decryptValue(vector.sealed, {
      key: vectors.key,
      scope: vector.scope,
      name: vector.name,
    }));
  });
}

Deno.test("accepts padded base64url key and payload", async () => {
  assertEquals(
    await decryptValue(`${primary.sealed}==`, {
      key: parseKey(`${vectors.key}=`),
      scope: primary.scope,
      name: primary.name,
    }),
    primary.plaintext,
  );
});

Deno.test("parses and decrypts env objects", async () => {
  const env = parseEnv(`${primary.name}=${primary.sealed}\nPLAIN=value\n`);
  assertEquals({ ...await decryptEnv(env, {
    key: vectors.key,
    scope: primary.scope,
  }) }, {
    [primary.name]: primary.plaintext,
    PLAIN: "value",
  });
});

Deno.test("parses quoted dotenv values", () => {
  const env = parseEnv("PLAIN= value \nDOUBLE=\" hello world \"\nSINGLE=' keep spaces '\nESCAPED=\"line\\nnext\\t\\\"q\\\"\"\n");
  assertEquals({ ...env }, {
    PLAIN: "value",
    DOUBLE: " hello world ",
    SINGLE: " keep spaces ",
    ESCAPED: "line\nnext\t\"q\"",
  });
});

Deno.test("parseEnv denies prototype pollution keys", () => {
  const env = parseEnv("__proto__=x\nconstructor=y\nprototype=z\nSAFE=value\n");
  assertEquals(Object.getPrototypeOf(env), null);
  assertEquals(Object.keys(env), ["SAFE"]);
  assertEquals(env.SAFE, "value");
});

function assertEquals(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`assertEquals failed: ${JSON.stringify(actual)} !== ${JSON.stringify(expected)}`);
  }
}

async function assertRejects(fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch {
    return;
  }
  throw new Error("assertRejects failed: promise resolved");
}
