import test from "node:test";
import assert from "node:assert/strict";
import {
  MAX_HOSTED_ENVELOPE_BYTES,
  NvaultClient,
} from "../dist/index.js";

const baseOptions = {
  baseUrl: "https://api.example.test/http",
  org: "org_123456789",
  env: "env_123456789",
  token: `nvk_${"A".repeat(43)}`,
};

function json(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

test("pull follows bounded cursor pages", async () => {
  const calls = [];
  const fetch = async (input) => {
    calls.push(String(input));
    return calls.length === 1
      ? json({
          items: [
            {
              key: "FIRST",
              kind: "secret",
              ciphertext: "ciphertext-1",
              version: 1,
            },
          ],
          recipient_revision: 4,
          cursor: "cursor-2",
          done: false,
        })
      : json({
          items: [
            {
              key: "SECOND",
              kind: "param",
              ciphertext: "ciphertext-2",
              version: 2,
            },
          ],
          recipient_revision: 4,
          cursor: null,
          done: true,
        });
  };
  const client = new NvaultClient({ ...baseOptions, fetch });
  const items = await client.pull();
  assert.deepEqual(
    items.map((item) => item.key),
    ["FIRST", "SECOND"],
  );
  assert.equal(calls.length, 2);
  assert.match(calls[0], /limit=10/);
  assert.match(calls[1], /cursor=cursor-2/);
});

test("policy returns bounded public encryption metadata", async () => {
  let requested = "";
  const client = new NvaultClient({
    ...baseOptions,
    fetch: async (input) => {
      requested = String(input);
      return json({
        recipient_revision: 7,
        recipients: [
          {
            id: `member-${"B".repeat(42)}A`,
            public_key: `nvpub_${"B".repeat(42)}A`,
          },
          {
            id: `org-recovery-${"R".repeat(42)}A`,
            public_key: `nvpub_${"R".repeat(42)}A`,
          },
        ],
      });
    },
  });
  const policy = await client.policy();
  assert.equal(policy.recipient_revision, 7);
  assert.equal(policy.recipients.length, 2);
  assert.match(requested, /\/sync\/policy\?/);
});

test("pull rejects malformed and repeated cursors", async () => {
  const malformed = new NvaultClient({
    ...baseOptions,
    fetch: async () => json({ items: [], cursor: null, done: false }),
  });
  await assert.rejects(() => malformed.pull(), /invalid pull response/);

  const repeated = new NvaultClient({
    ...baseOptions,
    fetch: async () =>
      json({
        items: [],
        recipient_revision: 4,
        cursor: "same-cursor",
        done: false,
      }),
  });
  await assert.rejects(() => repeated.pull(), /repeated pull cursor/);
});

test("pull rejects a recipient-policy change between pages", async () => {
  let calls = 0;
  const client = new NvaultClient({
    ...baseOptions,
    fetch: async () => {
      calls += 1;
      return json({
        items: [],
        recipient_revision: calls,
        cursor: calls === 1 ? "next" : null,
        done: calls !== 1,
      });
    },
  });
  await assert.rejects(() => client.pull(), /recipient policy changed/);
});

test("pull rejects a duplicate key between pages", async () => {
  let calls = 0;
  const client = new NvaultClient({
    ...baseOptions,
    fetch: async () => {
      calls += 1;
      return json({
        items: [
          {
            key: "DUPLICATE",
            kind: "secret",
            ciphertext: `ciphertext-${calls}`,
            version: calls,
          },
        ],
        recipient_revision: 1,
        cursor: calls === 1 ? "next" : null,
        done: calls !== 1,
      });
    },
  });
  await assert.rejects(() => client.pull(), /duplicate key/);
});

test("push validates the batch and narrows the response", async () => {
  let sent;
  const client = new NvaultClient({
    ...baseOptions,
    fetch: async (_input, init) => {
      sent = JSON.parse(String(init?.body));
      return json({ results: [{ key: "TOKEN", version: 3 }] });
    },
  });
  assert.deepEqual(
    await client.push(
      [
        {
          key: "TOKEN",
          kind: "secret",
          ciphertext: "ciphertext",
          expected_version: 2,
        },
      ],
      { recipientRevision: 4 },
    ),
    { results: [{ key: "TOKEN", version: 3 }] },
  );
  assert.equal(sent.items[0].expected_version, 2);
  assert.equal(sent.recipient_revision, 4);
  await assert.rejects(
    () =>
      client.push(
        [
          {
            key: "TOKEN",
            kind: "secret",
            ciphertext: "one",
            expected_version: 0,
          },
          {
            key: "TOKEN",
            kind: "secret",
            ciphertext: "two",
            expected_version: 0,
          },
        ],
        { recipientRevision: 4 },
      ),
    /duplicate key/,
  );
  await assert.rejects(
    () =>
      client.push([
        {
          key: "TOKEN",
          kind: "secret",
          ciphertext: "one",
          expected_version: 0,
        },
      ]),
    /recipientRevision/,
  );

  const mismatched = new NvaultClient({
    ...baseOptions,
    fetch: async () => json({ results: [{ key: "OTHER", version: 1 }] }),
  });
  await assert.rejects(
    () =>
      mismatched.push(
        [
          {
            key: "TOKEN",
            kind: "secret",
            ciphertext: "one",
            expected_version: 0,
          },
        ],
        { recipientRevision: 4 },
      ),
    /invalid push result/,
  );
});

test("versions and delete use compare-and-swap metadata", async () => {
  const requests = [];
  const client = new NvaultClient({
    ...baseOptions,
    fetch: async (input, init) => {
      requests.push({
        url: String(input),
        body: JSON.parse(String(init?.body)),
      });
      if (String(input).endsWith("/sync/versions")) {
        return json({
          results: [
            { key: "TOKEN", version: 3, deleted: false },
            { key: "NEW", version: 0, deleted: false },
          ],
        });
      }
      return json({ key: "TOKEN", version: 4, deleted: true });
    },
  });
  const versions = await client.versions(["TOKEN", "NEW"]);
  assert.equal(versions.results[0].version, 3);
  const deleted = await client.delete("TOKEN", 3);
  assert.deepEqual(deleted, { key: "TOKEN", version: 4, deleted: true });
  assert.equal(requests[0].body.keys.length, 2);
  assert.equal(requests[1].body.expected_version, 3);
  await assert.rejects(() => client.versions(["TOKEN", "TOKEN"]), /duplicate/);
  await assert.rejects(() => client.delete("TOKEN", -1), /expectedVersion/);
});

test("requests reject redirects and sanitize remote error text", async () => {
  let redirect;
  const client = new NvaultClient({
    ...baseOptions,
    fetch: async (_input, init) => {
      redirect = init?.redirect;
      return new Response("bad\n\u001b[31mresponse", { status: 400 });
    },
  });
  await assert.rejects(
    () => client.pullPage(),
    (error) =>
      /bad response/.test(error.message) && !error.message.includes("\n"),
  );
  assert.equal(redirect, "error");
});

test("remote cleartext HTTP needs explicit authorization", () => {
  assert.throws(
    () =>
      new NvaultClient({
        ...baseOptions,
        baseUrl: "http://api.example.test",
        fetch: async () => json({ items: [], cursor: null, done: true }),
      }),
    /HTTPS outside local development/,
  );
  assert.doesNotThrow(
    () =>
      new NvaultClient({
        ...baseOptions,
        baseUrl: "http://127.0.0.1:3211/http",
        fetch: async () => json({ items: [], cursor: null, done: true }),
      }),
  );
  assert.doesNotThrow(
    () =>
      new NvaultClient({
        ...baseOptions,
        baseUrl: "http://api.example.test",
        allowInsecureHttp: true,
        fetch: async () => json({ items: [], cursor: null, done: true }),
      }),
  );
});

test("constructor rejects malformed tenant and token configuration", () => {
  assert.throws(
    () =>
      new NvaultClient({
        ...baseOptions,
        org: "../other",
        fetch: async () => json({ items: [], cursor: null, done: true }),
      }),
    /org is invalid/,
  );
  assert.throws(
    () =>
      new NvaultClient({
        ...baseOptions,
        token: "nvk_short",
        fetch: async () => json({ items: [], cursor: null, done: true }),
      }),
    /token is invalid/,
  );
});

test("push rejects an envelope that cannot fit in hosted storage", async () => {
  let called = false;
  const client = new NvaultClient({
    ...baseOptions,
    fetch: async () => {
      called = true;
      return json({ results: [] });
    },
  });
  await assert.rejects(
    () =>
      client.push(
        [
          {
            key: "TOO_LARGE",
            kind: "secret",
            ciphertext: "x".repeat(MAX_HOSTED_ENVELOPE_BYTES + 1),
            expected_version: 0,
          },
        ],
        { recipientRevision: 1 },
      ),
    /invalid/,
  );
  assert.equal(called, false);
});
