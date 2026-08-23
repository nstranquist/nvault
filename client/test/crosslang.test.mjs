// Cross-language wire-compatibility test: proves the TypeScript SDK
// (@nvault/client) and the Go reference implementation (nvault / internal/vault/
// crypto) produce and consume the SAME envelope format (nvault.enc.v1).
//
//   Go  → TS : `nvault encrypt` seals to a TS-generated public key; openEnvelope
//             decrypts it in Node.
//   TS  → Go : sealEnvelope produces an envelope; `nvault decrypt` (with the
//             matching private key via NVAULT_IDENTITY_KEY) decrypts it.
//
// This is the contract that lets a secret sealed in the browser open in the CLI
// and vice-versa. Run with: pnpm test (builds dist first).
//
// NOTE: we import ONLY through the compiled SDK (../dist), never directly from
// "libsodium-wrappers". libsodium-wrappers@0.7.x ships a broken ESM build (its
// .mjs imports a libsodium.mjs it never publishes), so a static `import sodium
// from "libsodium-wrappers"` in this .mjs would crash. The SDK is compiled to
// CommonJS, so its internal `require("libsodium-wrappers")` resolves the
// package's working CJS entry. Base64 here is Node's Buffer (this test is
// Node-only).
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  decodePublicKey,
  encodePrivateKey,
  generateIdentity,
  identityFromPrivateKey,
  openEnvelope,
  parseEnvelopeJSON,
  rewrapEnvelope,
  sealEnvelope,
} from "../dist/index.js";

const privToB64 = (u8) => Buffer.from(u8).toString("base64");

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..", "..");

let nvaultBin;
let goHome; // temp HOME so `nvault` recipients.json + any keychain noise is isolated

before(() => {
  // Resolve the nvault binary: honor NVAULT_BIN, else build it.
  if (process.env.NVAULT_BIN) {
    nvaultBin = process.env.NVAULT_BIN;
  } else {
    nvaultBin = join(mkdtempSync(join(tmpdir(), "nvault-bin-")), "nvault");
    execFileSync("go", ["build", "-o", nvaultBin, "./cmd/nvault/"], {
	  cwd: repoRoot,
      stdio: "inherit",
    });
  }
  goHome = mkdtempSync(join(tmpdir(), "nvault-home-"));
});

// nvault runs the CLI with an isolated HOME and optional extra env + stdin.
function nvault(args, { input, env } = {}) {
  return execFileSync(nvaultBin, args, {
    input,
    encoding: "utf8",
    env: { ...process.env, HOME: goHome, ...env },
  });
}

const PLAINTEXT = "super-secret-cross-lang-value-🔐";
const AAD = "org_x/env_y/global/DB_URL";

test("nvpriv backup restores the same identity", async () => {
  const original = await generateIdentity();
  const restored = await identityFromPrivateKey(encodePrivateKey(original.privateKey));
  assert.equal(restored.publicKey, original.publicKey);
  assert.deepEqual(restored.privateKey, original.privateKey);
});

test("Go nvault encrypt → TS openEnvelope", async () => {
  const id = await generateIdentity();

  // Go seals directly to the TS public key. No private key is needed.
  const envelopeJSON = nvault(["encrypt", "--recipient", `tsuser=${id.publicKey}`, "--aad", AAD], { input: PLAINTEXT });
  const envelope = JSON.parse(envelopeJSON);

  assert.equal(envelope.v, "nvault.enc.v1", "envelope version");
  assert.ok(!envelopeJSON.includes(PLAINTEXT), "ciphertext must not contain plaintext");

  const opened = await openEnvelope(envelope, id, AAD);
  assert.equal(new TextDecoder().decode(opened), PLAINTEXT, "TS opened Go-sealed envelope");
});

test("TS sealEnvelope → Go nvault decrypt", async () => {
  const id = await generateIdentity();
  const privB64 = privToB64(id.privateKey);

  // TS seals to its own key.
  const envelope = await sealEnvelope(
    new TextEncoder().encode(PLAINTEXT),
    [{ id: "tsuser", public_key: id.publicKey }],
    AAD,
  );

  // Go decrypts it using the matching private key (headless env seam).
  const plaintext = nvault(["decrypt", "--aad", AAD], {
    input: JSON.stringify(envelope),
    env: { NVAULT_IDENTITY_KEY: privB64 },
  });
  assert.equal(plaintext.replace(/\n$/, ""), PLAINTEXT, "Go decrypted TS-sealed envelope");
});

test("AAD mismatch is rejected across languages", async () => {
  const id = await generateIdentity();
  const envelope = await sealEnvelope(
    new TextEncoder().encode(PLAINTEXT),
    [{ id: "tsuser", public_key: id.publicKey }],
    "correct/aad",
  );
  // Tamper the AAD; Go decrypt must fail (AEAD binds the slot).
  envelope.aad = "wrong/aad";
  const privB64 = privToB64(id.privateKey);
  assert.throws(
    () =>
      nvault(["decrypt", "--aad", "correct/aad"], {
        input: JSON.stringify(envelope),
        env: { NVAULT_IDENTITY_KEY: privB64 },
      }),
    "Go must reject an envelope whose AAD was changed",
  );
});

test("whole-envelope relocation is rejected by the TypeScript client", async () => {
  const id = await generateIdentity();
  const envelope = await sealEnvelope(
    new TextEncoder().encode(PLAINTEXT),
    [{ id: "tsuser", public_key: id.publicKey }],
    "org/prod/DB_URL",
  );
  await assert.rejects(
    () => openEnvelope(envelope, id, "org/dev/DB_URL"),
    /does not match expected slot/,
    "a valid envelope from another slot must not open",
  );
});

test("malformed envelopes are rejected before crypto", async () => {
  const id = await generateIdentity();
  const envelope = await sealEnvelope(
    new TextEncoder().encode(PLAINTEXT),
    [{ id: "tsuser", public_key: id.publicKey }],
    AAD,
  );
  for (const mutate of [
    (copy) => { copy.nonce = "AQ=="; },
    (copy) => { copy.ciphertext = "AQ=="; },
    (copy) => { copy.recipients[0].wrapped_key = "AQ=="; },
    (copy) => { copy.recipients.push({ ...copy.recipients[0] }); },
  ]) {
    const copy = structuredClone(envelope);
    mutate(copy);
    await assert.rejects(() => openEnvelope(copy, id, AAD), /invalid envelope/);
  }
});

test("envelope JSON rejects duplicate and unknown fields", async () => {
  const id = await generateIdentity();
  const envelope = await sealEnvelope(
    new TextEncoder().encode(PLAINTEXT),
    [{ id: "tsuser", public_key: id.publicKey }],
    AAD,
  );
  const raw = JSON.stringify(envelope);
  await assert.rejects(
    () => parseEnvelopeJSON(raw.replace("{", '{"v":"nvault.enc.v1",')),
    /duplicate field/,
  );
  await assert.rejects(
    () => parseEnvelopeJSON(JSON.stringify({ ...envelope, unknown: true })),
    /unknown field/,
  );
  assert.deepEqual(await parseEnvelopeJSON(raw), envelope);
});

test("public and private keys require canonical encodings", async () => {
  const id = await generateIdentity();
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const tail = alphabet.indexOf(id.publicKey.at(-1));
  assert.equal(tail % 4, 0);
  const alias = `${id.publicKey.slice(0, -1)}${alphabet[tail + 1]}`;
  assert.throws(() => decodePublicKey(alias), /canonical/);

  const backup = encodePrivateKey(id.privateKey);
  const privateTail = alphabet.indexOf(backup.at(-1));
  assert.equal(privateTail % 4, 0);
  const privateAlias = `${backup.slice(0, -1)}${alphabet[privateTail + 1]}`;
  await assert.rejects(() => identityFromPrivateKey(privateAlias), /canonical/);
});

test("embedded AAD tampering is rejected by authentication", async () => {
  const id = await generateIdentity();
  const envelope = await sealEnvelope(
    new TextEncoder().encode(PLAINTEXT),
    [{ id: "tsuser", public_key: id.publicKey }],
    "slot-a",
  );
  envelope.aad = "slot-b";
  await assert.rejects(() => openEnvelope(envelope, id, "slot-b"));
});

test("wrong key cannot decrypt (TS side)", async () => {
  const a = await generateIdentity();
  const b = await generateIdentity();
  const envelope = await sealEnvelope(
    new TextEncoder().encode(PLAINTEXT),
    [{ id: "a", public_key: a.publicKey }],
    "",
  );
  await assert.rejects(() => openEnvelope(envelope, b, ""), "non-recipient must not decrypt");
});

test("rewrap preserves the encrypted body and rotates recipients", async () => {
  const first = await generateIdentity();
  const removed = await generateIdentity();
  const added = await generateIdentity();
  const envelope = await sealEnvelope(
    new TextEncoder().encode(PLAINTEXT),
    [
      { id: "first", public_key: first.publicKey },
      { id: "removed", public_key: removed.publicKey },
    ],
    AAD,
  );
  const rotated = await rewrapEnvelope(envelope, first, AAD, [
    { id: "first", public_key: first.publicKey },
    { id: "added", public_key: added.publicKey },
  ]);

  assert.equal(rotated.nonce, envelope.nonce);
  assert.equal(rotated.ciphertext, envelope.ciphertext);
  assert.equal(new TextDecoder().decode(await openEnvelope(rotated, added, AAD)), PLAINTEXT);
  await assert.rejects(() => openEnvelope(rotated, removed, AAD));

  const tampered = structuredClone(envelope);
  tampered.ciphertext = `${tampered.ciphertext.slice(0, -4)}AAAA`;
  await assert.rejects(() =>
    rewrapEnvelope(tampered, first, AAD, [
      { id: "added", public_key: added.publicKey },
    ]),
  );
});
