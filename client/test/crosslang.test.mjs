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

import { generateIdentity, sealEnvelope, openEnvelope } from "../dist/index.js";

const privToB64 = (u8) => Buffer.from(u8).toString("base64");

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..", "..", "..");
const nicosDev = join(repoRoot, "nicos-dev");

let nvaultBin;
let goHome; // temp HOME so `nvault` recipients.json + any keychain noise is isolated

before(() => {
  // Resolve the nvault binary: honor NVAULT_BIN, else build it.
  if (process.env.NVAULT_BIN) {
    nvaultBin = process.env.NVAULT_BIN;
  } else {
    nvaultBin = join(mkdtempSync(join(tmpdir(), "nvault-bin-")), "nvault");
    execFileSync("go", ["build", "-o", nvaultBin, "./cmd/nvault/"], {
      cwd: nicosDev,
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

test("Go nvault encrypt → TS openEnvelope", async () => {
  const id = await generateIdentity();

  // Register the TS public key as a recipient (file-based, headless).
  nvault(["key", "add-recipient", "tsuser", id.publicKey]);

  // Go seals to it (encrypt needs only recipients, never the Keychain).
  const envelopeJSON = nvault(["encrypt", "--aad", AAD], { input: PLAINTEXT });
  const envelope = JSON.parse(envelopeJSON);

  assert.equal(envelope.v, "nvault.enc.v1", "envelope version");
  assert.ok(!envelopeJSON.includes(PLAINTEXT), "ciphertext must not contain plaintext");

  const opened = await openEnvelope(envelope, id);
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
  const plaintext = nvault(["decrypt"], {
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
      nvault(["decrypt"], {
        input: JSON.stringify(envelope),
        env: { NVAULT_IDENTITY_KEY: privB64 },
      }),
    "Go must reject an envelope whose AAD was changed",
  );
});

test("wrong key cannot decrypt (TS side)", async () => {
  const a = await generateIdentity();
  const b = await generateIdentity();
  const envelope = await sealEnvelope(
    new TextEncoder().encode(PLAINTEXT),
    [{ id: "a", public_key: a.publicKey }],
    "",
  );
  await assert.rejects(() => openEnvelope(envelope, b), "non-recipient must not decrypt");
});
