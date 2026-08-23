import test from "node:test";
import assert from "node:assert/strict";
import { cloudAAD } from "../dist/index.js";

test("cloudAAD matches the Go and hosted slot contract", () => {
  assert.equal(
    cloudAAD("org_123", "env_456", "global", "DB_URL"),
    "org_123/env_456/global/DB_URL",
  );
  assert.throws(() => cloudAAD("org/other", "env", "global", "KEY"));
  assert.throws(() => cloudAAD("org", "env", "bad/scope", "KEY"));
  assert.throws(() => cloudAAD("org", "env", "global", "bad/key"));
});
