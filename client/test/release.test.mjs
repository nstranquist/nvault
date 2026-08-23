import test from "node:test";
import assert from "node:assert/strict";
import { distTagForVersion } from "../scripts/npm-dist-tag.mjs";

test("stable npm releases use latest", () => {
  assert.equal(distTagForVersion("1.2.3"), "latest");
});

test("prerelease npm releases do not replace latest", () => {
  assert.equal(distTagForVersion("0.2.0-alpha.1"), "next");
  assert.equal(distTagForVersion("1.0.0-rc.2"), "next");
});

test("invalid versions fail closed", () => {
  assert.throws(() => distTagForVersion("v1.2"), /Invalid Semantic Versioning/);
});
