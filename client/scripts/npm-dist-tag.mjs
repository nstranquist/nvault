import { appendFile, readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export function distTagForVersion(version) {
  const match = SEMVER.exec(version);
  if (!match) throw new Error(`Invalid Semantic Versioning value: ${version}`);
  return match[4] ? "next" : "latest";
}

async function main() {
  const manifest = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  );
  if (typeof manifest.version !== "string") {
    throw new Error("client/package.json does not contain a version");
  }
  const ref = process.env.GITHUB_REF_NAME?.replace(/^v/, "");
  if (ref && ref !== manifest.version) {
    throw new Error(
      `Release tag ${ref} does not match package version ${manifest.version}`,
    );
  }
  const tag = distTagForVersion(manifest.version);
  if (process.env.GITHUB_OUTPUT) {
    await appendFile(process.env.GITHUB_OUTPUT, `tag=${tag}\n`, "utf8");
  } else {
    process.stdout.write(`${tag}\n`);
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await main();
}
