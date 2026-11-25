#!/usr/bin/env node

import { readdir, readFile, writeFile } from "node:fs/promises";
import { basename, join, relative } from "node:path";

const [root, version, baseUrl, output, notes = ""] = process.argv.slice(2);
if (!root || !version || !baseUrl || !output) {
  throw new Error("usage: release-manifest.mjs ARTIFACT_DIR VERSION BASE_URL OUTPUT [NOTES]");
}
if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
  throw new Error("version must be SemVer");
}

async function files(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  return (await Promise.all(entries.map(async (entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : [path];
  }))).flat();
}

const targets = {
  "darwin-aarch64": { build: "aarch64-apple-darwin", package: /\.app\.tar\.gz$/ },
  "windows-x86_64": { build: "x86_64-pc-windows-msvc", package: /\.exe$/ },
  "windows-aarch64": { build: "aarch64-pc-windows-msvc", package: /\.exe$/ },
  "linux-x86_64": { build: "x86_64-unknown-linux-gnu", package: /\.AppImage$/ },
  "linux-aarch64": { build: "aarch64-unknown-linux-gnu", package: /\.AppImage$/ },
};
const packages = await files(root);
const platforms = {};
for (const [target, specification] of Object.entries(targets)) {
  const candidates = packages.filter((file) => file.includes(specification.build) && specification.package.test(file));
  if (candidates.length !== 1) throw new Error(`${target} needs exactly one updater package, found ${candidates.length}`);
  const packageFile = candidates[0];
  const signatureFile = `${packageFile}.sig`;
  const signature = (await readFile(signatureFile, "utf8")).trim();
  if (!signature) throw new Error(`${relative(root, signatureFile)} is empty`);
  const name = basename(packageFile);
  platforms[target] = { url: `${baseUrl.replace(/\/$/, "")}/${version}/${target}/${encodeURIComponent(name)}`, signature };
}
await writeFile(output, `${JSON.stringify({ version, notes, platforms }, null, 2)}\n`);
