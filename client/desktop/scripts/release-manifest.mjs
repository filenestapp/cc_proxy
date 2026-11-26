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
  "darwin-universal": {
    build: "universal-apple-darwin",
    package: /\.app\.tar\.gz$/,
    installer: /\.dmg$/,
    updaterKeys: ["darwin-aarch64", "darwin-x86_64"],
  },
  "windows-x86_64": { build: "x86_64-pc-windows-msvc", package: /\.exe$/ },
  "windows-aarch64": { build: "aarch64-pc-windows-msvc", package: /\.exe$/ },
  "linux-x86_64-appimage": { build: "x86_64-unknown-linux-gnu", package: /\.AppImage$/ },
  "linux-aarch64-appimage": { build: "aarch64-unknown-linux-gnu", package: /\.AppImage$/ },
  "linux-x86_64-deb": { build: "x86_64-unknown-linux-gnu", package: /\.deb$/ },
  "linux-aarch64-deb": { build: "aarch64-unknown-linux-gnu", package: /\.deb$/ },
};
const packages = await files(root);
const platforms = {};
const installers = {};
for (const [target, specification] of Object.entries(targets)) {
  const buildFiles = packages.filter((file) => relative(root, file).includes(specification.build));
  function artifact(pattern, kind) {
    const candidates = buildFiles.filter((file) => pattern.test(file));
    if (candidates.length !== 1) throw new Error(`${target} needs exactly one ${kind}, found ${candidates.length}`);
    return candidates[0];
  }
  const urlFor = (file) => `${baseUrl.replace(/\/$/, "")}/${version}/${target}/${encodeURIComponent(basename(file))}`;
  const packageFile = artifact(specification.package, "updater package");
  const signatureFile = `${packageFile}.sig`;
  const signature = (await readFile(signatureFile, "utf8")).trim();
  if (!signature) throw new Error(`${relative(root, signatureFile)} is empty`);
  for (const key of specification.updaterKeys || [target]) {
    platforms[key] = { url: urlFor(packageFile), signature };
  }
  installers[target] = urlFor(specification.installer ? artifact(specification.installer, "installer") : packageFile);
}
await writeFile(output, `${JSON.stringify({ version, notes, platforms, installers }, null, 2)}\n`);
