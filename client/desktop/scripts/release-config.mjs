#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";

const [source, output, version, publicKey, endpoint] = process.argv.slice(2);
if (!source || !output || !version || !publicKey || !endpoint) {
  throw new Error("usage: release-config.mjs SOURCE OUTPUT VERSION PUBLIC_KEY ENDPOINT");
}
if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
  throw new Error("version must be SemVer");
}
if (!publicKey.startsWith("dW50cnVzdGVkIGNvbW1lbnQ6")) {
  throw new Error("public key is not a Tauri updater key");
}
const config = JSON.parse(await readFile(source, "utf8"));
config.version = version;
config.bundle = { ...config.bundle, createUpdaterArtifacts: true };
config.plugins = {
  ...config.plugins,
  updater: {
    pubkey: publicKey,
    endpoints: [endpoint],
    requireSignedVersion: true,
    windows: { installMode: "passive" },
  },
};
await writeFile(output, `${JSON.stringify(config, null, 2)}\n`);
