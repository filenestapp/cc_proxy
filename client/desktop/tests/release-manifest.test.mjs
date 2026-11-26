import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const script = new URL("../scripts/release-manifest.mjs", import.meta.url);

async function addArtifact(root, target, name, signed = true) {
  const dir = join(root, `aifree-update-${target}`, "bundle", target);
  await mkdir(dir, { recursive: true });
  const file = join(dir, name);
  await writeFile(file, name);
  if (signed) await writeFile(`${file}.sig`, `signature-${target}\n`);
}

test("release manifest maps both macOS updater keys to one universal archive", async () => {
  const root = await mkdtemp(join(tmpdir(), "aifree-manifest-"));
  await addArtifact(root, "universal-apple-darwin", "aifree.app.tar.gz");
  await addArtifact(root, "universal-apple-darwin", "aifree_1.2.3_universal.dmg", false);
  await addArtifact(root, "x86_64-pc-windows-msvc", "aifree_1.2.3_x64-setup.exe");
  await addArtifact(root, "aarch64-pc-windows-msvc", "aifree_1.2.3_arm64-setup.exe");
  for (const arch of ["x86_64", "aarch64"]) {
    await addArtifact(root, `${arch}-unknown-linux-gnu`, `aifree_1.2.3_${arch}.AppImage`);
    await addArtifact(root, `${arch}-unknown-linux-gnu`, `aifree_1.2.3_${arch}.deb`);
  }
  const output = join(root, "stable.json");
  execFileSync(process.execPath, [script.pathname, root, "1.2.3", "https://downloads.example/desktop", output], { stdio: "pipe" });
  const manifest = JSON.parse(await readFile(output, "utf8"));

  assert.equal(manifest.platforms["darwin-aarch64"].url, manifest.platforms["darwin-x86_64"].url);
  assert.equal(manifest.platforms["darwin-aarch64"].signature, "signature-universal-apple-darwin");
  assert.match(manifest.installers["darwin-universal"], /darwin-universal\/aifree_1\.2\.3_universal\.dmg$/);
  assert.deepEqual(Object.keys(manifest.installers).sort(), [
    "darwin-universal", "linux-aarch64-appimage", "linux-aarch64-deb", "linux-x86_64-appimage",
    "linux-x86_64-deb", "windows-aarch64", "windows-x86_64",
  ]);
});
