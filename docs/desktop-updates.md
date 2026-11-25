# Desktop updates

The desktop app uses Tauri's signed updater. A release-only configuration points the app at
`https://downloads.aifree.sg/desktop/stable.json`. The app keeps the public verification key in
the signed executable and verifies every downloaded update before it installs anything.

## Release prerequisites

The following are external release inputs and are intentionally absent from the repository:

1. `TAURI_SIGNING_PRIVATE_KEY` holds the durable private key for all desktop updater releases.
   Store it as a protected GitHub Actions secret. Losing it prevents future releases from updating
   installed clients.
2. `AIFREE_UPDATER_PUBLIC_KEY` holds the matching public key. The release workflow embeds it in
   each release build. It is separate from the private key and may be stored as a protected secret
   for release configuration.
3. `downloads.aifree.sg` serves immutable package files at
   `/desktop/<version>/<target>/<file>` and the current manifest at `/desktop/stable.json` over HTTPS.
4. macOS builds need an Apple Developer signing identity and notarization. Windows builds need a
   Windows code-signing certificate. Linux packages rely on the updater signature.

The existing 0.1.0 application did not contain an updater. Customers need a one-time manual
installation of an updater-capable release before later releases can update themselves.

## Publishing

Run **desktop-release** on `main` with a new SemVer version. The workflow builds each supported
platform, bundles the CLI helper and sing-box with the application, signs the updater package, and
creates `stable.json`. The manifest job verifies that every platform has exactly one package and
signature.

Download `aifree-stable-update-<version>`, upload the versioned package files first, and replace
`stable.json` only after each package URL returns successfully. The manifest references AppImage on
Linux, NSIS on Windows, and a macOS application-bundle archive. Windows uses Tauri's passive
installer mode and may show installer progress while it applies the update.

## Client behavior

The app checks for a signed update at launch and when the window opens. It queues a valid update,
then enables installation after the proxy tunnel disconnects. The install command checks the tunnel
state again immediately before activation. A failed download, signature verification failure, or
installation error leaves the current app in place. The user can dismiss an update and receive it
again on the next launch.

Before replacing the stable manifest, test it through a separate update feed. Confirm that an
updater-capable earlier build detects the new manifest, installs it after disconnecting, restarts,
and reconnects with the existing device session. Repeat this verification for macOS, Windows, and
Linux.

## Validation status for this change

The development check covers the macOS Apple Silicon Rust test suite, the updater-enabled compile
path with a generated release configuration, and fixture validation for the release configuration
and five-platform manifest. It does not include an installed-package update because no durable
release key or update feed is configured yet. Windows x64, Windows ARM64, Linux x64, and Linux
ARM64 installer and restart behavior remain release-acceptance checks. In particular, a Windows
ARM64 cross-build or artifact is not evidence that the installer completed on Windows ARM64.
