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
   Its public R2 bucket CORS policy must permit `GET` from both `https://aifree.sg` and
   `https://app.aifree.sg`; the browser download chooser reads only the public manifest with no
   credentials. Purge the custom-domain cache after changing that policy.
4. macOS builds need an Apple Developer signing identity and notarization. Do not expose the DMG on
   the website or in `stable.json` until the app and all nested helpers have been signed and the
   notarized DMG has passed `stapler validate`. Windows builds use Azure
   Artifact Signing through OIDC in the main-only GitHub `release` environment. The signing principal
   needs the Certificate Profile Signer role on the selected profile. The workflow verifies the
   Windows Authenticode signatures before signing the installer for updates. Linux packages rely on
   the updater signature.

The existing 0.1.0 application did not contain an updater. Customers need a one-time manual
installation of an updater-capable release before later releases can update themselves.

## Publishing

Run **desktop-release** on `main` with a new SemVer version. The workflow builds each supported
platform, bundles the CLI helper and sing-box with the application, signs the updater package, and
creates `stable.json`. macOS is a universal `arm64` + `x86_64` application: the app and all three
helpers are checked for both architectures. The same signed application archive is registered for
both `darwin-aarch64` and `darwin-x86_64` updater keys; its first-install DMG is published as
`darwin-universal`. The manifest job verifies that every platform has exactly one package and
signature. The release configuration sets `requireSignedVersion`, so the updater rejects a package
whose signed version differs from the manifest version. The workflow binds any manually produced
Debian signature to the same release version.

Download `aifree-stable-update-<version>`. If the CI macOS artifacts were built without Developer ID
signing, rebuild the same universal release with the production updater key and Apple signing and
notarization credentials. Replace its DMG, `.app.tar.gz`, and `.sig` together, then rerun
`release-manifest.mjs` against the final artifacts. Do not reuse the manifest or signatures from an
unsigned macOS build. Upload every versioned installer and updater artifact before replacing
`stable.json`, and verify every published object URL, including `installers`, before that replacement.
The manifest references AppImage and Debian packages on Linux, NSIS on Windows, and one universal
macOS application-bundle archive. The release artifact also includes the universal `.dmg` and `.deb`
first-install packages. Windows uses Tauri's passive installer mode and may show installer progress
while it applies the update.

On Linux, Tauri selects the updater payload that matches the installed bundle type. An AppImage
replaces the AppImage. A Debian installation uses `pkexec` to run `dpkg`, so the desktop user may
receive an administrator-credential prompt before the package update completes.

## Client behavior

The app checks for a signed update at launch and when you reopen it from the system tray. If the
app is up to date, its background check runs again after six hours. It queues a valid update,
waits for the window to show the offer, then automatically installs after the proxy tunnel
disconnects. The install command checks the tunnel state and the Later choice again immediately
before activation. Once activation is claimed, a late Later request is rejected rather than racing
the installer. A failed download, signature verification failure, or installation error leaves the
current app in place, clears the stale offer, reports the failure in the window, and retries the
signed manifest with bounded backoff. The user can dismiss an update and receive it again on the
next launch.

Before replacing the stable manifest, test it through a separate update feed. Confirm that an
updater-capable earlier build detects the new manifest, installs it after disconnecting, restarts,
and reconnects with the existing device session. Repeat this verification for macOS, Windows, and
Linux.

## Validation history

The development check covers the macOS Apple Silicon Rust test suite, the updater-enabled compile
path with a generated release configuration, and fixture validation for the release configuration,
seven installer entries, and both macOS updater keys. Earlier Apple Silicon updater validation used
an ephemeral signing key and a local-only feed. A 0.2.0 application downloaded the signed 0.2.1
application archive, replaced itself, restarted, and reported 0.2.1. The test key, app, and feed
were removed afterward.

The local universal DMG passed image verification and contained `arm64` and `x86_64` slices in
the app and all three helpers. The helpers ran natively and under Rosetta, and the test updater
signature verified against the universal archive and its version. That test bundle did not use
Developer ID signing or notarization. The release still needs acceptance on an Apple silicon
Mac and an Intel Mac after signing and notarization.

Windows x64, Windows ARM64, Linux x64, and Linux ARM64 installer and restart behavior remain
release-acceptance checks. In particular, a Windows ARM64 cross-build or artifact is not evidence
that the installer completed on Windows ARM64.
