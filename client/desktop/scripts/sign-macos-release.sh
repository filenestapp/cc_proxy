#!/usr/bin/env bash
# Sign and notarize the universal macOS app and installer in an isolated keychain.
set -euo pipefail
umask 077

bundle=${1:?Usage: sign-macos-release.sh BUNDLE_DIRECTORY RELEASE_VERSION}
version=${2:?Release version required}
app="$bundle/macos/aifree.app"
archive="$bundle/macos/aifree.app.tar.gz"
dmg="$bundle/dmg/aifree_${version}_universal.dmg"
scripts="$(cd "$(dirname "$0")" && pwd)"

: "${MACOS_SIGNING_CERTIFICATES_P12:?Missing macOS signing certificates}"
: "${MACOS_SIGNING_CERTIFICATES_PASSWORD:?Missing macOS signing certificate password}"
: "${MACOS_TEAM_ID:?Missing Apple Developer team ID}"
: "${MACOS_NOTARY_PRIVATE_KEY:?Missing Apple notarization key}"
: "${MACOS_NOTARY_KEY_ID:?Missing Apple notarization key ID}"
: "${MACOS_NOTARY_ISSUER_ID:?Missing Apple notarization issuer ID}"
: "${TAURI_SIGNING_PRIVATE_KEY:?Missing updater signing key}"

test "$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$app/Contents/Info.plist")" = "$version"
main=$(/usr/libexec/PlistBuddy -c 'Print CFBundleExecutable' "$app/Contents/Info.plist")
for executable in "$main" aifree sing-box frpc; do
  for architecture in arm64 x86_64; do
    lipo "$app/Contents/MacOS/$executable" -verify_arch "$architecture"
  done
done
"$app/Contents/MacOS/aifree" --version | grep -Fx "aifree $version"

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/aifree-macos-signing.XXXXXX")
keychain="$work/release.keychain-db"
mount="$work/installer"
previous_keychains=()
while IFS= read -r entry; do
  previous_keychains+=("$entry")
done < <(security list-keychains -d user | sed -E 's/^[[:space:]]*"//; s/"$//')

cleanup() {
  hdiutil detach -quiet "$mount" >/dev/null 2>&1 || true
  security list-keychains -d user -s ${previous_keychains[@]+"${previous_keychains[@]}"} >/dev/null 2>&1 || true
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

keychain_password=$(openssl rand -hex 32)
printf '%s' "$MACOS_SIGNING_CERTIFICATES_P12" | base64 -D > "$work/release.p12"
printf '%s\n' "$MACOS_NOTARY_PRIVATE_KEY" > "$work/notary.p8"

security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 1800 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security list-keychains -d user -s "$keychain" ${previous_keychains[@]+"${previous_keychains[@]}"}
security import "$work/release.p12" -k "$keychain" -P "$MACOS_SIGNING_CERTIFICATES_PASSWORD" \
  -T /usr/bin/codesign -T /usr/bin/pkgbuild -T /usr/bin/productsign
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" >/dev/null

# Use the same Apple Developer ID G2 intermediate as the release certificates.
curl -fsSL --retry 3 --max-time 30 -o "$work/developer-id-g2.cer" \
  https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer
printf '%s  %s\n' f16cd3c54c7f83cea4bf1a3e6a0819c8aaa8e4a1528fd144715f350643d2df3a \
  "$work/developer-id-g2.cer" | shasum -a 256 -c -
security import "$work/developer-id-g2.cer" -k "$keychain" -t cert

identity() {
  security find-identity -v -p "$1" "$keychain" |
    awk -F '"' -v label="$2" -v team="$MACOS_TEAM_ID" \
      'index($2, label ": ") == 1 && index($2, "(" team ")") { print $2 }'
}
application_identity=$(identity codesigning 'Developer ID Application')
installer_identity=$(identity basic 'Developer ID Installer')
test -n "$application_identity" && test -n "$installer_identity"
printf 'Found the application and installer signing identities for Apple team %s.\n' "$MACOS_TEAM_ID"

for executable in aifree sing-box frpc; do
  codesign --force --keychain "$keychain" --sign "$application_identity" --options runtime --timestamp \
    "$app/Contents/MacOS/$executable"
done
codesign --force --keychain "$keychain" --sign "$application_identity" --options runtime --timestamp "$app"
codesign --verify --deep --strict "$app"

notarize() {
  xcrun notarytool submit "$1" --key "$work/notary.p8" --key-id "$MACOS_NOTARY_KEY_ID" \
    --issuer "$MACOS_NOTARY_ISSUER_ID" --wait --timeout 10m --output-format json > "$work/notary-result.json"
  cat "$work/notary-result.json"
  test "$(/usr/bin/plutil -extract status raw "$work/notary-result.json")" = Accepted
}

ditto -c -k --sequesterRsrc --keepParent "$app" "$work/aifree-notary.zip"
notarize "$work/aifree-notary.zip"
xcrun stapler staple "$app"
xcrun stapler validate "$app"
COPYFILE_DISABLE=1 tar -czf "$archive" -C "$bundle/macos" aifree.app
npx --yes @tauri-apps/cli@2.12.6 signer sign --app-version "$version" "$archive"
test -s "$archive.sig"

AIFREE_MAC_INSTALLER_IDENTITY="$installer_identity" AIFREE_MAC_INSTALLER_KEYCHAIN="$keychain" \
  "$scripts/package-macos-installer.sh" "$app" "$dmg"
codesign --force --keychain "$keychain" --sign "$application_identity" --timestamp "$dmg"
notarize "$dmg"
xcrun stapler staple "$dmg"
xcrun stapler validate "$dmg"
codesign --verify --strict "$dmg"
spctl --assess --type open --context context:primary-signature --verbose=2 "$dmg"

mkdir "$mount"
hdiutil attach -quiet -nobrowse -noautoopen -readonly -mountpoint "$mount" "$dmg"
pkgutil --check-signature "$mount/Install aifree.pkg" > "$work/package-signature.txt"
grep -F "$installer_identity" "$work/package-signature.txt"
grep -iF 'trusted timestamp' "$work/package-signature.txt"
hdiutil detach -quiet "$mount"
