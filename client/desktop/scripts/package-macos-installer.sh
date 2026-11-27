#!/usr/bin/env bash
# Keep the DMG download format and install both the app and terminal command using Installer.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
app="${1:?Usage: package-macos-installer.sh APP_BUNDLE OUTPUT_DMG}"
dmg="${2:?DMG output path required}"
version=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$app/Contents/Info.plist")

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root/Applications" "$work/image" "$(dirname "$dmg")"
ditto "$app" "$work/root/Applications/aifree.app"

cat > "$work/components.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
  <dict>
    <key>RootRelativeBundlePath</key><string>Applications/aifree.app</string>
    <key>BundleIsRelocatable</key><false/>
    <key>BundleIsVersionChecked</key><true/>
    <key>BundleOverwriteAction</key><string>upgrade</string>
  </dict>
</array>
</plist>
PLIST
args=(--root "$work/root" --component-plist "$work/components.plist"
  --identifier sg.aifree.desktop.pkg --version "$version" --install-location /
  --scripts "$here/../src-tauri/installer/macos")
if [[ -n "${AIFREE_MAC_INSTALLER_IDENTITY:-}" ]]; then
  args+=(--sign "$AIFREE_MAC_INSTALLER_IDENTITY")
  if [[ -n "${AIFREE_MAC_INSTALLER_KEYCHAIN:-}" ]]; then
    args+=(--keychain "$AIFREE_MAC_INSTALLER_KEYCHAIN")
  fi
fi
pkgbuild "${args[@]}" "$work/image/Install aifree.pkg"
hdiutil create -ov -fs HFS+ -format UDZO -volname aifree -srcfolder "$work/image" "$dmg"
