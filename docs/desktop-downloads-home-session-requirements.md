# Desktop compatibility, download selection, and homepage session

**Status:** Review · **Updated:** 2026-11-26 · **Confidence:** High

**Sources:** Customer request and current `main` behavior (desktop release, both download entry points, and account session).

## Outcome and scope

The current macOS download is Apple silicon only. The public download page does not select a package for the visitor, the account center shows an ungrouped list, and the homepage shows guest actions even after a customer has signed in. This change helps visitors and returning customers choose an installer and get back to their account from either language of the homepage.

| User | Goal and quality signal |
| --- | --- |
| Intel Mac or Apple silicon Mac owner | One macOS installer runs natively on both chip families, including all three bundled helpers. |
| Windows or Linux visitor; signed-in customer | Both download entry points make the same recommendation for a given device. All supported packages remain reachable by operating system. |
| Returning customer | The Chinese and English homepages show the account-center link for a valid web session and guest actions otherwise. |

**Out of scope:** mobile installers, desktop credential or connection changes, sharing account details with the marketing site, and new tracking or telemetry.

## Requirements and acceptance

| ID | Priority | Requirement | Acceptance check |
| --- | --- | --- | --- |
| D1 | Must | Build a native macOS installer for Apple silicon and Intel. Keep signed desktop updates working for both. | Inspect the installed app executable and `ccproxy`, `sing-box`, and `frpc` for `arm64` and `x86_64`. Both macOS updater keys resolve to the signed universal archive. |
| D2 | Must | On the public download page, open the detected operating system by default and put the compatible option first when the processor is known. | Check macOS, Windows x64 and ARM64, Linux x64 and ARM64, and the manual fallback. Switching to another OS remains possible by keyboard or pointer. |
| D3 | Must | Apply the same grouped and recommended options in the signed-in account center. | The same device gets the same suggestion in both places. With unknown or mobile devices, all categories are accessible and no incompatible choice is marked as recommended. |
| H1 | Must | Replace the homepage's log-in/sign-up actions with the account-center link when the web session is valid. | Guest → log in → return home → log out → return home. Confirm both languages and an expired/revoked session. The status response is not cached and never contains customer data or credentials. |
| R1 | Must | Keep known working links and guest navigation usable if detection or the status service fails. | Without JavaScript or with a missing/malformed release feed, the published baseline is still reachable; a package is not linked before it is validly advertised. |

## User flow and defaults

1. Open the public download page or sign in and find the download panel. Both list macOS, Windows, and Linux.
2. Open the detected system's group first. Default to the universal DMG on macOS so browsers that withhold chip information still get a compatible package. On Windows and Linux use a matching architecture when reported. Prefer a DEB when the browser identifies Debian or Ubuntu, otherwise prefer AppImage on Linux. Alternatives remain selectable.
3. If the OS is unknown, show the groups without a recommendation. If only the processor is unknown and there is no universal package, keep that system open for manual selection.
4. After signing in through the account center, return to either homepage language. A valid session displays the account link; a missing, invalid, or unreachable session leaves the guest links available.

The surfaces remain bilingual and keyboard accessible. Detection stays in the browser. The homepage reads only signed-in status using the existing account-host cookie; the cookie's host scope and permissions do not change.

## Execution and rollout

| Workstream | Ownership | Handoff |
| --- | --- | --- |
| Desktop release | macOS package, sidecars, release workflow, installer and updater manifest | Provide a verified universal DMG and matching manifest entries. |
| Download experience | Public bilingual download pages, account-center panel, shared detection and fallback | Prove the same selection on both surfaces and retain manual links. |
| Homepage session | Bilingual navigation and minimal account-session check | Prove sign-in and sign-out transitions and origin isolation. |
| Integration | Deployment wiring, cross-surface verification, release readiness | Coordinate the site and control-plane changes and verify against the old and new release manifests. |

**Assumptions and release decision:** Native Intel support and the three user-facing changes are requested. A universal DMG, no new telemetry, and retaining existing links until publishing are implementation defaults. Production rollout uses the existing manual release process; publish the signed and notarized package before exposing it in the stable manifest. The initial public release version and timing are not set by this requirement.
