# aifree

`aifree` routes selected traffic through assigned IPv4 exits. It includes a Rust desktop and CLI client, a Go control plane backed by PostgreSQL, and Linux exit nodes that run sing-box.

| Component | Documentation |
| --- | --- |
| Desktop and CLI | [Client setup and tests](client/README.md) |
| Control plane | [API, administration, and monitoring](controlplane/README.md) |
| Exit host | [IP binding and deployment](egress/README.md) |
| Exit-node installer | [Go agent, one-command install for macOS, Linux and Windows](egress/install/README.md) |
| Design | [Multi-IP architecture](docs/multi-ip-egress-proxy-design.md) |

## Development with GitHub Issues

Use [GitHub Issues](https://github.com/filenestapp/cc_proxy/issues) to track bugs and changes. Branch from `main` for an issue and link the pull request back to it with `Fixes #<number>` once the acceptance checks are met. Include the tests run and any remaining platform checks in the pull request. The [November review notes](docs/review-fix-issue-2026-11-22.md) record the earlier implementation and verification.
