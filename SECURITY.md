# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem in `hardenkit`.

Report it privately in one of two ways:

- **GitHub:** open a [private vulnerability report](https://github.com/hardenkit/scan/security/advisories/new).
- **Our site:** follow the steps on [hardenkit.com/legal/disclosure](https://hardenkit.com/legal/disclosure).

Tell us what you found, how to reproduce it, and which version you used (`hardenkit version`).

## Supported versions

Security fixes go into the latest release. Upgrade with the install script or your package manager.

## What counts

- A way to make `hardenkit` run code, write outside its own files, or leak data from the machine it scans.
- A problem in the install script, the release files, or the GitHub Action.

A vulnerability the scanner misses, or ranks wrongly, is a bug, not a security problem in the tool. Please open a normal issue for it.
