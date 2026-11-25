# Contributing

Issues and pull requests are welcome.

## Build and test

You need Go (the version in `go.mod`).

```bash
make build    # builds bin/hardenkit
make check    # go vet, tests and the gofmt check
```

Run your build against a project:

```bash
bin/hardenkit scan ./testdata
```

## Pull requests

- Keep one change per pull request, with a test when it changes behavior.
- `make check` must pass.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org), for example `fix(osv): ...` or `feat(kube): ...`.

## Reporting a missed or wrong finding

Open an issue with the package, its version, the advisory or CVE, and what `hardenkit scan -v` printed. A small lockfile that reproduces it helps most.

## Security problems

See [SECURITY.md](SECURITY.md). Please do not report them in public issues.
