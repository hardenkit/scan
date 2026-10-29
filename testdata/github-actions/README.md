# GitHub Actions test fixture

Deliberately risky workflows for testing `hardenkit scan`: a
`pull_request_target` job that checks out and builds pull request code with a
write-all token, pull request titles and comment bodies pasted into scripts,
third-party actions pinned to a tag or branch, and a literal secret. `ci.yml`
follows the guidance and should produce no issues. The secret is fake.

GitHub only runs workflows from the repository's top-level `.github`
directory, so these never run.
