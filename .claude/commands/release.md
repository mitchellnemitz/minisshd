---
description: Tag and push a release; watch the release workflow
argument-hint: vX.Y.Z
---

Tag: `$ARGUMENTS`

Cut a release using the tag above. Stop and surface the problem if any step
fails — do not press on.

1. Validate that `$ARGUMENTS` matches `vX.Y.Z` (semver, leading `v`, three
   numeric components, optionally with `-prerelease` suffix). If not, stop.
2. Confirm we're on `main`, the working tree is clean, and `main` is in sync
   with `origin/main` (no unpushed commits, no behind-commits). If not, report
   what needs to happen first and stop.
3. Confirm the tag does not already exist locally (`git rev-parse $ARGUMENTS`)
   or on the remote (`git ls-remote --tags origin $ARGUMENTS`). If it does,
   stop.
4. Create an annotated tag and push it:
   - `git tag -a $ARGUMENTS -m "$ARGUMENTS"`
   - `git push origin $ARGUMENTS`
5. Watch the `release.yml` workflow run kicked off by the tag push using
   `gh run watch` (resolve the run id with
   `gh run list --workflow=release.yml --limit=1 --json databaseId,status,conclusion,url`).
6. When the workflow finishes, report the conclusion and link to the
   GitHub Release (`gh release view $ARGUMENTS --web` is fine for a URL — do
   not actually open the browser).
