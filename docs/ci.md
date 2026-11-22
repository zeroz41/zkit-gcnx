# CI

A matching decomp needs the original game to build, and the game must never reach GitHub. So CI runs in two
places: a self-hosted runner that holds the original executable (read-only, never uploaded) builds and checks pull
requests, and GitHub-hosted runners do everything that needs only a report. zkit supplies the three steps that
carry the logic, so each workflow stays short:

| | |
| --- | --- |
| `zkit ci check --base REV --baseline FILE --out result.json` | the gate: build; nothing matched or linked in the baseline lost; no decompiler leftovers (`zkit check` errors) in the lines added since `REV`; no files that must not be committed (`zkit hygiene --only files`). Exit 1 when it fails. It also measures source quality since `REV` (`zkit quality --since`), which never fails the gate. |
| `zkit ci comment result.json --sha SHA --run-url URL` | the pull request comment for that result, behind a hidden marker so it can be updated in place; a missing result is a failed run. Its advisory source quality section lists the checks the change moved (the tree's count before and after, what the change removed and what it added; code that only moves counts as neither), every check by category in a collapsed table, and the findings on the lines the change adds, linked to the measured commit |
| `zkit ci report --sha SHA --out report.json` | the report a trusted run kept for a commit (needs `GITHUB_TOKEN` or `GH_TOKEN`, and `GITHUB_REPOSITORY` or `--repo`); exit 1 when there is none |

and the pages: `zkit report --out site --badges site/badges` writes the progress page, the treemap and the
shields.io badge data from a report alone, with no game and no build.

## The workflows

Three workflow files. The paths below are the defaults `zkit ci report` trusts (`--ci-workflow`,
`--progress-workflow` change them). `<label>` is the self-hosted runner's label, `<sha1>` the original
executable's SHA-1, and `<orig>` its path in the repository.

**`.github/workflows/ci.yml`**: on `pull_request` (and `workflow_dispatch`), on `[self-hosted, <label>]`, with
`permissions: {contents: read, actions: read, pull-requests: read}` and no secrets:

1. `actions/checkout` with `fetch-depth: 0`. The checkout cleans the workspace, so nothing an earlier run left
   in `build/` is used.
2. Copy the original executable from the runner's read-only folder to `<orig>` and check it:
   `install -D -m 0444 /opt/decomp-ci/orig/... <orig>`, then `echo "<sha1>  <orig>" | sha1sum -c -`. A symlink
   does not work, because zkit refuses links that lead out of the repository.
3. Baseline: `zkit ci report --sha "$BASE_SHA" --out "$RUNNER_TEMP/baseline.json"`, where `BASE_SHA` is
   `github.event.pull_request.base.sha`. When there is none, check out the base commit, build it, copy its
   report, and check out the merge commit again.
4. Build. If the repository pins zkit in a build script, run the full build here, so the pull request's pinned
   zkit is the one installed (the baseline build may have installed the base commit's).
5. `zkit ci check --baseline "$RUNNER_TEMP/baseline.json" --base "$BASE_SHA" --out ci-result/result.json`.
6. `zkit ci comment ci-result/result.json ... >> "$GITHUB_STEP_SUMMARY"` (`if: always()`).
7. On success, keep the report as the artifact `report-<tree>`, where `<tree>` is `git rev-parse 'HEAD^{tree}'`
   of the merge commit. When the pull request merges with the default branch unchanged, this is the merged
   commit's report.
8. Upload `ci-result/` as the artifact `ci-result` (`if: always()`).

**`.github/workflows/ci-comment.yml`**: on `workflow_run` of CI, `types: [completed]`, on `ubuntu-latest`, with
`permissions: {actions: read, contents: read, pull-requests: write}`. CI runs fork code with a read-only token and
cannot comment, so this workflow comments for it. It never checks out or runs pull request code.

- Check out only what runs zkit from the default branch: a sparse checkout of the build script and project file.
- Download `ci-result` from `github.event.workflow_run.id` (`continue-on-error`: a run that stopped early has
  none).
- Find the pull request from the run, never from the artifact: the open pull request whose head is
  `head_repository.owner.login:head_branch` at `head_sha`. If there is none, a newer push superseded this run.
- `zkit ci comment ci-result/result.json --sha "$HEAD_SHA" --run-url "$RUN_URL" > comment.md`. Then patch
  `github-actions[bot]`'s comment whose body starts with the first line of `comment.md`, or post a new one.

`workflow_run` only fires for workflow files on the default branch, so changes to this file take effect once
merged.

**`.github/workflows/progress.yml`**: on `push` to the default branch (and `workflow_dispatch`), with
`concurrency: {group: progress, cancel-in-progress: true}`:

- `reuse` (`ubuntu-latest`, `actions: read`, `pull-requests: read`, `continue-on-error`):
  `zkit ci report --sha "$GITHUB_SHA" --out <the target's report path>`, then `zkit report --out site --badges
  site/badges` and `actions/upload-pages-artifact` with `path: site`.
- `wait` (`ubuntu-latest`, only when `reuse` found nothing): `sleep 600`. A batch of merges then cancels
  down to one build.
- `build` (`[self-hosted, <label>]`, after `wait`, or straight away on a manual run): copy and check the
  executable, build, write the same site, keep the report as `report-<tree>` for the next pull request's
  baseline, and upload the pages artifact.
- `deploy` (`ubuntu-latest`, `pages: write`, `id-token: write`, environment `github-pages`):
  `actions/deploy-pages`.

The README's badges then read
`https://img.shields.io/endpoint?url=<pages url, URL-encoded>%2Fbadges%2Fcode.json` (and `data`, `functions`,
`code-linked`, `data-linked`, `units-linked`). Nothing is committed back to the repository, so hygiene can forbid a
progress table in the README (`progress_table: forbid`).

## Why a report is trusted

The baseline decides what counts as a regression, so a pull request must not be able to supply its own. `zkit
ci report` uses an artifact only when it is named `report-<tree of the commit>` and comes from one of:

- a successful CI run on a pull request whose head was merged as that commit;
- a successful progress run on the default branch, from a push or a manual run, at that commit.

The token is sent only to the GitHub API. The artifact download redirects to signed storage, which gets no token.

## The runner

The self-hosted runner runs pull request code, so:

- Set Settings → Actions → General → "Approval for running fork pull request workflows from contributors" to
  "Require approval for all external contributors". Read a pull request (its build script and `.github/` above
  all) before approving its run.
- Keep the default workflow token read-only (Settings → Actions → General → Workflow permissions); the
  workflows ask for what they need.
- Run the runner as an unprivileged user in a container with no Docker socket. Mount only the original
  executable's folder, read-only. Jobs must not use `container:`.

A container for an x86_64 Linux host (the runner keeps itself up to date after the first start):

```dockerfile
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git jq g++ python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 1001 runner
WORKDIR /home/runner
RUN version=$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest | jq -r .tag_name) \
 && version=${version#v} \
 && curl -fsSL -o runner.tar.gz \
      "https://github.com/actions/runner/releases/download/v${version}/actions-runner-linux-x64-${version}.tar.gz" \
 && tar xzf runner.tar.gz && rm runner.tar.gz \
 && ./bin/installdependencies.sh && rm -rf /var/lib/apt/lists/* \
 && chown -R runner:runner /home/runner
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh
USER runner
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
```

with `entrypoint.sh`, which registers the runner once and keeps the registration in the `/home/runner` volume:

```bash
#!/bin/bash
set -euo pipefail
cd /home/runner
if [ ! -f .runner ]; then
  : "${RUNNER_TOKEN:?set RUNNER_TOKEN to a registration token for the first start}"
  ./config.sh --unattended --replace --url "$RUNNER_REPO" --token "$RUNNER_TOKEN" \
    --name "${RUNNER_NAME:-decomp}" --labels "$RUNNER_LABEL" --work _work
fi
exec ./run.sh
```

```sh
docker build -t decomp-runner .
docker run -d --name decomp-runner --restart unless-stopped \
  -e RUNNER_REPO=https://github.com/OWNER/REPO -e RUNNER_LABEL=<label> -e RUNNER_TOKEN=<registration token> \
  -v decomp-runner:/home/runner -v /srv/decomp-ci/orig:/opt/decomp-ci/orig:ro decomp-runner
```

The registration token comes from Settings → Actions → Runners → New self-hosted runner and is only needed for
the first start. Each run starts from a clean checkout, so it downloads the build tools again (a few hundred MB).
