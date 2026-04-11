---
name: Release Checklist
about: Checklist for performing a GUAC release
title: "Release vX.Y.Z"
labels: release
assignees: ''
---

## Pre-release checklist

- [ ] No open issues tagged [`block-release`](https://github.com/guacsec/guac/issues?q=is%3Aissue+is%3Aopen+label%3Ablock-release)
- [ ] Locally tag a release candidate
- [ ] Candidate builds successfully
- [ ] Docs reviewed for areas needing updates
- [ ] Demos run through and verified working
- [ ] Release notes written (human-readable, not just commit list):
  - [ ] New features
  - [ ] Breaking changes
  - [ ] API changes
  - [ ] Other highlights (performance, etc.)
  - [ ] List of contributors
  - [ ] List of commits (use GitHub's generate release notes)
- [ ] If GraphQL schema changed: opened issue against [guac-visualizer](https://github.com/guacsec/guac-visualizer)
- [ ] [Helm chart](https://github.com/kusaridev/helm-charts/blob/main/charts/guac/Chart.yaml) updated

## Making the release

- [ ] Tag the new version: `git tag vX.Y.Z`
  - Major: voted on by maintainers
  - Minor: any API/CLI changes
  - Patch: otherwise
- [ ] Push the tag: `git push <remote> vX.Y.Z`
- [ ] [Release workflow](https://github.com/guacsec/guac/blob/main/.github/workflows/release.yaml) runs successfully
- [ ] Container images and binaries populated
- [ ] Release notes updated on the GitHub release
- [ ] One demo flow verified with new release tag

## Post-release

- [ ] Announce in relevant channels
