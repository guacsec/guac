# GUAC release process

This document includes information about the GUAC release process. Including
the release cadence and the process to perform releases.

## Release cadence

The GUAC release cadence aims to happen bi-monthly. 

## Pre-release checklist

A GUAC maintainer or community member can participate in a pre-release process
but cannot perform the actual release due to lack of permissions.

- [ ] Ensure that there are no issues that are tagged
  [`block-release`](https://github.com/guacsec/guac/issues?q=is%3Aissue+is%3Aopen+label%3Ablock-release),
  such open issues indicate that a release should not be made until they are
  closed.
- [ ] Locally tag a release candidate
- [ ] Ensure that the candidate builds
- [ ] Look through docs and identify if there are any areas which need to be
  updated
- [ ] Run through the demos to ensure they are not broken (it would be great if
  someone can help automate this check!)
- [ ] Write the release notes (release notes should be human readable and not
  just a list of commits), it should include information about
  - [ ] New features
  - [ ] Breaking changes, 
  - [ ] APIs 
  - [ ] Other significant highlights (performance increases, etc.)
  - [ ] List of contributors to the release
  - [ ] List of commits between last release and this one (use the Github
    generate release notes function to help with this)
- [ ] If the GraphQL schema changes, open an issue against [guac-visualizer](https://github.com/guacsec/guac-visualizer)
- [ ] Update the [Helm chart](https://github.com/kusaridev/helm-charts/blob/main/charts/guac/Chart.yaml)

The release template is as follows:

``` ## Highlights
* Addition of a new KeyValue backend (Redis and TiKV)
* Update and improve `guacone` CLI
* Add new graphQL Custom Directives `contains` and `startswith`
* Various updates to arangoDB and ENT backend
* REST API initial implementation
* Various bug fixes and improvements
* ...

## Contributors

* @pxp928
* @lumjjb
* @mihaimaruseac
* @jeffmendoza
* @mlieberman85
* ...

## What's Changed
* 8336525 1434-docker-compose - backend selection on startup (#1435)
* c197a9d 1550 Ent: hasSBOM 'included' implementation (#1583)
* 8daf872 Add Guacone collect files json.bz2 capability (#1395)
* 1fb5ee9 Add Redis and TiKV kv stores (#1502)
* bb36eab Add benchmark for TiKV (#1579)
* ab37eb4 Add comment for id field on PkgSpec (#1631)
* df88a40 Add comment on Edge schema to note that edges are bidirectional
  (#1632)
* 7176dec Add concurrency to arango hasSBOM query (#1609)
* ...  ```

## Making a release

Once the checklist is completed, a GUAC maintainer can perform a release by:

- [ ] Upload a tag for the new version (it must meet the glob `v*`)
  - [ ] Tag a new version from the candidate main commit, `git tag vx.y.z`)
    - Major version increments need to be voted on by GUAC maintainers
    - Any API/CLI changes should have an increase in minor version
    - Otherwise patch version increase
  - [ ] Push the tag `git push <remote> vx.y.z`
- [ ] This will trigger the [release
  workflow](https://github.com/guacsec/guac/blob/main/.github/workflows/release.yaml)
  on your tag
- [ ] Let the github actions run and validate that the container images and
  binaries are populated
- [ ] Update the release notes to the ones written in the pre-release process
- [ ] Try out one demo flow with the new release tag
- [ ] We are done! Yay!
