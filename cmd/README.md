# Developer notes for cli commands

Divide the commands into two categories:

- User-facing: Made to be run by a user / tester to accomplish something. Should
  be consistent and intuitive CLI UX. One powerful command makes sense for the
  user to learn.

- Service: Things to be run as a service, ex: in a container, as a cron, as a
  systemd service, etc. Separate single-purpose binaries make sense.

## Commands

user-facing:

**guacone**

- what it does: performs user-facing operations that require setting up a
  processor / ingestor / assembler in one binary, only talks to GQL, no nats
- options:
  - gql endpoint
- commands:
  - certify <type> - runs the <type> certifier once (once by default, optional
    poll)
  - collector <type> - runs the <type> collector once, includes "files" (once by
    default, optional poll)
  - query <name> - runs the canned <name> query.

services:

**guacgql**

- what it does: runs a GraphQL server
- options:
  - backend: inmem, neo4j, arango, ent, or future DB
  - backend-specific options: neo4j connection options
  - playground / debug: also start playground

**guaccsub**

- what it does: runs the collector-subscriber service
- options:
  - listening port

**guacingest**

- what it does: runs the ingestor connected to nats and GraphQL
- options:
  - nats addr
  - gql endpoint

**guaccollect**

- what it does: runs the named collector or certifier connected to GraphQL and
  nats
- options:
  - nats addr
  - gql addr
  - colsub addr
  - collector/certifier name
  - polling options
  - flag to toggle retrieving deps

## Collectors and Certifiers

These appear both in `guacone` and in `guaccollect`. The difference is that
`guacone` uses the all-in-one processor-ingestor-assembler, and only depends on
`guacgql` being up. Conversely `guaccollect` depends on the nats ingestion
pipeline (or future ingestor services) being up and running.

Collectors and Certifiers that are intended to be run by a user can be added to
`guacone` first, and should default to run-once. A polling option can be
included, though is not required..

Collectors and Certifiers that will be eventually run as part of a guac
deployment should be added to `guaccollect`. This is not required for initial
implementations / contributions. These should default to running as a service,
polling, a "watch", etc. An option to disable polling can be included, but is
not required.

## Flag names:

- Consistent name - For example, the Graph QL address is needed in most
  commands, the flag name should be the same across all commands.

- Consistent style - whatever it is, make is consistent. Use dash-style,
  therefore don't use camelCase anywhere.

- Descriptive on its own - The flag names are also used in the guac.yaml config
  file. Therefore a name should be self descriptive. Good: `nats-addr`, Bad:
  `type`. If it is something that has the same meaning everywhere, it is ok to
  be short: ex: interval.

- Namespaced - If appropriate, group a group of flags that go together with a
  prefix, ex: neo4j.

- Short versions - Service oriented flags don't need short versions, user
  oriented flags should.

- User oriented bools default false - Name bools so that the default is false.
  Because long names must be descriptive and possibly namespaced (for the config
  file), they are more cumbersome to type. You can't set a bool to false with
  the short version, only with long (--long-name=false), so default to false,
  and the short version can be used to enable it.

- Required args - required args should be positional. Options should be optional
  with good defaults.

All the current flags are in
https://github.com/guacsec/guac/blob/main/pkg/cli/store.go This helps with the
consistent name, and to make sure the flags are not used for different meanings
in two places.

## Other notes:

Prefix all the binaries with guac. Binaries could eventually be installed in
/usr/bin. Avoid collisions by namespacing, ex: `ingestor` or `collector` are too
generic.

Service-oriented CLI commands should exit gracefully. This means catching
SIGINT/SIGTERM and canceling contexts and/or calling Shutdown() on http servers.
`time.Sleep` should not be used anywhere for polling.

## Background / history:

https://github.com/guacsec/guac/issues/719
https://github.com/guacsec/guac/issues/762
https://github.com/guacsec/guac/issues/809
