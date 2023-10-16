# How to Contribute

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines you need to follow.

Refer to the [GraphQL Guide](https://docs.guac.sh/guac-graphql/) to go through
a setup.  Optionally, you can also consult [docker compose
documentation](https://docs.guac.sh/setup/).

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement (CLA). You (or your employer) retain the copyright to your
contribution; this simply gives us permission to use and redistribute your
contributions as part of the project. Head over to
<https://cla.developers.google.com/> to see your current agreements on file or
to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Code Reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

We require all commits in a PR to contain a `Signed-off-by` line which can be
added by using the `-s` flag of `git commit`. This is to enforce
[a Developer Certificate of Origin (DCO)](https://wiki.linuxfoundation.org/dco).

We also require two reviewers on every PR as this follows good security
practices. For reasoning, see
[CNCF Supply Chain Best Practices](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/CNCF_SSCP_v1.pdf).

## Community Guidelines

This project follows
[Google's Open Source Community Guidelines](https://opensource.google/conduct/).

## Getting Started

The project is managed via Github. For contributors that would like to find a
good place to start, take a look at the "good first issues" and "help wanted"
labels
[(filter link here)](https://github.com/guacsec/guac/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22).

We also have a [slack channel](https://openssf.slack.com/archives/C03U677QD46)
that you can reach us at and ask questions!

## Contributor ladder

We are excited that you want to contribute to GUAC! This contributor ladder
outlines different contributor roles within the project, along with
responsibilities and privileges that come with them.

Since GUAC is a complex project, there are 5 topic areas of interest:

- Ingestion: ingest software security metadata. Needs to write parsers for
  documents, maintain ingestion logic, write new collectors, etc.
- GraphQL: define the GraphQL interface used between ingestion pipeline and
  backend, and between backend and GUAC-based applications and front-ends.
- Backends: define efficient code to interface with database backends (Neo4j,
  etc.).
- Front-end: GUAC visualisation libraries, Javascript, CSS
- Clients: GUAC CLI, CI Checks, Policy Engines, IDE Plugins, etc.

The contribution ladder is summarized in the table below:

| Role                  | Responsibilities                                                                       | Requirements                                                                     | Privileges                                    | GitHub access level |
| --------------------- | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | --------------------------------------------- | ------------------- |
| Community Participant | Follow [Google's Open Source Community Guidelines](https://opensource.google/conduct/) | N/A                                                                              | N/A                                           | Read (default)      |
| Reviewer              | Review contributions from other members                                                | Prove technical expertise in at least one GUAC topic area                        | Can approve PRs                               | Write               |
| Owner                 | Set direction and priorities for topic area. Approval of contributions                 | Deep technical expertise in topic area. Proven record of reviews and authorship. | Invitation to owner&maintainers only channels | Write               |
| Maintainer            | Set direction and priorities of project. Participate in weekly syncs                   | Expertise in 3 out of the 5 topic areas                                          | (almost) complete repository access           | Maintain            |

Each level of the ladder is also described in more details below.

### Community Participant

Each new contributor to GUAC starts at this level. There is no longer a formal
requirement to
[register desire to contribute in issue #1](https://github.com/guacsec/guac/issues/1).

There are no requirements and no privileges. Every community participant can
create issues, fork the repository, create PRs, add comments to issues and PRs.

### Reviewer

Once a community participant has demonstrated expertise in one GUAC topic area,
owners and/or maintainers can propose graduating the community participant to
the Reviewer role, upon a maintainer majority vote.

A reviewer will be responsible of reviewing contributions from other
contributors that touch the corresponding topic area. They should ensure that
the PRs are adequately tested, follow the guidelines for the specific topic
area.

### Owner

A reviewer with significant review history and proven record of authorship in a
specific GUAC topic area can be promoted to Owner status, upon a maintainer
majority vote.

The Owner is in full control over the specific topic area. They are expected to
set direction and priorities, resolve technical trade-offs, prioritize between
adding new features and handling technical debt. As such, they must show a deep
understanding of technical problems involved in this area.

Owners are invited to the GUAC owners and maintainers Slack channel.

Owners will be added to `CODEOWNERS` file, so they will be notified of PRs that
touch their area of interest.

### Maintainer

An owner that gains a deep understanding of GUAC architecture and design and can
prove this by being an OWNER in at least 3 topic areas will be promoted to
maintainer, after a n-1 approval vote from the other maintainers, according to
the processes specified in [the governance document](./GOVERNANCE.md).

A maintainer has almost full access to the repository and is invited to all
maintainer meetings, where they can contribute input that will set direction and
priorities of the entire project. They must have ability to commit to
participating to at least the weekly maintainer sync meetings (currently 2
meetings totalling up to 2 hours every week).

A maintainer might be required to work with GUAC clients, thus they might be
required to sign NDAs.

The [GUAC governance document](./GOVERNANCE.md) also details the role of
technical advisory member, which is offered to members of the community that
have provided valuable input. The technical advisory members have a consulting
role and are the only role without an activity requirement.

### Inactivity, Stepping down

Each role in the contribution ladder requires maintaining active contributions
at the corresponding level. Inactivity is harmful to the project, so maintainers
can decide to remove privileges from inactive contributors, after a majority
vote. Inactivity is defined as periods longer than 3 months during which no
contribution is being done.

Contributors also have the option of stepping down voluntarily, by contacting
the maintainers when circumstances affect future contribution potential. For
highly active contributors that completely step away from the project, we will
create an emeritus process.

GUAC contributors are happy to help you advance along the contributor ladder!

### Reviewers list

| Reviewer                            | Area                                                                                                                       | Vote                                                       |
|-------------------------------------|----------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|
| [mrizzi](https://github.com/mrizzi) | [Backends (ent)](https://github.com/guacsec/guac/tree/4012842fab5d738f9bebf03f0cb44fc7ce39438b/pkg/assembler/backends/ent) | [issues/1310](https://github.com/guacsec/guac/issues/1310) |
