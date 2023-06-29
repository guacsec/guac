## GUAC Use Cases

The following are some of the use cases that we've seen that GUAC can help solve
towards. If you have any other use cases not covered here, please let us know.

1. Organizations be able to share SBOM and software metadata for their software,
   and allow others to reason about it
1. An organization’s security operators can perform prioritization on
   organization software risk and make policies around them
   1. Querying top artifact usage by ecosystem (Java, NPM, Go, Python, etc)
   1. Querying artifacts with a high number of distinct vulnerabilities
   1. Dashboard for organization remediation priorities
1. Security operators can determine blast radius (or through reports of affected
   products) of a bad package or a vulnerability and provide information and a
   patch plan towards remediation. (optionally with asset databases)
   1. New vulnerability surfaced, where did it come from? How to remediate (CVE
      Reported through existing tooling ( Snyk, Blackduck, or static analysis )
      or GUAC)
   1. “Check engine light is on”. What now? Provide guidance to remediate
   1. Determine root cause of CVE showing up in scan
      - As an engineer, I want to understand exactly where a vulnerable
        dependency is in my supply chain so that I can remediate quickly and
        confidently. Additionally, be confident it will not come back again.
   1. Security team notify appropriate team of CVE (Organizations tend to have
      massive CVE reports sorted by criticality without attribution)
      - As a security engineer, I want to alert the appropriate team of a
        vulnerability to reduce noise on the rest of the organization.
1. Vendors are able to provide additional threat data to customers that they can
   apply to their organization policies and decisions
1. Security operators can provide consistent policy enforcement across the
   entire SDLC from dev, build to prod
1. Auditors want to be able to determine the security of provenance of software
   being used.
   1. Provide the chain of evidence at a specific point in time to show who had
      which pieces of information when in the case of an audit.
   1. As an auditor, I want to understand if there was a vulnerability known at
      the time of an incident, as well as if that information was known to the
      engineering team at that time, so we can trace accountability to the
      appropriate internal organization
1. Licensing use case (transitive open source license)
