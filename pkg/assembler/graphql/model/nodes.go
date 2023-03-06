// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package model

import (
	"time"
)

// CveGhsaObject is a union of CVE and GHSA.
type CveGhsaObject interface {
	IsCveGhsaObject()
}

// OsvCveGhsaObject is a union of OSV, CVE and GHSA. Any of these objects can be specified for vulnerability
type OsvCveOrGhsa interface {
	IsOsvCveOrGhsa()
}

// PackageSourceOrArtifact is a union of Package, Source, and Artifact.
type PackageSourceOrArtifact interface {
	IsPackageSourceOrArtifact()
}

// PkgArtObject is a union of Package and Artifact. Any of these objects can be specified
type PkgArtObject interface {
	IsPkgArtObject()
}

// PkgSrcObject is a union of Package and Source. Any of these objects can be specified
type PkgSrcObject interface {
	IsPkgSrcObject()
}

// Artifact represents the artifact and contains a digest field
//
// Both field are mandatory and canonicalized to be lowercase.
//
// If having a `checksum` Go object, `algorithm` can be
// `strings.ToLower(string(checksum.Algorithm))` and `digest` can be
// `checksum.Value`.
type Artifact struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

func (Artifact) IsPkgArtObject() {}

func (Artifact) IsPackageSourceOrArtifact() {}

// ArtifactInputSpec is the same as Artifact, but used as mutation input.
//
// Both arguments will be canonicalized to lowercase.
type ArtifactInputSpec struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

// ArtifactSpec allows filtering the list of artifacts to return.
//
// Both arguments will be canonicalized to lowercase.
type ArtifactSpec struct {
	Algorithm *string `json:"algorithm"`
	Digest    *string `json:"digest"`
}

// Builder represents the builder such as (FRSCA or github actions).
//
// Currently builders are identified by the `uri` field, which is mandatory.
type Builder struct {
	URI string `json:"uri"`
}

// BuilderInputSpec is the same as Builder, but used for mutation ingestion.
type BuilderInputSpec struct {
	URI string `json:"uri"`
}

// BuilderSpec allows filtering the list of builders to return.
type BuilderSpec struct {
	URI *string `json:"uri"`
}

// CVE represents common vulnerabilities and exposures. It contains the year along
// with the CVE ID.
//
// The year is mandatory.
//
// This node is a singleton: backends guarantee that there is exactly one node
// with the same `year` value.
type Cve struct {
	Year  string   `json:"year"`
	CveID []*CVEId `json:"cveId"`
}

func (Cve) IsOsvCveOrGhsa() {}

func (Cve) IsCveGhsaObject() {}

// CVEId is the actual ID that is given to a specific vulnerability
//
// The `id` field is mandatory and canonicalized to be lowercase.
//
// This node can be referred to by other parts of GUAC.
type CVEId struct {
	ID string `json:"id"`
}

// CVEInputSpec is the same as CVESpec, but used for mutation ingestion.
type CVEInputSpec struct {
	Year  string `json:"year"`
	CveID string `json:"cveId"`
}

// CVESpec allows filtering the list of cves to return.
type CVESpec struct {
	Year  *string `json:"year"`
	CveID *string `json:"cveId"`
}

// CertifyBad is an attestation represents when a package, source or artifact is considered bad
//
// subject - union type that can be either a package, source or artifact object type
// justification (property) - string value representing why the subject is considered bad
// origin (property) - where this attestation was generated from (based on which document)
// collector (property) - the GUAC collector that collected the document that generated this attestation
//
// Note: Attestation must occur at the PackageName or the PackageVersion or at the SourceName.
type CertifyBad struct {
	Subject       PackageSourceOrArtifact `json:"subject"`
	Justification string                  `json:"justification"`
	Origin        string                  `json:"origin"`
	Collector     string                  `json:"collector"`
}

// CertifyBadSpec allows filtering the list of CertifyBad to return.
// Note: Package, Source or artifact must be specified but not at the same time
// For package - a PackageName or PackageVersion must be specified (name or name, version, qualifiers and subpath)
// For source - a SourceName must be specified (name, tag or commit)
type CertifyBadSpec struct {
	Package       *PkgSpec      `json:"package"`
	Source        *SourceSpec   `json:"source"`
	Artifact      *ArtifactSpec `json:"artifact"`
	Justification *string       `json:"justification"`
	Origin        *string       `json:"origin"`
	Collector     *string       `json:"collector"`
}

// CertifyPkg is an attestation that represents when a package objects are similar
//
// packages (subject) - list of package objects
// justification (property) - string value representing why the packages are similar
// origin (property) - where this attestation was generated from (based on which document)
// collector (property) - the GUAC collector that collected the document that generated this attestation
type CertifyPkg struct {
	Packages      []*Package `json:"packages"`
	Justification string     `json:"justification"`
	Origin        string     `json:"origin"`
	Collector     string     `json:"collector"`
}

// CertifyPkgSpec allows filtering the list of CertifyPkg to return.
//
// Specifying just the package allows to query for all similar packages (if they exist)
type CertifyPkgSpec struct {
	Packages      []*PkgSpec `json:"packages"`
	Justification *string    `json:"justification"`
	Origin        *string    `json:"origin"`
	Collector     *string    `json:"collector"`
}

// CertifyScorecard is an attestation which represents the scorecard of a
// particular source repository.
type CertifyScorecard struct {
	// The source repository that is being scanned (attestation subject)
	Source *Source `json:"source"`
	// The Scorecard attached to the repository (attestation object)
	Scorecard *Scorecard `json:"scorecard"`
}

// CertifyScorecardSpec allows filtering the list of CertifyScorecard to return.
type CertifyScorecardSpec struct {
	Source           *SourceSpec           `json:"source"`
	TimeScanned      *time.Time            `json:"timeScanned"`
	AggregateScore   *float64              `json:"aggregateScore"`
	Checks           []*ScorecardCheckSpec `json:"checks"`
	ScorecardVersion *string               `json:"scorecardVersion"`
	ScorecardCommit  *string               `json:"scorecardCommit"`
	Origin           *string               `json:"origin"`
	Collector        *string               `json:"collector"`
}

// CertifyVEXStatement is an attestation that represents when a package or artifact has a VEX about a specific vulnerability (CVE or GHSA)
//
// subject - union type that represents a package or artifact
// vulnerability (object) - union type that consists of cve or ghsa
// justification (property) - justification for VEX
// knownSince (property) - timestamp of the VEX (exact time in RFC 3339 format)
// origin (property) - where this attestation was generated from (based on which document)
// collector (property) - the GUAC collector that collected the document that generated this attestation
type CertifyVEXStatement struct {
	Subject       PkgArtObject  `json:"subject"`
	Vulnerability CveGhsaObject `json:"vulnerability"`
	Justification string        `json:"justification"`
	KnownSince    time.Time     `json:"knownSince"`
	Origin        string        `json:"origin"`
	Collector     string        `json:"collector"`
}

// CertifyVEXStatementSpec allows filtering the list of CertifyVEXStatement to return.
// Only package or artifact and CVE or GHSA can be specified at once.
type CertifyVEXStatementSpec struct {
	Package       *PkgSpec      `json:"package"`
	Artifact      *ArtifactSpec `json:"artifact"`
	Cve           *CVESpec      `json:"cve"`
	Ghsa          *GHSASpec     `json:"ghsa"`
	Justification *string       `json:"justification"`
	KnownSince    *time.Time    `json:"knownSince"`
	Origin        *string       `json:"origin"`
	Collector     *string       `json:"collector"`
}

// CertifyVuln is an attestation that represents when a package has a vulnerability
type CertifyVuln struct {
	// package (subject) - the package object type that represents the package
	Package *Package `json:"package"`
	// vulnerability (object) - union type that consists of osv, cve or ghsa
	Vulnerability OsvCveOrGhsa `json:"vulnerability"`
	// metadata (property) - contains all the vulnerability metadata
	Metadata *VulnerabilityMetaData `json:"metadata"`
}

// CertifyVulnSpec allows filtering the list of CertifyVuln to return.
//
// Specifying just the package allows to query for all vulnerabilities associated with the package.
// Only OSV, CVE or GHSA can be specified at once
type CertifyVulnSpec struct {
	Package        *PkgSpec          `json:"package"`
	Vulnerability  *OsvCveOrGhsaSpec `json:"vulnerability"`
	TimeScanned    *time.Time        `json:"timeScanned"`
	DbURI          *string           `json:"dbUri"`
	DbVersion      *string           `json:"dbVersion"`
	ScannerURI     *string           `json:"scannerUri"`
	ScannerVersion *string           `json:"scannerVersion"`
	Origin         *string           `json:"origin"`
	Collector      *string           `json:"collector"`
}

// GHSA represents GitHub security advisories.
//
// We create a separate node to allow retrieving all GHSAs.
type Ghsa struct {
	GhsaID []*GHSAId `json:"ghsaId"`
}

func (Ghsa) IsOsvCveOrGhsa() {}

func (Ghsa) IsCveGhsaObject() {}

// GHSAId is the actual ID that is given to a specific vulnerability on GitHub
//
// The `id` field is mandatory and canonicalized to be lowercase.
//
// This node can be referred to by other parts of GUAC.
type GHSAId struct {
	ID string `json:"id"`
}

// GHSAInputSpec is the same as GHSASpec, but used for mutation ingestion.
type GHSAInputSpec struct {
	GhsaID string `json:"ghsaId"`
}

// GHSASpec allows filtering the list of GHSA to return.
//
// The argument will be canonicalized to lowercase.
type GHSASpec struct {
	GhsaID *string `json:"ghsaId"`
}

// HasSBOM is an attestation represents that a package object or source object has an SBOM associated with a uri
//
// subject - union type that can be either a package or source object type
// uri (property) - identifier string for the SBOM
// origin (property) - where this attestation was generated from (based on which document)
// collector (property) - the GUAC collector that collected the document that generated this attestation
//
// Note: Only package object or source object can be defined. Not both.
type HasSbom struct {
	Subject   PkgSrcObject `json:"subject"`
	URI       string       `json:"uri"`
	Origin    string       `json:"origin"`
	Collector string       `json:"collector"`
}

// HashEqualSpec allows filtering the list of HasSBOM to return.
//
// Only the package or source can be added, not both. HasSourceAt will be used to create the package to source
// relationship.
type HasSBOMSpec struct {
	Package   *PkgSpec    `json:"package"`
	Source    *SourceSpec `json:"source"`
	URI       *string     `json:"uri"`
	Origin    *string     `json:"origin"`
	Collector *string     `json:"collector"`
}

// HasSLSA records that a subject node has a SLSA attestation.
type HasSlsa struct {
	// The subject of SLSA attestation: package, source, or artifact.
	Subject PackageSourceOrArtifact `json:"subject"`
	// The SLSA attestation.
	Slsa *Slsa `json:"slsa"`
}

// HasSLSASpec allows filtering the list of HasSLSA to return.
type HasSLSASpec struct {
	Package           *PkgSpec             `json:"package"`
	Source            *SourceSpec          `json:"source"`
	Artifact          *ArtifactSpec        `json:"artifact"`
	BuiltFromPackages []*PkgSpec           `json:"builtFromPackages"`
	BuiltFromSource   []*SourceSpec        `json:"builtFromSource"`
	BuiltFromArtifact []*ArtifactSpec      `json:"builtFromArtifact"`
	BuiltBy           *BuilderSpec         `json:"builtBy"`
	BuildType         *string              `json:"buildType"`
	Predicate         []*SLSAPredicateSpec `json:"predicate"`
	SlsaVersion       *string              `json:"slsaVersion"`
	StartedOn         *time.Time           `json:"startedOn"`
	FinishedOn        *time.Time           `json:"finishedOn"`
	Origin            *string              `json:"origin"`
	Collector         *string              `json:"collector"`
}

// HasSourceAt is an attestation represents that a package object has a source object since a timestamp
//
// package (subject) - the package object type that represents the package
// source (object) - the source object type that represents the source
// knownSince (property) - timestamp when this was last checked (exact time)
// justification (property) - string value representing why the package has a source specified
// origin (property) - where this attestation was generated from (based on which document)
// collector (property) - the GUAC collector that collected the document that generated this attestation
type HasSourceAt struct {
	Package       *Package `json:"package"`
	Source        *Source  `json:"source"`
	KnownSince    string   `json:"knownSince"`
	Justification string   `json:"justification"`
	Origin        string   `json:"origin"`
	Collector     string   `json:"collector"`
}

// HasSourceAtSpec allows filtering the list of HasSourceAt to return.
type HasSourceAtSpec struct {
	Package       *PkgSpec    `json:"package"`
	Source        *SourceSpec `json:"source"`
	KnownSince    *string     `json:"knownSince"`
	Justification *string     `json:"justification"`
	Origin        *string     `json:"origin"`
	Collector     *string     `json:"collector"`
}

// HashEqual is an attestation that represents when two artifact hash are similar based on a justification.
//
// artifacts (subject) - the artifacts (represented by algorithm and digest) that are equal
// justification (property) - string value representing why the artifacts are the equal
// origin (property) - where this attestation was generated from (based on which document)
// collector (property) - the GUAC collector that collected the document that generated this attestation
type HashEqual struct {
	Artifacts     []*Artifact `json:"artifacts"`
	Justification string      `json:"justification"`
	Origin        string      `json:"origin"`
	Collector     string      `json:"collector"`
}

// HashEqualSpec allows filtering the list of HashEqual to return.
//
// Specifying just the artifacts allows to query for all equivalent artifacts (if they exist)
type HashEqualSpec struct {
	Artifacts     []*ArtifactSpec `json:"artifacts"`
	Justification *string         `json:"justification"`
	Origin        *string         `json:"origin"`
	Collector     *string         `json:"collector"`
}

// IsDependency is an attestation that represents when a package is dependent on another package
//
// package (subject) - the package object type that represents the package
// dependentPackage (object) - the package object type that represents the packageName (cannot be to the packageVersion)
// versionRange (property) - string value for version range that applies to the dependent package
// justification (property) - string value representing why the artifacts are the equal
// origin (property) - where this attestation was generated from (based on which document)
// collector (property) - the GUAC collector that collected the document that generated this attestation
type IsDependency struct {
	Package          *Package `json:"package"`
	DependentPackage *Package `json:"dependentPackage"`
	VersionRange     string   `json:"versionRange"`
	Justification    string   `json:"justification"`
	Origin           string   `json:"origin"`
	Collector        string   `json:"collector"`
}

// IsDependencyInputSpec is the same as IsDependency but for mutation input.
//
// All fields are required.
type IsDependencyInputSpec struct {
	VersionRange  string `json:"versionRange"`
	Justification string `json:"justification"`
	Origin        string `json:"origin"`
	Collector     string `json:"collector"`
}

// IsDependencySpec allows filtering the list of IsDependency to return.
//
// Note: the package object must be defined to return its dependent packages.
// Dependent Packages must represent the packageName (cannot be the packageVersion)
type IsDependencySpec struct {
	Package          *PkgSpec     `json:"package"`
	DependentPackage *PkgNameSpec `json:"dependentPackage"`
	VersionRange     *string      `json:"versionRange"`
	Justification    *string      `json:"justification"`
	Origin           *string      `json:"origin"`
	Collector        *string      `json:"collector"`
}

// IsOccurrence is an attestation represents when either a package or source is represented by an artifact
//
// subject - union type that can be either a package or source object type
// occurrenceArtifact (object) - artifact that represent the the package or source
// justification (property) - string value representing why the package or source is represented by the specified artifact
// origin (property) - where this attestation was generated from (based on which document)
// collector (property) - the GUAC collector that collected the document that generated this attestation
//
// Note: Package or Source must be specified but not both at the same time.
// Attestation must occur at the PackageName or the PackageVersion or at the SourceName.
//
// HashEqual will be used to connect together two artifacts if a package or source
// is represented by more than one artifact.
//
// IsOccurrence does not connect a package with a source.
// HasSourceAt attestation will be used to connect a package with a source
type IsOccurrence struct {
	Subject            PkgSrcObject `json:"subject"`
	OccurrenceArtifact *Artifact    `json:"occurrenceArtifact"`
	Justification      string       `json:"justification"`
	Origin             string       `json:"origin"`
	Collector          string       `json:"collector"`
}

// IsOccurrenceInputSpec is the same as IsOccurrence but for mutation input.
//
// All fields are required.
type IsOccurrenceInputSpec struct {
	Justification string `json:"justification"`
	Origin        string `json:"origin"`
	Collector     string `json:"collector"`
}

// IsOccurrenceSpec allows filtering the list of IsOccurrence to return.
// Note: Package or Source must be specified but not both at the same time
// For package - a PackageName or PackageVersion must be specified (name or name, version, qualifiers and subpath)
// For source - a SourceName must be specified (name, tag or commit)
type IsOccurrenceSpec struct {
	Package       *PkgSpec      `json:"package"`
	Source        *SourceSpec   `json:"source"`
	Artifact      *ArtifactSpec `json:"artifact"`
	Justification *string       `json:"justification"`
	Origin        *string       `json:"origin"`
	Collector     *string       `json:"collector"`
}

// IsVulnerability is an attestation that represents when an OSV ID represents a CVE or GHSA
//
// osv (subject) - the osv object type that represents OSV and its ID
// vulnerability (object) - union type that consists of cve or ghsa
// justification (property) - the reason why the osv ID represents the cve or ghsa
// origin (property) - where this attestation was generated from (based on which document)
// collector (property) - the GUAC collector that collected the document that generated this attestation
type IsVulnerability struct {
	Osv           *Osv          `json:"osv"`
	Vulnerability CveGhsaObject `json:"vulnerability"`
	Justification string        `json:"justification"`
	Origin        string        `json:"origin"`
	Collector     string        `json:"collector"`
}

// IsVulnerabilitySpec allows filtering the list of IsVulnerability to return.
// Only CVE or GHSA can be specified at once.
type IsVulnerabilitySpec struct {
	Osv           *OSVSpec  `json:"osv"`
	Cve           *CVESpec  `json:"cve"`
	Ghsa          *GHSASpec `json:"ghsa"`
	Justification *string   `json:"justification"`
	Origin        *string   `json:"origin"`
	Collector     *string   `json:"collector"`
}

// OSV represents an Open Source Vulnerability.
//
// We create a separate node to allow retrieving all OSVs.
type Osv struct {
	OsvID []*OSVId `json:"osvId"`
}

func (Osv) IsOsvCveOrGhsa() {}

// OSVId is the actual ID that is given to a specific vulnerability.
//
// The `id` field is mandatory and canonicalized to be lowercase.
//
// This maps to a vulnerability ID specific to the environment (e.g., GHSA ID or
// CVE ID).
//
// This node can be referred to by other parts of GUAC.
type OSVId struct {
	ID string `json:"id"`
}

// OSVInputSpec is the same as OSVSpec, but used for mutation ingestion.
type OSVInputSpec struct {
	OsvID string `json:"osvId"`
}

// OSVSpec allows filtering the list of OSV to return.
type OSVSpec struct {
	OsvID *string `json:"osvId"`
}

// OsvCveOrGhsaInput allows using OsvCveOrGhsa union as
// input type to be used in mutations.
// Exactly one of the value must be set to non-nil.
type OsvCveOrGhsaInput struct {
	Osv  *OSVInputSpec  `json:"osv"`
	Cve  *CVEInputSpec  `json:"cve"`
	Ghsa *GHSAInputSpec `json:"ghsa"`
}

// OsvCveOrGhsaSpec allows using OsvCveOrGhsa union as
// input type to be used in read queries.
// Exactly one of the value must be set to non-nil.
type OsvCveOrGhsaSpec struct {
	Osv  *OSVSpec  `json:"osv"`
	Cve  *CVESpec  `json:"cve"`
	Ghsa *GHSASpec `json:"ghsa"`
}

// Package represents a package.
//
// In the pURL representation, each Package matches a `pkg:<type>` partial pURL.
// The `type` field matches the pURL types but we might also use `"guac"` for the
// cases where the pURL representation is not complete or when we have custom
// rules.
//
// This node is a singleton: backends guarantee that there is exactly one node
// with the same `type` value.
//
// Also note that this is named `Package`, not `PackageType`. This is only to make
// queries more readable.
type Package struct {
	Type       string              `json:"type"`
	Namespaces []*PackageNamespace `json:"namespaces"`
}

func (Package) IsPkgArtObject() {}

func (Package) IsPkgSrcObject() {}

func (Package) IsPackageSourceOrArtifact() {}

// PackageName is a name for packages.
//
// In the pURL representation, each PackageName matches the
// `pkg:<type>/<namespace>/<name>` pURL.
//
// Names are always mandatory.
//
// This is the first node in the trie that can be referred to by other parts of
// GUAC.
type PackageName struct {
	Name     string            `json:"name"`
	Versions []*PackageVersion `json:"versions"`
}

// PackageNamespace is a namespace for packages.
//
// In the pURL representation, each PackageNamespace matches the
// `pkg:<type>/<namespace>/` partial pURL.
//
// Namespaces are optional and type specific. Because they are optional, we use
// empty string to denote missing namespaces.
type PackageNamespace struct {
	Namespace string         `json:"namespace"`
	Names     []*PackageName `json:"names"`
}

// PackageQualifier is a qualifier for a package, a key-value pair.
//
// In the pURL representation, it is a part of the `<qualifiers>` part of the
// `pkg:<type>/<namespace>/<name>@<version>?<qualifiers>` pURL.
//
// Qualifiers are optional, each Package type defines own rules for handling them,
// and multiple qualifiers could be attached to the same package.
//
// This node cannot be directly referred by other parts of GUAC.
type PackageQualifier struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// PackageQualifierInputSpec is the same as PackageQualifier, but usable as
// mutation input.
//
// GraphQL does not allow input types to contain composite types and does not allow
// composite types to contain input types. So, although in this case these two
// types are semantically the same, we have to duplicate the definition.
//
// Both fields are mandatory.
type PackageQualifierInputSpec struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// PackageQualifierSpec is the same as PackageQualifier, but usable as query
// input.
//
// GraphQL does not allow input types to contain composite types and does not allow
// composite types to contain input types. So, although in this case these two
// types are semantically the same, we have to duplicate the definition.
//
// Keys are mandatory, but values could also be `null` if we want to match all
// values for a specific key.
//
// TODO(mihaimaruseac): Formalize empty vs null when the schema is fully done
type PackageQualifierSpec struct {
	Key   string  `json:"key"`
	Value *string `json:"value"`
}

// PackageVersion is a package version.
//
// In the pURL representation, each PackageName matches the
// `pkg:<type>/<namespace>/<name>@<version>` pURL.
//
// Versions are optional and each Package type defines own rules for handling them.
// For this level of GUAC, these are just opaque strings.
//
// This node can be referred to by other parts of GUAC.
//
// Subpath and qualifiers are optional. Lack of qualifiers is represented by an
// empty list and lack of subpath by empty string (to be consistent with
// optionality of namespace and version). Two nodes that have different qualifiers
// and/or subpath but the same version mean two different packages in the trie
// (they are different). Two nodes that have same version but qualifiers of one are
// a subset of the qualifier of the other also mean two different packages in the
// trie.
type PackageVersion struct {
	Version    string              `json:"version"`
	Qualifiers []*PackageQualifier `json:"qualifiers"`
	Subpath    string              `json:"subpath"`
}

// PkgInputSpec specifies a package for a mutation.
//
// This is different than PkgSpec because we want to encode mandatory fields:
// `type` and `name`. All optional fields are given empty default values.
type PkgInputSpec struct {
	Type       string                       `json:"type"`
	Namespace  *string                      `json:"namespace"`
	Name       string                       `json:"name"`
	Version    *string                      `json:"version"`
	Qualifiers []*PackageQualifierInputSpec `json:"qualifiers"`
	Subpath    *string                      `json:"subpath"`
}

// PkgNameSpec is used for IsDependency to input dependent packages. This is different from PkgSpec
// as the IsDependency attestation should only be allowed to be made to the packageName node and not the
// packageVersion node. Versions will be handled by the version_range in the IsDependency attestation node.
type PkgNameSpec struct {
	Type      *string `json:"type"`
	Namespace *string `json:"namespace"`
	Name      *string `json:"name"`
}

// PkgSpec allows filtering the list of packages to return.
//
// Each field matches a qualifier from pURL. Use `null` to match on all values at
// that level. For example, to get all packages in GUAC backend, use a PkgSpec
// where every field is `null`.
//
// Empty string at a field means matching with the empty string. If passing in
// qualifiers, all of the values in the list must match. Since we want to return
// nodes with any number of qualifiers if no qualifiers are passed in the input, we
// must also return the same set of nodes it the qualifiers list is empty. To match
// on nodes that don't contain any qualifier, set `matchOnlyEmptyQualifiers` to
// true. If this field is true, then the qualifiers argument is ignored.
type PkgSpec struct {
	Type                     *string                 `json:"type"`
	Namespace                *string                 `json:"namespace"`
	Name                     *string                 `json:"name"`
	Version                  *string                 `json:"version"`
	Qualifiers               []*PackageQualifierSpec `json:"qualifiers"`
	MatchOnlyEmptyQualifiers *bool                   `json:"matchOnlyEmptyQualifiers"`
	Subpath                  *string                 `json:"subpath"`
}

// SLSA contains all of the fields present in a SLSA attestation.
//
// The materials and builders are objects of the HasSLSA predicate, everything
// else are properties extracted from the attestation.
//
// We also include fields to specify under what conditions the check was performed
// (time of scan, version of scanners, etc.) as well as how this information got
// included into GUAC (origin document and the collector for that document).
type Slsa struct {
	// Sources of the build resulting in subject (materials)
	BuiltFrom []PackageSourceOrArtifact `json:"builtFrom"`
	// Builder performing the build
	BuiltBy *Builder `json:"builtBy"`
	// Type of the builder
	BuildType string `json:"buildType"`
	// Individual predicates found in the attestation
	SlsaPredicate []*SLSAPredicate `json:"slsaPredicate"`
	// Version of the SLSA predicate
	SlsaVersion string `json:"slsaVersion"`
	// Timestamp (RFC3339Nano format) of build start time
	StartedOn time.Time `json:"startedOn"`
	// Timestamp (RFC3339Nano format) of build end time
	FinishedOn time.Time `json:"finishedOn"`
	// Document from which this attestation is generated from
	Origin string `json:"origin"`
	// GUAC collector for the document
	Collector string `json:"collector"`
}

// SLSAPredicate are the values from the SLSA predicate in key-value pair form.
//
// # For example, given the following predicate
//
// ```
//
//	"predicate": {
//	  "buildDefinition": {
//	    "externalParameters": {
//	      "repository": "https://github.com/octocat/hello-world",
//	      ...
//	    },
//	    ...
//	  },
//	  ...
//	}
//
// ```
//
// we have
//
// ```
// key   = "buildDefinition.externalParameters.repository"
// value = "https://github.com/octocat/hello-world"
// ```
//
// This node cannot be directly referred by other parts of GUAC.
//
// TODO(mihaimaruseac): Can we define these directly?
type SLSAPredicate struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// SLSAPredicateSpec is the same as SLSAPredicateSpec, but usable as query
// input.
type SLSAPredicateSpec struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Scorecard contains all of the fields present in a Scorecard attestation.
//
// We also include fields to specify under what conditions the check was performed
// (time of scan, version of scanners, etc.) as well as how this information got
// included into GUAC (origin document and the collector for that document).
type Scorecard struct {
	// Individual Scorecard check scores (Branch-Protection, Code-Review, ...)
	Checks []*ScorecardCheck `json:"checks"`
	// Overall Scorecard score for the source
	AggregateScore float64 `json:"aggregateScore"`
	// Exact timestamp when the source was last scanned (in RFC 3339 format)
	TimeScanned time.Time `json:"timeScanned"`
	// Version of the Scorecard scanner used to analyze the source
	ScorecardVersion string `json:"scorecardVersion"`
	// Commit of the Scorecards repository at the time of scanning the source
	ScorecardCommit string `json:"scorecardCommit"`
	// Document from which this attestation is generated from
	Origin string `json:"origin"`
	// GUAC collector for the document
	Collector string `json:"collector"`
}

// ScorecardCheck are the individual checks from scorecard and their values as a
// key-value pair.
//
// For example:  Branch-Protection, Code-Review...etc
//
// Based off scorecard's:
//
//	type jsonCheckResultV2 struct {
//	  Details []string                 `json:"details"`
//	  Score   int                      `json:"score"`
//	  Reason  string                   `json:"reason"`
//	  Name    string                   `json:"name"`
//	  Doc     jsonCheckDocumentationV2 `json:"documentation"`
//	}
//
// This node cannot be directly referred by other parts of GUAC.
type ScorecardCheck struct {
	Check string `json:"check"`
	Score int    `json:"score"`
}

// ScorecardCheckInputSpec is the same as ScorecardCheck, but for mutation input.
type ScorecardCheckInputSpec struct {
	Check string `json:"check"`
	Score int    `json:"score"`
}

// ScorecardCheckSpec is the same as ScorecardCheck, but usable as query input.
type ScorecardCheckSpec struct {
	Check string `json:"check"`
	Score int    `json:"score"`
}

// ScorecardInputSpec is the same as Scorecard but for mutation input.
//
// All fields are required.
type ScorecardInputSpec struct {
	Checks           []*ScorecardCheckInputSpec `json:"checks"`
	AggregateScore   float64                    `json:"aggregateScore"`
	TimeScanned      time.Time                  `json:"timeScanned"`
	ScorecardVersion string                     `json:"scorecardVersion"`
	ScorecardCommit  string                     `json:"scorecardCommit"`
	Origin           string                     `json:"origin"`
	Collector        string                     `json:"collector"`
}

// Source represents a source.
//
// This can be the version control system that is being used.
//
// This node is a singleton: backends guarantee that there is exactly one node
// with the same `type` value.
//
// Also note that this is named `Source`, not `SourceType`. This is only to make
// queries more readable.
type Source struct {
	Type       string             `json:"type"`
	Namespaces []*SourceNamespace `json:"namespaces"`
}

func (Source) IsPkgSrcObject() {}

func (Source) IsPackageSourceOrArtifact() {}

// SourceInputSpec specifies a source for a mutation.
//
// This is different than SourceSpec because we want to encode that all fields
// except tag and commit are mandatory fields. All optional fields are given
// empty default values.
//
// It is an error to set both `tag` and `commit` fields to values different than
// the default.
type SourceInputSpec struct {
	Type      string  `json:"type"`
	Namespace string  `json:"namespace"`
	Name      string  `json:"name"`
	Tag       *string `json:"tag"`
	Commit    *string `json:"commit"`
}

// SourceName is a url of the repository and its tag or commit.
//
// The `name` field is mandatory. The `tag` and `commit` fields are optional, but
// it is an error to specify both.
//
// This is the only source trie node that can be referenced by other parts of
// GUAC.
type SourceName struct {
	Name   string  `json:"name"`
	Tag    *string `json:"tag"`
	Commit *string `json:"commit"`
}

// SourceNamespace is a namespace for sources.
//
// This is the location of the repository (such as github/gitlab/bitbucket).
//
// The `namespace` field is mandatory.
type SourceNamespace struct {
	Namespace string        `json:"namespace"`
	Names     []*SourceName `json:"names"`
}

// SourceSpec allows filtering the list of sources to return.
//
// Empty string at a field means matching with the empty string. Missing field
// means retrieving all possible matches.
//
// It is an error to specify both `tag` and `commit` fields, except it both are
// set as empty string (in which case the returned sources are only those for
// which there is no tag/commit information).
type SourceSpec struct {
	Type      *string `json:"type"`
	Namespace *string `json:"namespace"`
	Name      *string `json:"name"`
	Tag       *string `json:"tag"`
	Commit    *string `json:"commit"`
}

type VulnerabilityMetaData struct {
	// timeScanned (property) - timestamp of when the package was last scanned
	TimeScanned time.Time `json:"timeScanned"`
	// dbUri (property) - scanner vulnerability database uri
	DbURI string `json:"dbUri"`
	// dbVersion (property) - scanner vulnerability database version
	DbVersion string `json:"dbVersion"`
	// scannerUri (property) - vulnerability scanner's uri
	ScannerURI string `json:"scannerUri"`
	// scannerVersion (property) - vulnerability scanner version
	ScannerVersion string `json:"scannerVersion"`
	// origin (property) - where this attestation was generated from (based on which document)
	Origin string `json:"origin"`
	// collector (property) - the GUAC collector that collected the document that generated this attestation
	Collector string `json:"collector"`
}

// VulnerabilityInputSpec is the same as VulnerabilityMetaData but for mutation input.
//
// All fields are required.
type VulnerabilityMetaDataInput struct {
	TimeScanned    time.Time `json:"timeScanned"`
	DbURI          string    `json:"dbUri"`
	DbVersion      string    `json:"dbVersion"`
	ScannerURI     string    `json:"scannerUri"`
	ScannerVersion string    `json:"scannerVersion"`
	Origin         string    `json:"origin"`
	Collector      string    `json:"collector"`
}
