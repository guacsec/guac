// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package model

// Currently artifacts and packages can depend on each other. Hence, we need a union for this edge.
type ArtifactOrPackage interface {
	IsArtifactOrPackage()
}

type AttestationPayload interface {
	IsAttestationPayload()
}

type MetadataPayload interface {
	IsMetadataPayload()
}

// NodeInfo contains fields that are common for any GUAC node. These are metadata
// information that allows identifying the collector details from which a node
// gets created after parsing a document.
type NodeInfo interface {
	IsNodeInfo()
	// sourceInfo is the file location for the document from which the node was
	// created.
	GetSourceInfo() *string
	// collectorInfo is the collector from which the file that created the node came
	// from
	GetCollectorInfo() *string
}

// Artifact nodes represent artifacts. These are files on disk (cf. Package).
// There could be artifacts not included in any package.
type Artifact struct {
	// digest is the identifier of an artifact. It is in the format
	// `algorithm:value` where `algorithm` is the hashing algorithm (e.g. "sha1")
	// and `value` is the digest obtained by using this algorithm.
	//
	// Note: in the future we might change this to contain a collection of hashes,
	// at which point we will need other ways to resolve an artifact given a digest.
	Digest string `json:"digest"`
	// name of the artifact
	Name *string `json:"name"`
	// tags associated with the artifact
	Tags          []string            `json:"tags"`
	SourceInfo    *string             `json:"sourceInfo"`
	CollectorInfo *string             `json:"collectorInfo"`
	BuiltBy       []*Builder          `json:"builtBy"`
	DependsOn     []ArtifactOrPackage `json:"dependsOn"`
}

func (Artifact) IsNodeInfo() {}

// sourceInfo is the file location for the document from which the node was
// created.
func (this Artifact) GetSourceInfo() *string { return this.SourceInfo }

// collectorInfo is the collector from which the file that created the node came
// from
func (this Artifact) GetCollectorInfo() *string { return this.CollectorInfo }

func (Artifact) IsArtifactOrPackage() {}

// Attestation nodes represent attestations about artifacts and packages.
type Attestation struct {
	// digest is the identifier of an attestation, uniquely identifying it.
	//
	// Note: in the future we might change this to contain a collection of hashes,
	// at which point we will need other ways to resolve an identity given a digest.
	Digest string `json:"digest"`
	// filePath is the path to the attestation, during ingestion
	FilePath *string `json:"filePath"`
	// type is the attestation type (SLSA/VEX/...?)
	Type *string `json:"type"`
	// payload is additional payload on the attestation, depending on type
	Payload         AttestationPayload  `json:"payload"`
	SourceInfo      *string             `json:"sourceInfo"`
	CollectorInfo   *string             `json:"collectorInfo"`
	AttestedObjects []ArtifactOrPackage `json:"attestedObjects"`
	Vulnerabilities []*Vulnerability    `json:"vulnerabilities"`
}

func (Attestation) IsNodeInfo() {}

// sourceInfo is the file location for the document from which the node was
// created.
func (this Attestation) GetSourceInfo() *string { return this.SourceInfo }

// collectorInfo is the collector from which the file that created the node came
// from
func (this Attestation) GetCollectorInfo() *string { return this.CollectorInfo }

// Builder nodes represent builders of artifacts (from provenance documents).
type Builder struct {
	// type is type of builder. Coupled with id, it uniquely identifies the builder.
	Type string `json:"type"`
	// id is the id of builder. Coupled with type, it uniquely identifies the builder.
	ID            string  `json:"id"`
	SourceInfo    *string `json:"sourceInfo"`
	CollectorInfo *string `json:"collectorInfo"`
}

func (Builder) IsNodeInfo() {}

// sourceInfo is the file location for the document from which the node was
// created.
func (this Builder) GetSourceInfo() *string { return this.SourceInfo }

// collectorInfo is the collector from which the file that created the node came
// from
func (this Builder) GetCollectorInfo() *string { return this.CollectorInfo }

// Identity nodes are ....
type Identity struct {
	// digest is the identifier of an identity, uniquely identifying it.
	//
	// Note: in the future we might change this to contain a collection of hashes,
	// at which point we will need other ways to resolve an identity given a digest.
	Digest string `json:"digest"`
	// id is the id of an identity.
	ID string `json:"id"`
	// key ...
	Key *string `json:"key"`
	// keyType ...
	KeyType *string `json:"keyType"`
	// keyScheme ...
	KeyScheme     *string        `json:"keyScheme"`
	SourceInfo    *string        `json:"sourceInfo"`
	CollectorInfo *string        `json:"collectorInfo"`
	Attestations  []*Attestation `json:"attestations"`
}

func (Identity) IsNodeInfo() {}

// sourceInfo is the file location for the document from which the node was
// created.
func (this Identity) GetSourceInfo() *string { return this.SourceInfo }

// collectorInfo is the collector from which the file that created the node came
// from
func (this Identity) GetCollectorInfo() *string { return this.CollectorInfo }

// Metadata nodes represent metadata about an artifact. These are extracted from attestations.
type Metadata struct {
	// type is type of metadata. Coupled with id, it uniquely identifies the metadata.
	Type string `json:"type"`
	// id is the id of metadata. Coupled with type, it uniquely identifies the metadata.
	ID string `json:"id"`
	// payload is additional payload on the attestation, depending on type
	Payload       MetadataPayload     `json:"payload"`
	SourceInfo    *string             `json:"sourceInfo"`
	CollectorInfo *string             `json:"collectorInfo"`
	AttachedTo    []ArtifactOrPackage `json:"attachedTo"`
}

func (Metadata) IsNodeInfo() {}

// sourceInfo is the file location for the document from which the node was
// created.
func (this Metadata) GetSourceInfo() *string { return this.SourceInfo }

// collectorInfo is the collector from which the file that created the node came
// from
func (this Metadata) GetCollectorInfo() *string { return this.CollectorInfo }

// Package nodes represent packages. These are packages from a package repository
// (cf. Artifact). Upon installing a package one or multiple artifacts could be
// generated.
type Package struct {
	// purl is the Package identifier, in purl format. Uniquely identifies the package.
	Purl string `json:"purl"`
	// name of the package
	Name *string `json:"name"`
	// version of the package
	Version *string `json:"version"`
	// digests for the package
	Digest []string `json:"digest"`
	// CPEs represent CPEs for the package
	CPEs []string `json:"CPEs"`
	// tags associated with the artifact
	Tags          []string            `json:"tags"`
	SourceInfo    *string             `json:"sourceInfo"`
	CollectorInfo *string             `json:"collectorInfo"`
	Contains      []*Artifact         `json:"contains"`
	DependsOn     []ArtifactOrPackage `json:"dependsOn"`
}

func (Package) IsNodeInfo() {}

// sourceInfo is the file location for the document from which the node was
// created.
func (this Package) GetSourceInfo() *string { return this.SourceInfo }

// collectorInfo is the collector from which the file that created the node came
// from
func (this Package) GetCollectorInfo() *string { return this.CollectorInfo }

func (Package) IsArtifactOrPackage() {}

// ScorecardPayload are payloads of Scorecards metadata.
type ScorecardPayload struct {
	Repo             string  `json:"repo"`
	Commit           string  `json:"commit"`
	ScorecardVersion string  `json:"scorecard_version"`
	ScorecardCommit  string  `json:"scorecard_commit"`
	AggregateScore   float64 `json:"aggregate_score"`
}

func (ScorecardPayload) IsMetadataPayload() {}

// VEXInvocation contains details about a VEX scan invocation
type VEXInvocation struct {
	Parameters []string `json:"parameters"`
	URI        string   `json:"uri"`
	EventID    string   `json:"eventID"`
	ProducerID string   `json:"producerID"`
	ScannedOn  string   `json:"scannedOn"`
}

// VEXPayload are payloads commonly found in VEX attestations.
type VEXPayload struct {
	// invocation represents data about the VEX scanner invocation
	Invocation *VEXInvocation `json:"invocation"`
	// scanner represents data about the VEX scanner process
	Scanner *VEXScanner `json:"scanner"`
	// vulnerability represents data about vulnerabilities found by VEX scanning
	Vulnerabilities []*VEXVulnerability `json:"vulnerabilities"`
}

func (VEXPayload) IsAttestationPayload() {}

// VEXScanner contains details about a scanner used by a VEX scan invocation
type VEXScanner struct {
	URI       string `json:"uri"`
	Version   string `json:"version"`
	DbURI     string `json:"db_uri"`
	DbVersion string `json:"db_version"`
}

// VEXVulnerability is a vulnerability found by a VEX scan invocation
type VEXVulnerability struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

// Vulnerability nodes represent vulnerability information
type Vulnerability struct {
	// id is the id of a vulnerability (cve??)
	ID            string  `json:"id"`
	SourceInfo    *string `json:"sourceInfo"`
	CollectorInfo *string `json:"collectorInfo"`
}

func (Vulnerability) IsNodeInfo() {}

// sourceInfo is the file location for the document from which the node was
// created.
func (this Vulnerability) GetSourceInfo() *string { return this.SourceInfo }

// collectorInfo is the collector from which the file that created the node came
// from
func (this Vulnerability) GetCollectorInfo() *string { return this.CollectorInfo }
