//
// Copyright 2022 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package assembler

// ArtifactNode is a node that represents an artifact
type ArtifactNode struct {
	Name   string
	Digest string
	Tags   []string
}

func (an ArtifactNode) Type() string {
	return "Artifact"
}

func (an ArtifactNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["name"] = an.Name
	properties["digest"] = an.Digest
	properties["tags"] = an.Tags
	return properties
}

func (an ArtifactNode) PropertyNames() []string {
	return []string{"name", "digest", "tags"}
}

func (an ArtifactNode) IdentifiablePropertyNames() []string {
	// An artifact can be uniquely identified by digest
	return []string{"digest"}
}

// PackageNode is a node that represents an artifact
type PackageNode struct {
	Name   string
	Digest []string
	Purl   string
	CPEs   []string
	Tags   []string
}

func (an PackageNode) Type() string {
	return "Package"
}

func (an PackageNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["name"] = an.Name
	properties["purl"] = an.Purl
	properties["cpes"] = an.CPEs
	properties["digest"] = an.Digest
	properties["tags"] = an.Tags
	return properties
}

func (an PackageNode) PropertyNames() []string {
	return []string{"name", "digest", "purl", "cpes", "tags"}
}

func (an PackageNode) IdentifiablePropertyNames() []string {
	return []string{"purl"}
}

// IdentityNode is a node that represents an identity
type IdentityNode struct {
	ID     string
	Digest string
	// base64 encoded
	Key       string
	KeyType   string
	KeyScheme string
}

func (in IdentityNode) Type() string {
	return "Identity"
}

func (in IdentityNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["id"] = in.ID
	properties["digest"] = in.Digest
	properties["key"] = in.Key
	properties["keyType"] = in.KeyType
	properties["keyScheme"] = in.KeyScheme
	return properties
}

func (in IdentityNode) PropertyNames() []string {
	return []string{"id", "digest", "key", "keyType", "keyScheme"}
}

func (in IdentityNode) IdentifiablePropertyNames() []string {
	// An identity can be uniquely identified by digest
	return []string{"digest"}
}

// AttestationNode is a node that represents an attestation
type AttestationNode struct {
	// TODO(mihaimaruseac): Unsure what fields to store here
	FilePath string
	Digest   string
}

func (an AttestationNode) Type() string {
	return "Attestation"
}

func (an AttestationNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["filepath"] = an.FilePath
	properties["digest"] = an.Digest
	return properties
}

func (an AttestationNode) PropertyNames() []string {
	return []string{"filepath", "digest"}
}

func (an AttestationNode) IdentifiablePropertyNames() []string {
	return []string{"digest"}
}

// BuilderNode is a node that represents a builder for an artifact
type BuilderNode struct {
	BuilderType string
	BuilderId   string
}

func (bn BuilderNode) Type() string {
	return "Builder"
}

func (bn BuilderNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["type"] = bn.BuilderType
	properties["id"] = bn.BuilderId
	return properties
}

func (bn BuilderNode) PropertyNames() []string {
	return []string{"type", "id"}
}

func (bn BuilderNode) IdentifiablePropertyNames() []string {
	// A builder needs both type and id to be identified
	return []string{"type", "id"}
}

// ScorecardNode is a node that represents an artifact
type ScorecardNode struct {
	MetadataType     string
	Repo             string
	Commit           string
	ScorecardVersion string
	ScorecardCommit  string
	Score            float64

	// Checks
	CheckBinaryArtifact     int
	CheckCITests            int
	CheckCodeReview         int
	CheckDangerousWorkflow  int
	CheckLicense            int
	CheckPinnedDependencies int
	CheckSecurityPolicy     int
	CheckTokenPermissions   int
	CheckVulnerabilities    int
}

func (sn ScorecardNode) Type() string {
	return "Scorecard"
}

func (sn ScorecardNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["metadata_type"] = sn.MetadataType
	properties["repo"] = sn.Repo
	properties["commit"] = sn.Commit
	properties["scorecard_version"] = sn.ScorecardVersion
	properties["scorecard_commit"] = sn.ScorecardCommit
	properties["score"] = sn.Score

	properties["check_binary_artifact"] = sn.CheckBinaryArtifact
	properties["check_ci_tests"] = sn.CheckCITests
	properties["check_code_review"] = sn.CheckCodeReview
	properties["check_dangerous_workflow"] = sn.CheckDangerousWorkflow
	properties["check_license"] = sn.CheckLicense
	properties["check_pinned_dependencies"] = sn.CheckPinnedDependencies
	properties["check_security_policy"] = sn.CheckSecurityPolicy
	properties["check_token_permissions"] = sn.CheckTokenPermissions
	properties["check_vulnerabilities"] = sn.CheckVulnerabilities

	return properties
}

func (sn ScorecardNode) PropertyNames() []string {
	return []string{"metadata_type", "repo", "commit", "scorecard_version", "scorecard_commit", "score",
		"check_binary_artifact", "check_ci_tests", "check_code_review", "check_dangerous_workflow",
		"check_license", "check_pinned_dependencies", "check_security_policy",
		"check_token_permissions", "check_vulnerabilities",
	}

}

func (sn ScorecardNode) IdentifiablePropertyNames() []string {
	return []string{"repo", "commit"}
}

// IdentityForEdge is an edge that represents the fact that an
// `IdentityNode` is an identity for an `AttestationNode`.
type IdentityForEdge struct {
	IdentityNode    IdentityNode
	AttestationNode AttestationNode
}

func (e IdentityForEdge) Type() string {
	return "Identity"
}

func (e IdentityForEdge) Nodes() (v, u GuacNode) {
	return e.IdentityNode, e.AttestationNode
}

func (e IdentityForEdge) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e IdentityForEdge) PropertyNames() []string {
	return []string{}
}

func (e IdentityForEdge) IdentifiablePropertyNames() []string {
	return []string{}
}

// AttestationForEdge is an edge that represents the fact that an
// `AttestationNode` is an attestation for an `ArtifactNode`.
type AttestationForEdge struct {
	AttestationNode AttestationNode
	ArtifactNode    ArtifactNode
}

func (e AttestationForEdge) Type() string {
	return "Attestation"
}

func (e AttestationForEdge) Nodes() (v, u GuacNode) {
	return e.AttestationNode, e.ArtifactNode
}

func (e AttestationForEdge) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e AttestationForEdge) PropertyNames() []string {
	return []string{}
}

func (e AttestationForEdge) IdentifiablePropertyNames() []string {
	return []string{}
}

// BuiltByEdge is an edge that represents the fact that an
// `ArtifactNode` has been built by a `BuilderNode`
type BuiltByEdge struct {
	ArtifactNode ArtifactNode
	BuilderNode  BuilderNode
}

func (e BuiltByEdge) Type() string {
	return "BuiltBy"
}

func (e BuiltByEdge) Nodes() (v, u GuacNode) {
	return e.ArtifactNode, e.BuilderNode
}

func (e BuiltByEdge) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e BuiltByEdge) PropertyNames() []string {
	return []string{}
}

func (e BuiltByEdge) IdentifiablePropertyNames() []string {
	return []string{}
}

// DependsOnEdge is an edge that represents the fact that an
// `ArtifactNode/PackageNode` depends on another `ArtifactNode/PackageNode`
// Only one of each side of the edge should be defined.
type DependsOnEdge struct {
	ArtifactNode       ArtifactNode
	PackageNode        PackageNode
	ArtifactDependency ArtifactNode
	PackageDependency  PackageNode
}

func (e DependsOnEdge) Type() string {
	return "DependsOn"
}

func (e DependsOnEdge) Nodes() (v, u GuacNode) {
	vA, vP := isDefined(e.ArtifactNode), isDefined(e.PackageNode)
	uA, uP := isDefined(e.ArtifactDependency), isDefined(e.PackageDependency)
	if vA == vP {
		panic("only one of package and artifact node defined for DependsOn relationship")
	}

	if uA == uP {
		panic("only on of package and artifact dependency node defined for DependsOn relationship")
	}

	if vA {
		v = e.ArtifactNode
	} else {
		v = e.PackageNode
	}

	if uA {
		u = e.ArtifactDependency
	} else {
		u = e.PackageDependency
	}

	return v, u
}

func (e DependsOnEdge) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e DependsOnEdge) PropertyNames() []string {
	return []string{}
}

func (e DependsOnEdge) IdentifiablePropertyNames() []string {
	return []string{}
}

// Contains is an edge that represents the fact that an
// `PackageNode` contains a `ArtifactNode`
type ContainsEdge struct {
	PackageNode       PackageNode
	ContainedArtifact ArtifactNode
}

func (e ContainsEdge) Type() string {
	return "Contains"
}

func (e ContainsEdge) Nodes() (v, u GuacNode) {
	return e.PackageNode, e.ContainedArtifact
}

func (e ContainsEdge) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e ContainsEdge) PropertyNames() []string {
	return []string{}
}

func (e ContainsEdge) IdentifiablePropertyNames() []string {
	return []string{}
}

// MetadataFor is an edge that represents the fact that an
// a metadata node represents metadata for an `ArtifactNode/PackageNode`
// Only one of each side of the edge should be defined.
type MetadataForEdge struct {
	// From node
	MetadataScorecard ScorecardNode
	// To node
	ForArtifact ArtifactNode
	ForPackage  PackageNode
}

func (e MetadataForEdge) Type() string {
	return "MetadataFor"
}

func (e MetadataForEdge) Nodes() (v, u GuacNode) {
	uA, uP := isDefined(e.ForArtifact), isDefined(e.ForPackage)
	if uA == uP {
		panic("only on of package and artifact dependency node defined for DependsOn relationship")
	}

	v = e.MetadataScorecard
	if uA {
		u = e.ForArtifact
	} else {
		u = e.ForPackage
	}

	return v, u
}

func (e MetadataForEdge) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e MetadataForEdge) PropertyNames() []string {
	return []string{}
}

func (e MetadataForEdge) IdentifiablePropertyNames() []string {
	return []string{}
}
