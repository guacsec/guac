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

import "strings"

// ArtifactNode is a node that represents an artifact
type ArtifactNode struct {
	Name     string
	Digest   string
	Tags     []string
	NodeData objectMetadata
}

func (an ArtifactNode) Type() string {
	return "Artifact"
}

func (an ArtifactNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["name"] = an.Name
	properties["digest"] = strings.ToLower(an.Digest)
	properties["tags"] = an.Tags
	an.NodeData.addProperties(properties)
	return properties
}

func (an ArtifactNode) PropertyNames() []string {
	fields := []string{"name", "digest", "tags"}
	fields = append(fields, an.NodeData.getProperties()...)
	return fields
}

func (an ArtifactNode) IdentifiablePropertyNames() []string {
	// An artifact can be uniquely identified by digest
	return []string{"digest"}
}

// PackageNode is a node that represents an artifact
type PackageNode struct {
	Name     string
	Digest   []string
	Version  string
	Purl     string
	CPEs     []string
	Tags     []string
	NodeData objectMetadata
}

func (pn PackageNode) Type() string {
	return "Package"
}

func (pn PackageNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["name"] = pn.Name
	properties["purl"] = pn.Purl
	properties["version"] = pn.Version
	properties["cpes"] = pn.CPEs
	properties["digest"] = toLower(pn.Digest...)
	properties["tags"] = pn.Tags
	pn.NodeData.addProperties(properties)
	return properties
}

func (pn PackageNode) PropertyNames() []string {
	fields := []string{"name", "digest", "purl", "cpes", "tags", "version"}
	fields = append(fields, pn.NodeData.getProperties()...)
	return fields
}

func (pn PackageNode) IdentifiablePropertyNames() []string {
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
	NodeData  objectMetadata
}

func (in IdentityNode) Type() string {
	return "Identity"
}

func (in IdentityNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["id"] = in.ID
	properties["digest"] = strings.ToLower(in.Digest)
	properties["key"] = in.Key
	properties["keyType"] = in.KeyType
	properties["keyScheme"] = in.KeyScheme
	in.NodeData.addProperties(properties)
	return properties
}

func (in IdentityNode) PropertyNames() []string {
	fields := []string{"id", "digest", "key", "keyType", "keyScheme"}
	fields = append(fields, in.NodeData.getProperties()...)
	return fields
}

func (in IdentityNode) IdentifiablePropertyNames() []string {
	// An identity can be uniquely identified by digest
	return []string{"digest"}
}

// AttestationNode is a node that represents an attestation
type AttestationNode struct {
	// TODO(mihaimaruseac): Unsure what fields to store here
	FilePath        string
	Digest          string
	AttestationType string
	Payload         map[string]interface{}
	NodeData        objectMetadata
}

func (an AttestationNode) Type() string {
	return "Attestation"
}

func (an AttestationNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["filepath"] = an.FilePath
	properties["digest"] = strings.ToLower(an.Digest)
	properties["attestation_type"] = an.AttestationType
	for k, v := range an.Payload {
		properties[k] = v
	}
	an.NodeData.addProperties(properties)

	return properties
}

func (an AttestationNode) PropertyNames() []string {
	fields := []string{"filepath", "digest", "attestation_type"}
	for k := range an.Payload {
		fields = append(fields, k)
	}
	fields = append(fields, an.NodeData.getProperties()...)
	return fields
}

func (an AttestationNode) IdentifiablePropertyNames() []string {
	return []string{"digest"}
}

// BuilderNode is a node that represents a builder for an artifact
type BuilderNode struct {
	BuilderType string
	BuilderId   string
	NodeData    objectMetadata
}

func (bn BuilderNode) Type() string {
	return "Builder"
}

func (bn BuilderNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["type"] = bn.BuilderType
	properties["id"] = bn.BuilderId
	bn.NodeData.addProperties(properties)
	return properties
}

func (bn BuilderNode) PropertyNames() []string {
	fields := []string{"type", "id"}
	fields = append(fields, bn.NodeData.getProperties()...)
	return fields
}

func (bn BuilderNode) IdentifiablePropertyNames() []string {
	// A builder needs both type and id to be identified
	return []string{"type", "id"}
}

// MetadataNode is a node that represents metadata about an artifact/package
type MetadataNode struct {
	MetadataType string
	ID           string
	Details      map[string]interface{}
}

func (mn MetadataNode) Type() string {
	return "Metadata"
}

func (mn MetadataNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["metadata_type"] = mn.MetadataType
	properties["id"] = mn.ID

	for k, v := range mn.Details {
		properties[k] = v
	}

	return properties
}

func (mn MetadataNode) PropertyNames() []string {
	fields := []string{"metadata_type", "id"}
	for k := range mn.Details {
		fields = append(fields, k)
	}

	return fields
}

func (mn MetadataNode) IdentifiablePropertyNames() []string {
	return []string{"metadata_type", "id"}
}

// VulnerabilityNode is a node that represents a vulnerability associated with the certifier attestation
type VulnerabilityNode struct {
	ID       string
	NodeData objectMetadata
}

func (vn VulnerabilityNode) Type() string {
	return "Vulnerability"
}

func (vn VulnerabilityNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["id"] = vn.ID
	vn.NodeData.addProperties(properties)
	return properties
}

func (vn VulnerabilityNode) PropertyNames() []string {
	fields := []string{"id"}
	fields = append(fields, vn.NodeData.getProperties()...)
	return fields
}

func (vn VulnerabilityNode) IdentifiablePropertyNames() []string {
	// Based on the ID of the vulnerability, more information can be obtained but not stored in the graph DB
	return []string{"id"}
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
		panic("only one of package and artifact dependency node defined for DependsOn relationship")
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
	MetadataNode MetadataNode
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
		panic("only one of package and artifact dependency node defined for DependsOn relationship")
	}

	v = e.MetadataNode
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

// AttestationForPackage is an edge that represents the fact that an
// `AttestationNode` is an attestation for an `PackageNode`.
type AttestationForPackage struct {
	AttestationNode AttestationNode
	PackageNode     PackageNode
}

func (e AttestationForPackage) Type() string {
	return "Attestation"
}

func (e AttestationForPackage) Nodes() (v, u GuacNode) {
	return e.AttestationNode, e.PackageNode
}

func (e AttestationForPackage) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e AttestationForPackage) PropertyNames() []string {
	return []string{}
}

func (e AttestationForPackage) IdentifiablePropertyNames() []string {
	return []string{}
}

// VulnerableEdge is an edge that represents the fact that an
// artifact is vulnerable or not based on certification attestation
// This edge gets created when the attestation contains vulnerabilities
type VulnerableEdge struct {
	AttestationNode   AttestationNode
	VulnerabilityNode VulnerabilityNode
}

func (e VulnerableEdge) Type() string {
	return "Vulnerable"
}

func (e VulnerableEdge) Nodes() (v, u GuacNode) {
	return e.AttestationNode, e.VulnerabilityNode
}

func (e VulnerableEdge) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e VulnerableEdge) PropertyNames() []string {
	return []string{}
}

func (e VulnerableEdge) IdentifiablePropertyNames() []string {
	return []string{}
}
