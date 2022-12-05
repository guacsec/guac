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

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	ArtifactNodeType       string = "Artifact"
	PackageNodeType        string = "Package"
	IdentityNodeType       string = "Identity"
	AttestationNodeType    string = "Attestation"
	BuilderNodeType        string = "Builder"
	MetadataNodeType       string = "Metadata"
	VulnerabilityNodeType  string = "Vulnerability"
	IdentityForEdgeType    string = "Identity"
	AttestationForEdgeType string = "Attestation"
	BuiltByEdgeType        string = "BuiltBy"
	DependsOnEdgeType      string = "DependsOn"
	ContainsEdgeType       string = "Contains"
	MetadataForEdgeType    string = "MetadataFor"
	VulnerableEdgeType     string = "Vulnerable"
)

// ArtifactNode is a node that represents an artifact
type ArtifactNode struct {
	Name     string         `json:"name"`
	Digest   string         `json:"digest"`
	Tags     []string       `json:"tags"`
	NodeData objectMetadata `json:"nodedata"`
}

func (an ArtifactNode) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range an.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["type"] = an.Type()
	marshalProperties["nodedata"] = an.NodeData

	return json.Marshal(marshalProperties)
}

func (an ArtifactNode) Type() string {
	return ArtifactNodeType
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
	Name     string         `json:"name"`
	Digest   []string       `json:"digest"`
	Version  string         `json:"version"`
	Purl     string         `json:"purl"`
	CPEs     []string       `json:"cpes"`
	Tags     []string       `json:"tags"`
	NodeData objectMetadata `json:"nodedata"`
}

func (pn PackageNode) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range pn.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["type"] = pn.Type()
	marshalProperties["nodedata"] = pn.NodeData

	return json.Marshal(marshalProperties)
}

func (pn PackageNode) Type() string {
	return PackageNodeType
}

func (pn PackageNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	if len(pn.Name) > 0 {
		properties["name"] = pn.Name
	}
	if len(pn.Purl) > 0 {
		properties["purl"] = pn.Purl
	}
	if len(pn.Version) > 0 {
		properties["version"] = pn.Version
	}
	if len(pn.CPEs) > 0 {
		properties["cpes"] = pn.CPEs
	}
	if len(pn.Digest) > 0 {
		properties["digest"] = toLower(pn.Digest...)
	}
	if len(pn.Tags) > 0 {
		properties["tags"] = pn.Tags
	}
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
	IdentityID string `json:"identity_id"`
	Digest     string `json:"digest"`
	// base64 encoded
	Key       string         `json:"key"`
	KeyType   string         `json:"key_type"`
	KeyScheme string         `json:"key_scheme"`
	NodeData  objectMetadata `json:"nodedata"`
}

func (in IdentityNode) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range in.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["type"] = in.Type()
	marshalProperties["nodedata"] = in.NodeData
	return json.Marshal(marshalProperties)
}

func (in IdentityNode) Type() string {
	return IdentityNodeType
}

func (in IdentityNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["identity_id"] = in.IdentityID
	properties["digest"] = strings.ToLower(in.Digest)
	properties["key"] = in.Key
	properties["key_type"] = in.KeyType
	properties["key_scheme"] = in.KeyScheme
	in.NodeData.addProperties(properties)
	return properties
}

func (in IdentityNode) PropertyNames() []string {
	fields := []string{"identity_id", "digest", "key", "key_type", "key_scheme"}
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
	FilePath        string                 `json:"filepath"`
	Digest          string                 `json:"digest"`
	AttestationType string                 `json:"attestation_type"`
	Payload         map[string]interface{} `json:"payload"`
	NodeData        objectMetadata         `json:"nodedata"`
}

func (an AttestationNode) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range an.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["type"] = an.Type()
	marshalProperties["nodedata"] = an.NodeData
	marshalProperties["payload"] = an.Payload
	return json.Marshal(marshalProperties)
}

func (an AttestationNode) Type() string {
	return AttestationNodeType
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
	BuilderType string         `json:"builder_type"`
	BuilderId   string         `json:"builder_id"`
	NodeData    objectMetadata `json:"nodedata"`
}

func (bn BuilderNode) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range bn.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["type"] = bn.Type()
	marshalProperties["nodedata"] = bn.NodeData
	return json.Marshal(marshalProperties)
}

func (bn BuilderNode) Type() string {
	return BuilderNodeType
}

func (bn BuilderNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["builder_type"] = bn.BuilderType
	properties["builder_id"] = bn.BuilderId
	bn.NodeData.addProperties(properties)
	return properties
}

func (bn BuilderNode) PropertyNames() []string {
	fields := []string{"builder_type", "builder_id"}
	fields = append(fields, bn.NodeData.getProperties()...)
	return fields
}

func (bn BuilderNode) IdentifiablePropertyNames() []string {
	// A builder needs both type and id to be identified
	return []string{"builder_type", "builder_id"}
}

// MetadataNode is a node that represents metadata about an artifact/package
type MetadataNode struct {
	MetadataType string                 `json:"metadata_type"`
	MetadataID   string                 `json:"metadata_id"`
	Details      map[string]interface{} `json:"details"`
	NodeData     objectMetadata         `json:"nodedata"`
}

func (mn MetadataNode) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range mn.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["type"] = mn.Type()
	marshalProperties["nodedata"] = mn.NodeData
	marshalProperties["details"] = mn.Details
	return json.Marshal(marshalProperties)
}

func (mn MetadataNode) Type() string {
	return MetadataNodeType
}

func (mn MetadataNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["metadata_type"] = mn.MetadataType
	properties["metadata_id"] = mn.MetadataID

	for k, v := range mn.Details {
		properties[k] = v
	}

	mn.NodeData.addProperties(properties)
	return properties
}

func (mn MetadataNode) PropertyNames() []string {
	fields := []string{"metadata_type", "metadata_id"}
	for k := range mn.Details {
		fields = append(fields, k)
	}
	fields = append(fields, mn.NodeData.getProperties()...)
	return fields
}

func (mn MetadataNode) IdentifiablePropertyNames() []string {
	return []string{"metadata_type", "metadata_id"}
}

// VulnerabilityNode is a node that represents a vulnerability associated with the certifier attestation
type VulnerabilityNode struct {
	VulnerabilityID string         `json:"vulnerability_id"`
	NodeData        objectMetadata `json:"nodedata"`
}

func (vn VulnerabilityNode) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range vn.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["type"] = vn.Type()
	marshalProperties["nodedata"] = vn.NodeData
	return json.Marshal(marshalProperties)
}

func (vn VulnerabilityNode) Type() string {
	return VulnerabilityNodeType
}

func (vn VulnerabilityNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["vulnerability_id"] = vn.VulnerabilityID
	vn.NodeData.addProperties(properties)
	return properties
}

func (vn VulnerabilityNode) PropertyNames() []string {
	fields := []string{"vulnerability_id"}
	fields = append(fields, vn.NodeData.getProperties()...)
	return fields
}

func (vn VulnerabilityNode) IdentifiablePropertyNames() []string {
	// Based on the ID of the vulnerability, more information can be obtained but not stored in the graph DB
	return []string{"vulnerability_id"}
}

// IdentityForEdge is an edge that represents the fact that an
// `IdentityNode` is an identity for an `AttestationNode`.
type IdentityForEdge struct {
	IdentityNode    IdentityNode    `json:"identitynode"`
	AttestationNode AttestationNode `json:"attestationnode"`
}

func (e IdentityForEdge) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range e.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["identitynode"] = e.IdentityNode
	marshalProperties["attestationnode"] = e.AttestationNode

	marshalProperties["type"] = e.Type()

	return json.Marshal(marshalProperties)
}

func (e IdentityForEdge) Type() string {
	return IdentityForEdgeType
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
// `AttestationNode` is an attestation for an `ArtifactNode/PackageNode`.
// Only one of each side of the edge should be defined.
type AttestationForEdge struct {
	AttestationNode AttestationNode `json:"attestationnode"`
	ForArtifact     ArtifactNode    `json:"forartifact"`
	ForPackage      PackageNode     `json:"forpackage"`
}

func (e AttestationForEdge) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range e.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["attestationnode"] = e.AttestationNode
	marshalProperties["forartifact"] = e.ForArtifact
	marshalProperties["forpackage"] = e.ForPackage

	marshalProperties["type"] = e.Type()

	return json.Marshal(marshalProperties)
}

func (e AttestationForEdge) Type() string {
	return AttestationForEdgeType
}

func (e AttestationForEdge) Nodes() (v, u GuacNode) {
	uA, uP := isDefined(e.ForArtifact), isDefined(e.ForPackage)
	if uA == uP {
		panic("only one of package or artifact dependency node must be defined for Attestation relationship")
	}

	v = e.AttestationNode
	if uA {
		u = e.ForArtifact
	} else {
		u = e.ForPackage
	}

	return v, u
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
	ArtifactNode ArtifactNode `json:"artifactnode"`
	BuilderNode  BuilderNode  `json:"buildernode"`
}

func (e BuiltByEdge) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range e.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["artifactnode"] = e.ArtifactNode
	marshalProperties["buildernode"] = e.BuilderNode

	marshalProperties["type"] = e.Type()

	return json.Marshal(marshalProperties)
}

func (e BuiltByEdge) Type() string {
	return BuiltByEdgeType
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
	ArtifactNode       ArtifactNode `json:"artifactnode"`
	PackageNode        PackageNode  `json:"packagenode"`
	ArtifactDependency ArtifactNode `json:"artifactdependency"`
	PackageDependency  PackageNode  `json:"packagedependency"`
}

func (e DependsOnEdge) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range e.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["artifactnode"] = e.ArtifactNode
	marshalProperties["packagenode"] = e.PackageNode
	marshalProperties["artifactdependency"] = e.ArtifactDependency
	marshalProperties["packagedependency"] = e.PackageDependency

	marshalProperties["type"] = e.Type()

	return json.Marshal(marshalProperties)
}

func (e DependsOnEdge) Type() string {
	return DependsOnEdgeType
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
	PackageNode       PackageNode  `json:"packagenode"`
	ContainedArtifact ArtifactNode `json:"containedartifact"`
}

func (e ContainsEdge) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range e.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["packagenode"] = e.PackageNode
	marshalProperties["containedartifact"] = e.ContainedArtifact

	marshalProperties["type"] = e.Type()

	return json.Marshal(marshalProperties)
}

func (e ContainsEdge) Type() string {
	return ContainsEdgeType
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
	MetadataNode MetadataNode `json:"metadatanode"`
	// To node
	ForArtifact ArtifactNode `json:"forartifact"`
	ForPackage  PackageNode  `json:"forpackage"`
}

func (e MetadataForEdge) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range e.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["metadatanode"] = e.MetadataNode
	marshalProperties["forartifact"] = e.ForArtifact
	marshalProperties["forpackage"] = e.ForPackage

	marshalProperties["type"] = e.Type()

	return json.Marshal(marshalProperties)
}

func (e MetadataForEdge) Type() string {
	return MetadataForEdgeType
}

func (e MetadataForEdge) Nodes() (v, u GuacNode) {
	uA, uP := isDefined(e.ForArtifact), isDefined(e.ForPackage)
	if uA == uP {
		fmt.Print("bad place reached")
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

// VulnerableEdge is an edge that represents the fact that an
// artifact is vulnerable or not based on certification attestation
// This edge gets created when the attestation contains vulnerabilities
type VulnerableEdge struct {
	AttestationNode   AttestationNode   `json:"attestationnode"`
	VulnerabilityNode VulnerabilityNode `json:"vulnerabilitynode"`
}

func (e VulnerableEdge) MarshalJSON() ([]byte, error) {
	marshalProperties := make(map[string]interface{})

	for k, v := range e.Properties() {
		marshalProperties[k] = v
	}

	marshalProperties["attestationnode"] = e.AttestationNode
	marshalProperties["vulnerabilitynode"] = e.VulnerabilityNode

	marshalProperties["type"] = e.Type()

	return json.Marshal(marshalProperties)
}

func (e VulnerableEdge) Type() string {
	return VulnerableEdgeType
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
