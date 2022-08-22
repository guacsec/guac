//
// Copyright 2022 The AFF Authors.
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

package parser

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/in-toto/in-toto-golang/in_toto"
)

const (
	algorithmSHA256 string = "sha256"
)

type graphBuilder struct {
	foundIdentities       []assembler.IdentityNode
	foundSubjectArtifacts []assembler.ArtifactNode
	foundAttestations     []assembler.AttestationNode
	foundBuilders         []assembler.BuilderNode
	foundDependencies     []assembler.ArtifactNode
}

func newGraphBuilder() *graphBuilder {
	return &graphBuilder{
		foundIdentities:       []assembler.IdentityNode{},
		foundSubjectArtifacts: []assembler.ArtifactNode{},
		foundAttestations:     []assembler.AttestationNode{},
		foundBuilders:         []assembler.BuilderNode{},
		foundDependencies:     []assembler.ArtifactNode{},
	}
}

// ParseDocumentTree
func ParseDocumentTree(docTree processor.DocumentTree) (assembler.AssemblerInput, error) {

	builder := newGraphBuilder()
	err := builder.parse(docTree)
	if err != nil {
		return assembler.AssemblerInput{}, err
	}

	assemblerinput := assembler.AssemblerInput{
		V: builder.createNodes(),
		E: builder.createEdges(),
	}

	return assemblerinput, nil
}

func (b *graphBuilder) createEdges() []assembler.GuacEdge {
	edges := []assembler.GuacEdge{}
	for _, i := range b.foundIdentities {
		for _, a := range b.foundAttestations {
			edges = append(edges, assembler.IdentityForEdge{IdentityNode: i, AttestationNode: a})
		}
	}
	for _, s := range b.foundSubjectArtifacts {
		for _, b := range b.foundBuilders {
			edges = append(edges, assembler.BuiltByEdge{ArtifactNode: s, BuilderNode: b})
		}
		for _, a := range b.foundAttestations {
			edges = append(edges, assembler.AttestationForEdge{AttestationNode: a, ArtifactNode: s})
		}
		for _, d := range b.foundDependencies {
			edges = append(edges, assembler.DependsOnEdge{ArtifactNode: s, Dependency: d})
		}
	}
	return edges
}

func (b *graphBuilder) createNodes() []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, i := range b.foundIdentities {
		nodes = append(nodes, i)
	}
	for _, s := range b.foundSubjectArtifacts {
		nodes = append(nodes, s)
	}
	for _, a := range b.foundAttestations {
		nodes = append(nodes, a)
	}
	for _, d := range b.foundDependencies {
		nodes = append(nodes, d)
	}
	for _, b := range b.foundBuilders {
		nodes = append(nodes, b)
	}
	return nodes
}

func (b *graphBuilder) parse(root processor.DocumentTree) error {
	err := b.parserHelper(root.Document)
	if err != nil {
		return err
	}

	if len(root.Children) == 0 {
		return nil
	}

	for _, c := range root.Children {
		err := b.parse(c)
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *graphBuilder) parserHelper(doc *processor.Document) error {

	sub, err := getSubjectArtifact(doc)
	if err != nil {
		return err
	}
	b.foundSubjectArtifacts = append(b.foundSubjectArtifacts, sub...)

	dep, err := geDependencyArtifact(doc)
	if err != nil {
		return err
	}
	b.foundDependencies = append(b.foundDependencies, dep...)

	id, err := getIdentity(doc)
	if err != nil {
		return err
	}
	b.foundIdentities = append(b.foundIdentities, id...)

	att, err := getAttNode(doc)
	if err != nil {
		return err
	}
	b.foundAttestations = append(b.foundAttestations, att...)

	build, err := getBuilder(doc)
	if err != nil {
		return err
	}
	b.foundBuilders = append(b.foundBuilders, build...)

	return nil
}

func getSubjectArtifact(doc *processor.Document) ([]assembler.ArtifactNode, error) {
	foundSubject := []assembler.ArtifactNode{}
	switch doc.Type {
	case processor.DocumentSLSA:
		statement, err := parseSlsaPredicate(doc.Blob)
		if err != nil {
			return nil, err
		}
		// append artifact node for the subjects
		for _, sub := range statement.Subject {
			for alg, ds := range sub.Digest {
				foundSubject = append(foundSubject, assembler.ArtifactNode{Name: sub.Name, Digest: alg + ":" + ds})
			}
		}
		return foundSubject, nil
	}
	return nil, nil
}

func geDependencyArtifact(doc *processor.Document) ([]assembler.ArtifactNode, error) {
	foundDependency := []assembler.ArtifactNode{}
	switch doc.Type {
	case processor.DocumentSLSA:
		statement, err := parseSlsaPredicate(doc.Blob)
		if err != nil {
			return nil, err
		}
		// append dependency nodes for the materials
		for _, mat := range statement.Predicate.Materials {
			for alg, ds := range mat.Digest {
				foundDependency = append(foundDependency, assembler.ArtifactNode{Name: mat.URI, Digest: alg + ":" + ds})
			}
		}
		return foundDependency, nil
	}
	return nil, nil
}

func getIdentity(doc *processor.Document) ([]assembler.IdentityNode, error) {
	foundIdentity := []assembler.IdentityNode{}
	switch doc.Type {
	case processor.DocumentDSSE:
		identities, err := verifier.VerifyIdentity(doc)
		if err != nil {
			return nil, err
		}
		for _, i := range identities {
			foundIdentity = append(foundIdentity, assembler.IdentityNode{ID: i.ID, Digest: i.Key.KeyHash, Key: base64.StdEncoding.EncodeToString(i.Key.KeyVal)})
		}
		return foundIdentity, nil
	}
	return nil, nil
}

func getAttNode(doc *processor.Document) ([]assembler.AttestationNode, error) {
	foundAttestation := []assembler.AttestationNode{}
	switch doc.Type {
	case processor.DocumentSLSA:
		h := sha256.Sum256(doc.Blob)
		foundAttestation = append(foundAttestation, assembler.AttestationNode{FilePath: doc.SourceInformation.Source, Digest: algorithmSHA256 + ":" + hex.EncodeToString(h[:])})
		return foundAttestation, nil
	}
	return nil, nil
}

func getBuilder(doc *processor.Document) ([]assembler.BuilderNode, error) {
	foundBuilder := []assembler.BuilderNode{}
	switch doc.Type {
	case processor.DocumentSLSA:
		statement, err := parseSlsaPredicate(doc.Blob)
		if err != nil {
			return nil, err
		}
		// append builder node for builder
		foundBuilder = append(foundBuilder, assembler.BuilderNode{BuilderType: statement.Predicate.BuildType, BuilderId: statement.Predicate.Builder.ID})
		return foundBuilder, nil
	}
	return nil, nil
}

func parseSlsaPredicate(p []byte) (*in_toto.ProvenanceStatement, error) {
	predicate := in_toto.ProvenanceStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}
