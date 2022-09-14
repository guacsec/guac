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

package parser

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

const (
	algorithmSHA256 string = "sha256"
)

type docTreeBuilder struct {
	identities    []assembler.IdentityNode
	graphBuilders []*graphBuilder
}

type graphBuilder struct {
	doc                   *processor.Document
	foundIdentities       []assembler.IdentityNode
	foundSubjectArtifacts []assembler.ArtifactNode
	foundAttestations     []assembler.AttestationNode
	foundBuilders         []assembler.BuilderNode
	foundDependencies     []assembler.ArtifactNode
}

func newDocTreeBuilder() *docTreeBuilder {
	return &docTreeBuilder{
		identities:    []assembler.IdentityNode{},
		graphBuilders: []*graphBuilder{},
	}
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

// ParseDocumentTree takes the DocumentTree and create graph inputs (nodes and edges) per document node
func ParseDocumentTree(docTree processor.DocumentTree) ([]assembler.AssemblerInput, error) {

	assemblerinputs := []assembler.AssemblerInput{}
	docTreeBuilder := newDocTreeBuilder()
	err := docTreeBuilder.parse(docTree)
	if err != nil {
		return []assembler.AssemblerInput{}, err
	}
	for _, builder := range docTreeBuilder.graphBuilders {
		assemblerinput := builder.createAssemblerInput(docTreeBuilder.identities)
		assemblerinputs = append(assemblerinputs, assemblerinput)
	}

	return assemblerinputs, nil
}

func (b *graphBuilder) createAssemblerInput(foundIdentities []assembler.IdentityNode) assembler.AssemblerInput {
	assemblerinput := assembler.AssemblerInput{
		Nodes: b.createNodes(),
		Edges: b.createEdges(foundIdentities),
	}
	return assemblerinput
}

func (b *graphBuilder) createEdges(foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	edges := []assembler.GuacEdge{}
	for _, i := range foundIdentities {
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

func (t *docTreeBuilder) parse(root processor.DocumentTree) error {
	builder := newGraphBuilder()
	err := builder.parserHelper(root.Document)
	if err != nil {
		return err
	}

	t.graphBuilders = append(t.graphBuilders, builder)
	t.identities = append(t.identities, builder.foundIdentities...)

	if len(root.Children) == 0 {
		return nil
	}

	for _, c := range root.Children {
		err := t.parse(c)
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *graphBuilder) parserHelper(doc *processor.Document) error {
	b.doc = doc
	sub, err := getSubject(doc)
	if err != nil {
		return err
	}
	b.foundSubjectArtifacts = append(b.foundSubjectArtifacts, sub...)

	dep, err := getDependency(doc)
	if err != nil {
		return err
	}
	b.foundDependencies = append(b.foundDependencies, dep...)

	id, err := getIdentity(doc)
	if err != nil {
		return err
	}
	b.foundIdentities = append(b.foundIdentities, id...)

	att, err := getAttestation(doc)
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

func getSubject(doc *processor.Document) ([]assembler.ArtifactNode, error) {
	foundSubject := []assembler.ArtifactNode{}
	switch doc.Type {
	case processor.DocumentITE6SLSA:
		statement, err := parseSlsaPredicate(doc.Blob)
		if err != nil {
			return nil, err
		}
		// append artifact node for the subjects
		for _, sub := range statement.Subject {
			for alg, ds := range sub.Digest {
				foundSubject = append(foundSubject, assembler.ArtifactNode{
					Name: sub.Name, Digest: alg + ":" + ds})
			}
		}
		return foundSubject, nil
	}
	return nil, nil
}

func getDependency(doc *processor.Document) ([]assembler.ArtifactNode, error) {
	foundDependency := []assembler.ArtifactNode{}
	switch doc.Type {
	case processor.DocumentITE6SLSA:
		statement, err := parseSlsaPredicate(doc.Blob)
		if err != nil {
			return nil, err
		}
		// append dependency nodes for the materials
		for _, mat := range statement.Predicate.Materials {
			for alg, ds := range mat.Digest {
				foundDependency = append(foundDependency, assembler.ArtifactNode{
					Name: mat.URI, Digest: alg + ":" + ds})
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
			pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(i.Key.Val)
			if err != nil {
				return nil, fmt.Errorf("MarshalPublicKeyToPEM returned error: %v", err)
			}
			foundIdentity = append(foundIdentity, assembler.IdentityNode{
				ID: i.ID, Digest: i.Key.Hash, Key: base64.StdEncoding.EncodeToString(pemBytes), KeyType: string(i.Key.Type), KeyScheme: string(i.Key.Scheme)})
		}
		return foundIdentity, nil
	}
	return nil, nil
}

func getAttestation(doc *processor.Document) ([]assembler.AttestationNode, error) {
	foundAttestation := []assembler.AttestationNode{}
	switch doc.Type {
	case processor.DocumentITE6SLSA:
		h := sha256.Sum256(doc.Blob)
		foundAttestation = append(foundAttestation, assembler.AttestationNode{
			FilePath: doc.SourceInformation.Source, Digest: algorithmSHA256 + ":" + hex.EncodeToString(h[:])})
		return foundAttestation, nil
	}
	return nil, nil
}

func getBuilder(doc *processor.Document) ([]assembler.BuilderNode, error) {
	foundBuilder := []assembler.BuilderNode{}
	switch doc.Type {
	case processor.DocumentITE6SLSA:
		statement, err := parseSlsaPredicate(doc.Blob)
		if err != nil {
			return nil, err
		}
		// append builder node for builder
		foundBuilder = append(foundBuilder, assembler.BuilderNode{
			BuilderType: statement.Predicate.BuildType, BuilderId: statement.Predicate.Builder.ID})
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
