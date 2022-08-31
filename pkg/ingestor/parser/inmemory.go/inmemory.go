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

package inmemory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/in-toto/in-toto-golang/in_toto"
)

const (
	algorithmSHA256 string = "sha256"
)

type InMemoryParser struct{}

func (m *InMemoryParser) ParseDocumentTree(processedDocTree processor.DocumentTree) (assembler.AssemblerInput, error) {

	nodes, edges, err := parserHelper(processedDocTree)
	if err != nil {
		return assembler.AssemblerInput{}, err
	}

	assemblerinput := assembler.AssemblerInput{
		V: nodes,
		E: edges,
	}

	return assemblerinput, nil
}

func (m *InMemoryParser) Type() string {
	return "inmemory"
}

func parserHelper(processedDocTree processor.DocumentTree) ([]assembler.GuacNode, []assembler.GuacEdge, error) {
	foundNodes := []assembler.GuacNode{}
	foundEdges := []assembler.GuacEdge{}

	nodes, edges, err := parseDoc(processedDocTree.Document)
	if err != nil {
		return nil, nil, err
	}

	foundNodes = append(foundNodes, nodes...)
	foundEdges = append(foundEdges, edges...)

	for _, d := range processedDocTree.Children {
		nodes, edges, err := parserHelper(processor.DocumentTree(d))
		if err != nil {
			return nil, nil, err
		}
		foundNodes = append(foundNodes, nodes...)
		foundEdges = append(foundEdges, edges...)
	}
	return foundNodes, foundEdges, nil
}

func parseDoc(doc *processor.Document) ([]assembler.GuacNode, []assembler.GuacEdge, error) {
	foundNodes := []assembler.GuacNode{}
	foundEdges := []assembler.GuacEdge{}
	switch doc.Type {
	case processor.DocumentDSSE:
		//verify the signatures and create the identity node
	case processor.DocumentSLSA:
		if len(doc.Blob) > 0 {
			// append attestation node
			h := sha256.Sum256(doc.Blob)
			attNode := assembler.AttestationNode{FilePath: "", Digest: algorithmSHA256 + ":" + hex.EncodeToString(h[:])}
			foundNodes = append(foundNodes, attNode)

			statement, err := parseSlsaPredicate(doc.Blob)
			if err != nil {
				return nil, nil, err
			}

			// append builder node for builder
			builderNode := assembler.BuilderNode{BuilderType: statement.Predicate.BuildType, BuilderId: statement.Predicate.Builder.ID}
			foundNodes = append(foundNodes, builderNode)

			// append dependency nodes for the materials
			mats := []assembler.ArtifactNode{}
			for _, mat := range statement.Predicate.Materials {
				for alg, ds := range mat.Digest {
					mat := assembler.ArtifactNode{Name: mat.URI, Digest: alg + ":" + ds}
					mats = append(mats, mat)
					foundNodes = append(foundNodes, mat)
				}
			}

			// append artifact node for the subjects
			for _, sub := range statement.Subject {
				for alg, ds := range sub.Digest {
					atfNode := assembler.ArtifactNode{Name: sub.Name, Digest: alg + ":" + ds}
					foundEdges = append(foundEdges, assembler.AttestationForEdge{AttestationNode: attNode, ArtifactNode: atfNode})
					foundEdges = append(foundEdges, assembler.BuiltByEdge{BuilderNode: builderNode, ArtifactNode: atfNode})
					foundNodes = append(foundNodes, atfNode)
					for _, m := range mats {
						foundEdges = append(foundEdges, assembler.DependsOnEdge{ArtifactNode: atfNode, Dependency: m})
					}
				}
			}
		}
	}
	return foundNodes, foundEdges, nil
}

func parseSlsaPredicate(p []byte) (*in_toto.ProvenanceStatement, error) {
	predicate := in_toto.ProvenanceStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}
