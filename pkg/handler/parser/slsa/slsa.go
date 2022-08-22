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

package slsa

import (
	"encoding/json"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/ingestor/processor"
	"github.com/in-toto/in-toto-golang/in_toto"
)

func ParseDocument(processedDoc *processor.Document) (assembler.AssemblerInput, error) {
	nodes := []assembler.GuacNode{}
	edges := []assembler.GuacEdge{}

	assemblerinput := assembler.AssemblerInput{
		V: nodes,
		E: edges,
	}

	if len(processedDoc.Blob) > 0 {
		statement, err := parseStatement(processedDoc.Blob)
		if err != nil {
			return result, err
		}
	}

	//TODO: Create edges from the nodes

	subNodes := []assembler.GuacNode{}
	for _, sub := range att.Subject {
		identifiable := make(map[string]interface{})
		identifiable["name"] = sub.Name
		identifiable["digest"] = sub.Digest

		trival := assembler.TrivalIdentifiable{Fields: identifiable}
		subNodes = append(subNodes, assembler.ArtifactNode{trival})
	}

	matNodes := []assembler.GuacNode{}
	for _, mat := range att.Predicate.Materials {
		identifiable := make(map[string]interface{})
		identifiable["name"] = mat.URI
		identifiable["digest"] = mat.Digest

		trival := assembler.TrivalIdentifiable{Fields: identifiable}
		matNodes = append(matNodes, assembler.ArtifactNode{trival})
	}

	identifiable := make(map[string]interface{})
	identifiable["name"] = att.Predicate.Builder.ID

	return assemblerinput, nil
}

func parseStatement(p []byte) (*in_toto.Statement, error) {
	ps := in_toto.Statement{}
	if err := json.Unmarshal(p, &ps); err != nil {
		return nil, err
	}
	return &ps, nil
}

func parseSlsaPredicate(p []byte) (*in_toto.ProvenanceStatement, error) {
	predicate := in_toto.ProvenanceStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}
