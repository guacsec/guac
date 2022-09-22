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

package slsa

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/in-toto/in-toto-golang/in_toto"
)

const (
	algorithmSHA256 string = "sha256"
)

func ParseITE6Slsa(doc *processor.Document) (common.GraphBuilder, error) {
	b := common.NewGenericGraphBuilder()
	statement, err := parseSlsaPredicate(doc.Blob)
	if err != nil {
		return nil, fmt.Errorf("failed to parse slsa predicate: %w", err)
	}
	sub, err := getSubject(statement)
	if err != nil {
		return nil, err
	}
	b.FoundSubjectArtifacts = append(b.FoundSubjectArtifacts, sub...)

	dep, err := getDependency(statement)
	if err != nil {
		return nil, err
	}
	b.FoundDependencies = append(b.FoundDependencies, dep...)

	att, err := getAttestation(doc.Blob, doc.SourceInformation.Source)
	if err != nil {
		return nil, err
	}
	b.FoundAttestations = append(b.FoundAttestations, att...)

	build, err := getBuilder(statement)
	if err != nil {
		return nil, err
	}
	b.FoundBuilders = append(b.FoundBuilders, build...)

	return b, nil
}
func getSubject(statement *in_toto.ProvenanceStatement) ([]assembler.ArtifactNode, error) {
	FoundSubject := []assembler.ArtifactNode{}
	// append artifact node for the subjects
	for _, sub := range statement.Subject {
		for alg, ds := range sub.Digest {
			FoundSubject = append(FoundSubject, assembler.ArtifactNode{
				Name: sub.Name, Digest: alg + ":" + ds})
		}
	}
	return FoundSubject, nil
}

func getDependency(statement *in_toto.ProvenanceStatement) ([]assembler.ArtifactNode, error) {
	FoundDependency := []assembler.ArtifactNode{}
	// append dependency nodes for the materials
	for _, mat := range statement.Predicate.Materials {
		for alg, ds := range mat.Digest {
			FoundDependency = append(FoundDependency, assembler.ArtifactNode{
				Name: mat.URI, Digest: alg + ":" + ds})
		}
	}
	return FoundDependency, nil
}

func getAttestation(blob []byte, source string) ([]assembler.AttestationNode, error) {
	FoundAttestation := []assembler.AttestationNode{}
	h := sha256.Sum256(blob)
	FoundAttestation = append(FoundAttestation, assembler.AttestationNode{
		FilePath: source, Digest: algorithmSHA256 + ":" + hex.EncodeToString(h[:])})
	return FoundAttestation, nil
}

func getBuilder(statement *in_toto.ProvenanceStatement) ([]assembler.BuilderNode, error) {
	FoundBuilder := []assembler.BuilderNode{}
	// append builder node for builder
	FoundBuilder = append(FoundBuilder, assembler.BuilderNode{
		BuilderType: statement.Predicate.BuildType, BuilderId: statement.Predicate.Builder.ID})
	return FoundBuilder, nil
}

func parseSlsaPredicate(p []byte) (*in_toto.ProvenanceStatement, error) {
	predicate := in_toto.ProvenanceStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}
