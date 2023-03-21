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
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/jeremywohl/flatten"
)

const (
	algorithmSHA256 string = "sha256"
)

// each subject or object is made of:
// - A artifact for each digest information
// - a pkg or source depending on what is represented by the name/URI
// - An IsOccurence input spec which will generate a predicate for each occurence
type slsaEntity struct {
	artifacts []model.ArtifactInputSpec
	occurence model.IsOccurrenceInputSpec

	// Either pkg or source
	pkg    *model.PkgInputSpec
	source *model.SourceInputSpec
}

type slsaParser struct {
	doc *processor.Document

	subjects        []slsaEntity
	materials       []slsaEntity
	builder         model.BuilderInputSpec
	slsaAttestation model.SLSAInputSpec

	identifierStrings *common.IdentifierStrings
}

// NewSLSAParser initializes the slsaParser
func NewSLSAParser() common.DocumentParser {
	return &slsaParser{
		subjects:          []slsaEntity{},
		materials:         []slsaEntity{},
		slsaAttestation:   model.SLSAInputSpec{},
		builder:           model.BuilderInputSpec{},
		identifierStrings: &common.IdentifierStrings{},
	}
}

// Parse breaks out the document into the graph components
func (s *slsaParser) Parse(ctx context.Context, doc *processor.Document) error {
	s.doc = doc
	statement, err := parseSlsaPredicate(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse slsa predicate: %w", err)
	}
	s.getSubject(statement)
	s.getMaterials(statement)
	err = s.getSLSA(statement)
	if err != nil {
		return err
	}
	s.getBuilder(statement)
	return nil
}

type parsedObject struct {
	singletonArtifact *model.ArtifactInputSpec
	singletonSource   *model.SourceInputSpec
	// if it is a pkg, it returns the pkg encapsulated in
	// the IsOccurence predicate
	pkg *assembler.IsOccurenceIngest
}

func (s *slsaParser) getSubject(statement *in_toto.ProvenanceStatement) {
	// append artifact node for the subjects
	for _, sub := range statement.Subject {
		artifacts := []model.ArtifactInputSpec{}
		for alg, ds := range sub.Digest {
			artifacts = append(artifacts, model.ArtifactInputSpec{
				Algorithm: alg,
				Digest:    strings.Trim(ds, "'"), // some slsa documents incorrectly add additional quotes
			})

			s.identifierStrings.UnclassifiedStrings = append(s.identifierStrings.UnclassifiedStrings, sub.Name)
		}
		s.subjects = append(s.subjects, getSlsaEntity(sub.Name, artifacts))
	}
}

func (s *slsaParser) getMaterials(statement *in_toto.ProvenanceStatement) {
	// append dependency nodes for the materials
	for _, mat := range statement.Predicate.Materials {
		artifacts := []model.ArtifactInputSpec{}
		for alg, ds := range mat.Digest {
			artifacts = append(artifacts, model.ArtifactInputSpec{
				Algorithm: alg,
				Digest:    strings.Trim(ds, "'"), // some slsa documents incorrectly add additional quotes
			})

			s.identifierStrings.UnclassifiedStrings = append(s.identifierStrings.UnclassifiedStrings, mat.URI)
		}
		s.materials = append(s.materials, getSlsaEntity(mat.URI, artifacts))
	}
}

func getSlsaEntity(name string, artifacts []model.ArtifactInputSpec) slsaEntity {
	s := slsaEntity{
		artifacts: artifacts,
	}

	var (
		src *model.SourceInputSpec
		pkg *model.PkgInputSpec
	)
	pkg, err := helpers.PurlToPkg(name)
	if err == nil {
		s.pkg = pkg
		goto finish
	}

	src, err = helpers.VcsToSrc(name)
	if err == nil {
		s.source = src
		goto finish
	}

	// else we create a GUAC package for it
	pkg, err = helpers.PurlToPkg(helpers.GuacGenericPurl(name))
	if err == nil {
		s.pkg = pkg
		goto finish
	} else {
		panic("unable to get Guac Generic Purl, this should not happen")
	}

finish:
	s.occurence = model.IsOccurrenceInputSpec{
		Justification: "from SLSA definition of checksums for subject/materials",
	}

	return s
}

func (s *slsaParser) getSLSA(stmt *in_toto.ProvenanceStatement) error {
	inp := model.SLSAInputSpec{}
	inp.BuildType = stmt.Predicate.BuildType

	inp.SlsaVersion = stmt.PredicateType
	if stmt.Predicate.Metadata.BuildStartedOn != nil {
		inp.StartedOn = *stmt.Predicate.Metadata.BuildStartedOn
	}
	if stmt.Predicate.Metadata.BuildFinishedOn != nil {
		inp.FinishedOn = *stmt.Predicate.Metadata.BuildStartedOn
	}

	data, _ := json.Marshal(stmt.Predicate)
	var genericMap map[string]any
	err := json.Unmarshal(data, &genericMap)
	if err != nil {
		return err
	}

	flatMap, err := flatten.Flatten(genericMap, "slsa.", flatten.SeparatorStyle{Middle: "."})
	if err != nil {
		return err
	}

	for k, v := range flatMap {
		inp.SlsaPredicate = append(inp.SlsaPredicate, model.SLSAPredicateInputSpec{
			Key:   k,
			Value: fmt.Sprintf("%v", v),
		})
	}

	s.slsaAttestation = inp

	return nil
}

func (s *slsaParser) getBuilder(statement *in_toto.ProvenanceStatement) {
	s.builder = model.BuilderInputSpec{
		Uri: statement.Predicate.Builder.ID,
	}
}

func parseSlsaPredicate(p []byte) (*in_toto.ProvenanceStatement, error) {
	predicate := in_toto.ProvenanceStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}

func (s *slsaParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	preds := &assembler.IngestPredicates{}

	// Create occurences for subjects and materials
	for _, o := range s.subjects {
		for _, a := range o.artifacts {
			preds.IsOccurence = append(preds.IsOccurence, assembler.IsOccurenceIngest{
				Pkg:         o.pkg,
				Src:         o.source,
				Artifact:    &a,
				IsOccurence: &o.occurence,
			})
		}
	}

	for _, o := range s.materials {
		for _, a := range o.artifacts {
			preds.IsOccurence = append(preds.IsOccurence, assembler.IsOccurenceIngest{
				Pkg:         o.pkg,
				Src:         o.source,
				Artifact:    &a,
				IsOccurence: &o.occurence,
			})
		}
	}

	// Assemble materials
	materials := []model.ArtifactInputSpec{}
	for _, o := range s.materials {
		for _, a := range o.artifacts {
			materials = append(materials, a)
		}
	}

	for _, o := range s.subjects {
		for _, a := range o.artifacts {
			preds.HasSlsa = append(preds.HasSlsa, assembler.HasSlsaIngest{
				Artifact:  &a,
				HasSlsa:   &s.slsaAttestation,
				Materials: materials,
				Builder:   &s.builder,
			})
		}
	}

	return preds
}

// GetIdentities gets the identity node from the document if they exist
func (s *slsaParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (s *slsaParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return s.identifierStrings, nil
}
