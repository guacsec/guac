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

	"github.com/in-toto/in-toto-golang/in_toto"
	scommon "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa01 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	"github.com/jeremywohl/flatten"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

// each subject or object is made of:
// - A artifact for each digest information
// - a pkg or source depending on what is represented by the name/URI
// - An IsOccurence input spec which will generate a predicate for each occurence
type slsaEntity struct {
	artifacts []*model.ArtifactInputSpec
	occurence *model.IsOccurrenceInputSpec

	// Either pkg or source
	pkg    *model.PkgInputSpec
	source *model.SourceInputSpec
}

type slsaParser struct {
	header            *in_toto.StatementHeader
	s01smt            *in_toto.ProvenanceStatementSLSA01
	s02smt            *in_toto.ProvenanceStatementSLSA02
	s1smt             *in_toto.ProvenanceStatementSLSA1
	subjects          []*slsaEntity
	materials         []*slsaEntity
	bareMaterials     []*model.ArtifactInputSpec
	builder           *model.BuilderInputSpec
	slsaAttestation   *model.SLSAInputSpec
	identifierStrings *common.IdentifierStrings
}

// NewSLSAParser initializes the slsaParser
func NewSLSAParser() common.DocumentParser {
	return &slsaParser{
		identifierStrings: &common.IdentifierStrings{},
	}
}

// Parse breaks out the document into the graph components
func (s *slsaParser) Parse(ctx context.Context, doc *processor.Document) error {
	if err := s.parseSlsaPredicate(doc.Blob); err != nil {
		return err
	}
	if err := s.getSubject(); err != nil {
		return err
	}
	if err := s.getMaterials(); err != nil {
		return err
	}
	if err := s.getSLSA(); err != nil {
		return err
	}
	s.getBuilder()
	return nil
}

func (s *slsaParser) getSubject() error {
	// append artifact node for the subjects
	for _, sub := range s.header.Subject {
		s.identifierStrings.UnclassifiedStrings = append(s.identifierStrings.UnclassifiedStrings, sub.Name)
		se, err := getSlsaEntity(sub.Name, sub.Digest)
		if err != nil {
			return err
		}
		s.subjects = append(s.subjects, se)
	}
	return nil
}

func (s *slsaParser) getMaterials() error {
	switch s.header.PredicateType {
	case slsa01.PredicateSLSAProvenance:
		if err := s.getMaterials0(s.s01smt.Predicate.Materials); err != nil {
			return err
		}
	case slsa02.PredicateSLSAProvenance:
		if err := s.getMaterials0(s.s02smt.Predicate.Materials); err != nil {
			return err
		}
	case slsa1.PredicateSLSAProvenance:
		if err := s.getMaterials1(s.s1smt.Predicate.BuildDefinition.ResolvedDependencies); err != nil {
			return err
		}
	}
	return nil
}

func (s *slsaParser) getMaterials1(rds []slsa1.ResourceDescriptor) error {
	for _, rd := range rds {
		// Only one of URI, Digest, or Content is required.
		// https://github.com/in-toto/attestation/blob/main/spec/v1.0/resource_descriptor.md
		if len(rd.Digest) == 0 {
			// Skip if Digest is empty
			continue
		}
		if rd.URI == "" {
			// If URI is empty, just add artifacts
			s.bareMaterials = append(s.bareMaterials, getArtifacts(rd.Digest)...)
			continue
		}
		// Digest(s) and URI are set, create IsOccurrence between them.
		s.identifierStrings.UnclassifiedStrings = append(s.identifierStrings.UnclassifiedStrings, rd.URI)
		se, err := getSlsaEntity(rd.URI, rd.Digest)
		if err != nil {
			return err
		}
		s.materials = append(s.materials, se)
	}
	return nil
}

func (s *slsaParser) getMaterials0(materials []scommon.ProvenanceMaterial) error {
	// append dependency nodes for the materials
	for _, mat := range materials {
		s.identifierStrings.UnclassifiedStrings = append(s.identifierStrings.UnclassifiedStrings, mat.URI)
		se, err := getSlsaEntity(mat.URI, mat.Digest)
		if err != nil {
			return err
		}
		s.materials = append(s.materials, se)
	}
	return nil
}

func getArtifacts(digests scommon.DigestSet) []*model.ArtifactInputSpec {
	var artifacts []*model.ArtifactInputSpec
	for alg, ds := range digests {
		artifacts = append(artifacts, &model.ArtifactInputSpec{
			Algorithm: alg,
			Digest:    strings.Trim(ds, "'"), // some slsa documents incorrectly add additional quotes
		})
	}
	return artifacts
}

func getSlsaEntity(name string, digests scommon.DigestSet) (*slsaEntity, error) {
	artifacts := getArtifacts(digests)
	slsa := &slsaEntity{
		artifacts: artifacts,
		occurence: &model.IsOccurrenceInputSpec{
			Justification: "from SLSA definition of checksums for subject/materials",
		},
	}

	if pkg, err := helpers.PurlToPkg(name); err == nil {
		slsa.pkg = pkg
		return slsa, nil
	}

	if src, err := helpers.VcsToSrc(name); err == nil {
		slsa.source = src
		return slsa, nil
	}

	// else we create a GUAC package for it
	pkg, err := helpers.PurlToPkg(helpers.GuacGenericPurl(name))
	if err == nil {
		slsa.pkg = pkg
		return slsa, nil
	}

	return nil, fmt.Errorf("%w unable to get Guac Generic Purl, this should not happen", err)
}

func fillSLSA01(inp *model.SLSAInputSpec, stmt *in_toto.ProvenanceStatementSLSA01) {
	inp.BuildType = stmt.Predicate.Recipe.Type
	if stmt.Predicate.Metadata.BuildStartedOn != nil {
		inp.StartedOn = *stmt.Predicate.Metadata.BuildStartedOn
	}
	if stmt.Predicate.Metadata.BuildFinishedOn != nil {
		inp.FinishedOn = *stmt.Predicate.Metadata.BuildStartedOn
	}
}

func fillSLSA02(inp *model.SLSAInputSpec, stmt *in_toto.ProvenanceStatementSLSA02) {
	inp.BuildType = stmt.Predicate.BuildType
	if stmt.Predicate.Metadata.BuildStartedOn != nil {
		inp.StartedOn = *stmt.Predicate.Metadata.BuildStartedOn
	}
	if stmt.Predicate.Metadata.BuildFinishedOn != nil {
		inp.FinishedOn = *stmt.Predicate.Metadata.BuildStartedOn
	}
}

func fillSLSA1(inp *model.SLSAInputSpec, stmt *in_toto.ProvenanceStatementSLSA1) {
	inp.BuildType = stmt.Predicate.BuildDefinition.BuildType
	if stmt.Predicate.RunDetails.BuildMetadata.StartedOn != nil {
		inp.StartedOn = *stmt.Predicate.RunDetails.BuildMetadata.StartedOn
	}
	if stmt.Predicate.RunDetails.BuildMetadata.FinishedOn != nil {
		inp.FinishedOn = *stmt.Predicate.RunDetails.BuildMetadata.FinishedOn
	}
}

func (s *slsaParser) getSLSA() error {
	inp := &model.SLSAInputSpec{
		SlsaVersion: s.header.PredicateType,
	}

	var pred any
	switch s.header.PredicateType {
	case slsa01.PredicateSLSAProvenance:
		fillSLSA01(inp, s.s01smt)
		pred = s.s01smt.Predicate
	case slsa02.PredicateSLSAProvenance:
		fillSLSA02(inp, s.s02smt)
		pred = s.s02smt.Predicate
	case slsa1.PredicateSLSAProvenance:
		fillSLSA1(inp, s.s1smt)
		pred = s.s1smt.Predicate
	}

	data, _ := json.Marshal(pred)
	var genericMap map[string]any
	err := json.Unmarshal(data, &genericMap)
	if err != nil {
		return fmt.Errorf("Could not unmarshal SLSA Predicate to map: %w", err)
	}

	flatMap, err := flatten.Flatten(genericMap, "slsa.", flatten.SeparatorStyle{Middle: "."})
	if err != nil {
		return fmt.Errorf("Could not flatten SLSA Predicate map: %w", err)
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

func (s *slsaParser) getBuilder() {
	s.builder = &model.BuilderInputSpec{}
	switch s.header.PredicateType {
	case slsa01.PredicateSLSAProvenance:
		s.builder.Uri = s.s01smt.Predicate.Builder.ID
	case slsa02.PredicateSLSAProvenance:
		s.builder.Uri = s.s02smt.Predicate.Builder.ID
	case slsa1.PredicateSLSAProvenance:
		s.builder.Uri = s.s1smt.Predicate.RunDetails.Builder.ID
	}
}

func (s *slsaParser) parseSlsaPredicate(p []byte) error {
	s.header = &in_toto.StatementHeader{}
	if err := json.Unmarshal(p, s.header); err != nil {
		return fmt.Errorf("Could not unmarshal SLSA statement header: %w", err)
	}
	switch s.header.PredicateType {
	case slsa01.PredicateSLSAProvenance:
		s.s01smt = &in_toto.ProvenanceStatementSLSA01{}
		if err := json.Unmarshal(p, s.s01smt); err != nil {
			return fmt.Errorf("Could not unmarshal v0.1 SLSA provenance statement : %w", err)
		}
	case slsa02.PredicateSLSAProvenance:
		s.s02smt = &in_toto.ProvenanceStatementSLSA02{}
		if err := json.Unmarshal(p, s.s02smt); err != nil {
			return fmt.Errorf("Could not unmarshal v0.2 SLSA provenance statement : %w", err)
		}
	case slsa1.PredicateSLSAProvenance:
		s.s1smt = &in_toto.ProvenanceStatementSLSA1{}
		if err := json.Unmarshal(p, s.s1smt); err != nil {
			return fmt.Errorf("Could not unmarshal v1.0 SLSA provenance statement : %w", err)
		}
	default:
		return fmt.Errorf("Unknown SLSA PredicateType: %q", s.header.PredicateType)
	}
	return nil
}

func (s *slsaParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	preds := &assembler.IngestPredicates{}

	// Create occurrences for subjects and materials
	for _, o := range s.subjects {
		for _, a := range o.artifacts {
			preds.IsOccurrence = append(preds.IsOccurrence, assembler.IsOccurrenceIngest{
				Pkg:          o.pkg,
				Src:          o.source,
				Artifact:     a,
				IsOccurrence: o.occurence,
			})
		}
	}

	for _, o := range s.materials {
		for _, a := range o.artifacts {
			preds.IsOccurrence = append(preds.IsOccurrence, assembler.IsOccurrenceIngest{
				Pkg:          o.pkg,
				Src:          o.source,
				Artifact:     a,
				IsOccurrence: o.occurence,
			})
		}
	}

	// Assemble materials
	var materials []model.ArtifactInputSpec
	for _, o := range s.materials {
		for _, a := range o.artifacts {
			materials = append(materials, *a)
		}
	}
	for _, a := range s.bareMaterials {
		materials = append(materials, *a)
	}

	for _, o := range s.subjects {
		for _, a := range o.artifacts {
			preds.HasSlsa = append(preds.HasSlsa, assembler.HasSlsaIngest{
				Artifact:  a,
				HasSlsa:   s.slsaAttestation,
				Materials: materials,
				Builder:   s.builder,
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
