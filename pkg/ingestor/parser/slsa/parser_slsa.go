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
	"errors"
	"fmt"

	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	slsa1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	scommon "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa01 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	smtslsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	"github.com/jeremywohl/flatten"
	"google.golang.org/protobuf/encoding/protojson"

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

var ErrMetadataNil = errors.New("SLSA Metadata is nil")
var ErrBuilderNil = errors.New("SLSA Builder is nil")
var json = jsoniter.ConfigCompatibleWithStandardLibrary

type slsaEntity struct {
	artifacts []*model.ArtifactInputSpec
	occurence *model.IsOccurrenceInputSpec

	// Either pkg or source
	pkg    *model.PkgInputSpec
	source *model.SourceInputSpec
}

type slsaParser struct {
	pred01            *slsa01.ProvenancePredicate
	pred02            *slsa02.ProvenancePredicate
	pred1             *slsa1.Provenance
	smt               *attestationv1.Statement
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
	if err := s.getBuilder(); err != nil {
		return err
	}
	return nil
}

func (s *slsaParser) getSubject() error {
	// append artifact node for the subjects
	for _, sub := range s.smt.Subject {
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
	switch s.smt.PredicateType {
	case slsa01.PredicateSLSAProvenance:
		if err := s.getMaterials0(s.pred01.Materials); err != nil {
			return err
		}
	case slsa02.PredicateSLSAProvenance:
		if err := s.getMaterials0(s.pred02.Materials); err != nil {
			return err
		}
	case smtslsa1.PredicateSLSAProvenance:
		if s.pred1.BuildDefinition == nil {
			return errors.New("SLSA1 buildDefinition is nil")
		}
		if err := s.getMaterials1(s.pred1.BuildDefinition.ResolvedDependencies); err != nil {
			return err
		}
	}
	return nil
}

func (s *slsaParser) getMaterials1(rds []*attestationv1.ResourceDescriptor) error {
	for _, rd := range rds {
		// Only one of URI, Digest, or Content is required.
		// https://github.com/in-toto/attestation/blob/main/spec/v1.0/resource_descriptor.md
		if len(rd.Digest) == 0 {
			// Skip if Digest is empty
			continue
		}
		if rd.Uri == "" {
			// If URI is empty, just add artifacts
			s.bareMaterials = append(s.bareMaterials, getArtifacts(rd.Digest)...)
			continue
		}
		// Digest(s) and URI are set, create IsOccurrence between them.
		s.identifierStrings.UnclassifiedStrings = append(s.identifierStrings.UnclassifiedStrings, rd.Uri)
		se, err := getSlsaEntity(rd.Uri, rd.Digest)
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

func fillSLSA01(inp *model.SLSAInputSpec, pred *slsa01.ProvenancePredicate) error {
	inp.BuildType = pred.Recipe.Type

	if pred.Metadata == nil {
		return ErrMetadataNil
	}
	if pred.Metadata.BuildStartedOn != nil {
		inp.StartedOn = pred.Metadata.BuildStartedOn
	}
	if pred.Metadata.BuildFinishedOn != nil {
		inp.FinishedOn = pred.Metadata.BuildFinishedOn
	}

	return nil
}

func fillSLSA02(inp *model.SLSAInputSpec, pred *slsa02.ProvenancePredicate) error {
	inp.BuildType = pred.BuildType

	if pred.Metadata == nil {
		return ErrMetadataNil
	}
	if pred.Metadata.BuildStartedOn != nil {
		inp.StartedOn = pred.Metadata.BuildStartedOn
	}
	if pred.Metadata.BuildFinishedOn != nil {
		inp.FinishedOn = pred.Metadata.BuildStartedOn
	}
	return nil
}

func fillSLSA1(inp *model.SLSAInputSpec, pred *slsa1.Provenance) error {
	inp.BuildType = pred.BuildDefinition.BuildType
	if pred.RunDetails == nil || pred.RunDetails.Metadata == nil {
		return ErrMetadataNil
	}
	if pred.RunDetails.Metadata.StartedOn != nil {
		startTimePB := time.Unix(pred.RunDetails.Metadata.StartedOn.GetSeconds(), int64(pred.RunDetails.Metadata.StartedOn.GetNanos()))
		inp.StartedOn = &startTimePB
	}
	if pred.RunDetails.Metadata.FinishedOn != nil {
		finishTimePB := time.Unix(pred.RunDetails.Metadata.StartedOn.GetSeconds(), int64(pred.RunDetails.Metadata.StartedOn.GetNanos()))
		inp.FinishedOn = &finishTimePB
	}
	return nil
}

func (s *slsaParser) getSLSA() error {
	inp := &model.SLSAInputSpec{
		SlsaVersion: s.smt.PredicateType,
	}

	var data []byte
	var err error
	switch s.smt.PredicateType {
	case slsa01.PredicateSLSAProvenance:
		if err := fillSLSA01(inp, s.pred01); err != nil {
			return fmt.Errorf("could not fill SLSA01: %w", err)
		}
		if data, err = json.Marshal(s.pred01); err != nil {
			return fmt.Errorf("could not marshal SLSA01: %w", err)
		}
	case slsa02.PredicateSLSAProvenance:
		if err := fillSLSA02(inp, s.pred02); err != nil {
			return fmt.Errorf("could not fill SLSA02: %w", err)
		}
		if data, err = json.Marshal(s.pred02); err != nil {
			return fmt.Errorf("could not marshal SLSA02: %w", err)
		}
	case smtslsa1.PredicateSLSAProvenance:
		if err := fillSLSA1(inp, s.pred1); err != nil {
			return fmt.Errorf("could not fill SLSA1: %w", err)
		}
		if data, err = protojson.Marshal(s.pred1); err != nil {
			return fmt.Errorf("could not marshal SLSA1: %w", err)
		}
	}

	var genericMap map[string]any
	err = json.Unmarshal(data, &genericMap)
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

func (s *slsaParser) getBuilder() error {
	s.builder = &model.BuilderInputSpec{}
	switch s.smt.PredicateType {
	case slsa01.PredicateSLSAProvenance:
		s.builder.Uri = s.pred01.Builder.ID
	case slsa02.PredicateSLSAProvenance:
		s.builder.Uri = s.pred02.Builder.ID
	case smtslsa1.PredicateSLSAProvenance:
		if s.pred1.RunDetails == nil || s.pred1.RunDetails.Builder == nil {
			return ErrBuilderNil
		}
		s.builder.Uri = s.pred1.RunDetails.Builder.Id
	}
	return nil
}

func (s *slsaParser) parseSlsaPredicate(p []byte) error {
	s.smt = &attestationv1.Statement{}
	if err := protojson.Unmarshal(p, s.smt); err != nil {
		return fmt.Errorf("Could not unmarshal SLSA statement: %w", err)
	}

	predBytes, err := json.Marshal(s.smt.Predicate)
	if err != nil {
		return fmt.Errorf("Could not marshal SLSA predicate: %w", err)
	}

	switch s.smt.PredicateType {
	case slsa01.PredicateSLSAProvenance:
		s.pred01 = &slsa01.ProvenancePredicate{}
		if err := json.Unmarshal(predBytes, s.pred01); err != nil {
			return fmt.Errorf("Could not unmarshal v0.1 SLSA provenance statement : %w", err)
		}
	case slsa02.PredicateSLSAProvenance:
		s.pred02 = &slsa02.ProvenancePredicate{}
		if err := json.Unmarshal(predBytes, s.pred02); err != nil {
			return fmt.Errorf("Could not unmarshal v0.2 SLSA provenance statement : %w", err)
		}
	case smtslsa1.PredicateSLSAProvenance:
		s.pred1 = &slsa1.Provenance{}
		if err := protojson.Unmarshal(predBytes, s.pred1); err != nil {
			return fmt.Errorf("Could not unmarshal v1.0 SLSA provenance statement : %w", err)
		}
	default:
		return fmt.Errorf("Unknown SLSA PredicateType: %q", s.smt.PredicateType)
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
