//
// Copyright 2023 The GUAC Authors.
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

package backend

import (
	"bytes"
	"context"
	"crypto/sha1"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/slsaattestation"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) HasSlsa(ctx context.Context, spec *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	query := []predicate.SLSAAttestation{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.BuildType, slsaattestation.BuildTypeEQ),
		optionalPredicate(spec.SlsaVersion, slsaattestation.SlsaVersionEQ),
		optionalPredicate(spec.Collector, slsaattestation.CollectorEQ),
		optionalPredicate(spec.Origin, slsaattestation.OriginEQ),
		optionalPredicate(spec.FinishedOn, slsaattestation.FinishedOnEQ),
		optionalPredicate(spec.StartedOn, slsaattestation.StartedOnEQ),
	}

	if spec.BuiltBy != nil {
		query = append(query, slsaattestation.HasBuiltByWith(builderQueryPredicate(spec.BuiltBy)))
	}

	if spec.Subject != nil {
		query = append(query, slsaattestation.HasSubjectWith(artifactQueryPredicates(spec.Subject)))
	}

	for _, art := range spec.BuiltFrom {
		query = append(query, slsaattestation.HasBuiltFromWith(artifactQueryPredicates(art)))
	}

	records, err := b.client.SLSAAttestation.Query().
		Where(query...).
		WithSubject().
		WithBuiltBy().
		WithBuiltFrom().
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelHasSLSA), nil
}

func (b *EntBackend) IngestSLSA(ctx context.Context, subject model.IDorArtifactInput, builtFrom []*model.IDorArtifactInput, builtBy model.IDorBuilderInput, slsa model.SLSAInputSpec) (string, error) {
	id, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertSLSA(ctx, ent.TxFromContext(ctx), subject, builtFrom, builtBy, slsa)
	})
	if err != nil {
		return "", err
	}

	return *id, nil
}

func (b *EntBackend) IngestSLSAs(ctx context.Context, subjects []*model.IDorArtifactInput, builtFromList [][]*model.IDorArtifactInput, builtByList []*model.IDorBuilderInput, slsaList []*model.SLSAInputSpec) ([]string, error) {
	funcName := "IngestSLSAs"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkSLSA(ctx, client, subjects, builtFromList, builtByList, slsaList)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	return *ids, nil
}

func upsertBulkSLSA(ctx context.Context, client *ent.Tx, subjects []*model.IDorArtifactInput, builtFromList [][]*model.IDorArtifactInput, builtByList []*model.IDorBuilderInput, slsaList []*model.SLSAInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		slsaattestation.FieldSubjectID,
		slsaattestation.FieldOrigin,
		slsaattestation.FieldCollector,
		slsaattestation.FieldBuildType,
		slsaattestation.FieldSlsaVersion,
		slsaattestation.FieldBuiltByID,
		slsaattestation.FieldBuiltFromHash}

	batches := chunk(slsaList, 100)

	index := 0
	for _, css := range batches {
		creates := make([]*ent.SLSAAttestationCreate, len(css))
		for i, slsa := range css {

			if builtByList[index].BuilderID == nil {
				return nil, fmt.Errorf("BuilderID not specified in IDorBuilderInput")
			}
			buildID, err := uuid.Parse(*builtByList[index].BuilderID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from BuilderID failed with error: %w", err)
			}

			if subjects[index].ArtifactID == nil {
				return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
			}
			subjectArtifactID, err := uuid.Parse(*subjects[index].ArtifactID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
			}

			var builtFromIDs []string
			for _, bf := range builtFromList[index] {
				builtFromIDs = append(builtFromIDs, *bf.ArtifactID)
			}

			sortedBuildFromIDs := helper.SortAndRemoveDups(builtFromIDs)

			var sortedBuildFromUUIDs []uuid.UUID
			for _, sbfID := range sortedBuildFromIDs {
				sbfUUID, err := uuid.Parse(sbfID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
				}
				sortedBuildFromUUIDs = append(sortedBuildFromUUIDs, sbfUUID)
			}

			creates[i] = client.SLSAAttestation.Create().
				SetBuiltFromHash(hashBuiltFrom(sortedBuildFromIDs)).
				SetSubjectID(subjectArtifactID).
				SetBuildType(slsa.BuildType).
				SetBuiltByID(buildID).
				SetCollector(slsa.Collector).
				SetOrigin(slsa.Origin).
				SetSlsaVersion(slsa.SlsaVersion).
				SetSlsaPredicate(toSLSAInputPredicate(slsa.SlsaPredicate)).
				SetNillableStartedOn(slsa.StartedOn).
				SetNillableFinishedOn(slsa.FinishedOn).
				AddBuiltFromIDs(sortedBuildFromUUIDs...)

			index++
		}

		err := client.SLSAAttestation.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	return &ids, nil
}

func upsertSLSA(ctx context.Context, client *ent.Tx, subject model.IDorArtifactInput, builtFrom []*model.IDorArtifactInput, builtBy model.IDorBuilderInput, slsa model.SLSAInputSpec) (*string, error) {

	if builtBy.BuilderID == nil {
		return nil, fmt.Errorf("BuilderID not specified in IDorBuilderInput")
	}
	buildID, err := uuid.Parse(*builtBy.BuilderID)
	if err != nil {
		return nil, fmt.Errorf("uuid conversion from BuilderID failed with error: %w", err)
	}

	if subject.ArtifactID == nil {
		return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
	}
	subjectArtifactID, err := uuid.Parse(*subject.ArtifactID)
	if err != nil {
		return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
	}

	var builtFromIDs []string
	for _, bf := range builtFrom {
		builtFromIDs = append(builtFromIDs, *bf.ArtifactID)
	}

	sortedBuildFromIDs := helper.SortAndRemoveDups(builtFromIDs)

	var sortedBuildFromUUIDs []uuid.UUID
	for _, sbfID := range sortedBuildFromIDs {
		sbfUUID, err := uuid.Parse(sbfID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
		}
		sortedBuildFromUUIDs = append(sortedBuildFromUUIDs, sbfUUID)
	}

	if _, err := client.SLSAAttestation.Create().
		SetBuiltFromHash(hashBuiltFrom(sortedBuildFromIDs)).
		SetSubjectID(subjectArtifactID).
		SetBuildType(slsa.BuildType).
		SetBuiltByID(buildID).
		SetCollector(slsa.Collector).
		SetOrigin(slsa.Origin).
		SetSlsaVersion(slsa.SlsaVersion).
		SetSlsaPredicate(toSLSAInputPredicate(slsa.SlsaPredicate)).
		SetNillableStartedOn(slsa.StartedOn).
		SetNillableFinishedOn(slsa.FinishedOn).
		AddBuiltFromIDs(sortedBuildFromUUIDs...).
		OnConflict(
			sql.ConflictColumns(
				slsaattestation.FieldSubjectID,
				slsaattestation.FieldOrigin,
				slsaattestation.FieldCollector,
				slsaattestation.FieldBuildType,
				slsaattestation.FieldSlsaVersion,
				slsaattestation.FieldBuiltByID,
				slsaattestation.FieldBuiltFromHash,
			),
		).
		DoNothing().
		ID(ctx); err != nil {

		return nil, err
	}

	return ptrfrom.String(""), nil
}

func toSLSAInputPredicate(rows []*model.SLSAPredicateInputSpec) []*model.SLSAPredicate {
	if len(rows) > 0 {
		preds := make([]*model.SLSAPredicate, len(rows))
		for i, row := range rows {
			preds[i] = &model.SLSAPredicate{
				Key:   row.Key,
				Value: row.Value,
			}
		}

		return preds
	} else {
		return nil
	}
}

func toModelHasSLSA(att *ent.SLSAAttestation) *model.HasSlsa {
	return &model.HasSlsa{
		ID:      att.ID.String(),
		Subject: toModelArtifact(att.Edges.Subject),
		Slsa: &model.Slsa{
			BuiltFrom:     collect(att.Edges.BuiltFrom, toModelArtifact),
			BuiltBy:       toModelBuilder(att.Edges.BuiltBy),
			BuildType:     att.BuildType,
			SlsaPredicate: att.SlsaPredicate,
			SlsaVersion:   att.SlsaVersion,
			StartedOn:     att.StartedOn,
			FinishedOn:    att.FinishedOn,
			Origin:        att.Origin,
			Collector:     att.Collector,
		},
	}
}

// hashBuiltFrom is used to create a unique key for all builtFrom artifacts
func hashBuiltFrom(slc []string) string {
	builtFrom := slc
	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	for _, v := range builtFrom {
		content.WriteString(fmt.Sprintf("%d", v))
	}

	hash.Write(content.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
}
