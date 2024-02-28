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
	"crypto/sha256"
	"fmt"
	"sort"
	"time"

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

func upsertBulkSLSA(ctx context.Context, tx *ent.Tx, subjects []*model.IDorArtifactInput, builtFromList [][]*model.IDorArtifactInput, builtByList []*model.IDorBuilderInput, slsaList []*model.SLSAInputSpec) (*[]string, error) {
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
			slsa := slsa
			var err error
			creates[i], err = generateSLSACreate(ctx, tx, subjects[index], builtFromList[index], builtByList[index], slsa)
			if err != nil {
				return nil, gqlerror.Errorf("generateSLSACreate :: %s", err)
			}
			index++
		}

		err := tx.SLSAAttestation.CreateBulk(creates...).
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

func generateSLSACreate(ctx context.Context, tx *ent.Tx, subject *model.IDorArtifactInput, builtFrom []*model.IDorArtifactInput, builtBy *model.IDorBuilderInput, slsa *model.SLSAInputSpec) (*ent.SLSAAttestationCreate, error) {
	slsaCreate := tx.SLSAAttestation.Create()

	slsaCreate.
		SetBuildType(slsa.BuildType).
		SetCollector(slsa.Collector).
		SetOrigin(slsa.Origin).
		SetSlsaVersion(slsa.SlsaVersion).
		SetSlsaPredicate(toSLSAInputPredicate(slsa.SlsaPredicate)).
		SetNillableStartedOn(slsa.StartedOn).
		SetNillableFinishedOn(slsa.FinishedOn)

	if builtBy == nil {
		return nil, fmt.Errorf("builtBy not specified for SLSA")
	}
	var buildID uuid.UUID
	if builtBy.BuilderID != nil {
		var err error
		buildID, err = uuid.Parse(*builtBy.BuilderID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from BuilderID failed with error: %w", err)
		}
	} else {
		builder, err := tx.Builder.Query().Where(builderInputQueryPredicate(*builtBy.BuilderInput)).Only(ctx)
		if err != nil {
			return nil, err
		}
		buildID = builder.ID
	}
	slsaCreate.SetBuiltByID(buildID)

	var subjectArtifactID uuid.UUID
	if subject.ArtifactID != nil {
		var err error
		subjectArtifactID, err = uuid.Parse(*subject.ArtifactID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
		}
	} else {
		foundArt, err := tx.Artifact.Query().Where(artifactQueryInputPredicates(*subject.ArtifactInput)).Only(ctx)
		if err != nil {
			return nil, err
		}
		subjectArtifactID = foundArt.ID
	}
	slsaCreate.SetSubjectID(subjectArtifactID)

	var builtFromIDs []string
	var builtFromHash string

	if len(builtFrom) > 0 {
		for _, bf := range builtFrom {
			if bf.ArtifactID != nil {
				builtFromIDs = append(builtFromIDs, *bf.ArtifactID)
			} else {
				foundArt, err := tx.Artifact.Query().Where(artifactQueryInputPredicates(*bf.ArtifactInput)).Only(ctx)
				if err != nil {
					return nil, err
				}
				builtFromIDs = append(builtFromIDs, foundArt.ID.String())
			}
		}

		sortedBuildFromIDs := helper.SortAndRemoveDups(builtFromIDs)

		for _, sbfID := range sortedBuildFromIDs {
			sbfUUID, err := uuid.Parse(sbfID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
			}
			slsaCreate.AddBuiltFromIDs(sbfUUID)
		}

		builtFromHash = hashListOfSortedKeys(sortedBuildFromIDs)
		slsaCreate.SetBuiltFromHash(builtFromHash)
	} else {
		builtFromHash = hashListOfSortedKeys([]string{""})
		slsaCreate.SetBuiltFromHash(builtFromHash)
	}

	slsaID, err := guacSLSAKey(subject, builtFromHash, builtBy, slsa)
	if err != nil {
		return nil, fmt.Errorf("failed to create slsa uuid with error: %w", err)
	}

	slsaCreate.SetID(*slsaID)

	return slsaCreate, nil
}

func upsertSLSA(ctx context.Context, tx *ent.Tx, subject model.IDorArtifactInput, builtFrom []*model.IDorArtifactInput, builtBy model.IDorBuilderInput, slsa model.SLSAInputSpec) (*string, error) {

	slsaCreate, err := generateSLSACreate(ctx, tx, &subject, builtFrom, &builtBy, &slsa)
	if err != nil {
		return nil, gqlerror.Errorf("generateSLSACreate :: %s", err)
	}

	if _, err := slsaCreate.
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

// hashListOfSortedKeys is used to create a hash of all the keys (i.e. builtFrom artifacts,
// hasSBOM included packages, included artifacts, included dependencies, included occurrences)
func hashListOfSortedKeys(slc []string) string {
	builtFrom := slc
	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	for _, v := range builtFrom {
		content.WriteString(v)
	}

	hash.Write(content.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func canonicalSLSAString(slsa model.SLSAInputSpec) string {

	// To ensure consistency, always sort the checks by key
	predicateMap := map[string]string{}
	var keys []string
	for _, kv := range slsa.SlsaPredicate {
		predicateMap[kv.Key] = kv.Value
		keys = append(keys, kv.Key)
	}
	sort.Strings(keys)
	var predicate []string
	for _, k := range keys {
		predicate = append(predicate, k, predicateMap[k])
	}

	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	for _, v := range predicate {
		content.WriteString(v)
	}

	hash.Write(content.Bytes())

	var startedOn time.Time
	var finishedOn time.Time
	if slsa.StartedOn != nil {
		startedOn = slsa.StartedOn.UTC()
	} else {
		startedOn = time.Unix(0, 0).UTC()
	}
	if slsa.FinishedOn != nil {
		finishedOn = slsa.FinishedOn.UTC()
	} else {
		finishedOn = time.Unix(0, 0).UTC()
	}

	return fmt.Sprintf("%s::%s::%s::%s::%s::%s::%s", slsa.BuildType, fmt.Sprintf("%x", hash.Sum(nil)), slsa.SlsaVersion, startedOn, finishedOn, slsa.Origin, slsa.Collector)
}

// guacSLSAKey generates an uuid based on the hash of the inputspec and inputs. slsa ID has to be set for bulk ingestion
// when ingesting multiple edges otherwise you get "violates foreign key constraint" as it creates
// a new ID for slsa node (even when already ingested) that it maps to the edge and fails the look up. This only occurs when using UUID with
// "Default" func to generate a new UUID
func guacSLSAKey(subject *model.IDorArtifactInput, builtFromHash string, builtBy *model.IDorBuilderInput, slsa *model.SLSAInputSpec) (*uuid.UUID, error) {
	depIDString := fmt.Sprintf("%s::%s::%s::%s?", *subject.ArtifactID, builtFromHash, *builtBy.BuilderID, canonicalSLSAString(*slsa))

	depID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(depIDString), 5)
	return &depID, nil
}
