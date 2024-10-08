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
	"sort"
	"time"

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/slsaattestation"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func slsaGlobalID(id string) string {
	return toGlobalID(slsaattestation.Table, id)
}

func bulkSLSAGlobalID(ids []string) []string {
	return toGlobalIDs(slsaattestation.Table, ids)
}

func (b *EntBackend) HasSLSAList(ctx context.Context, spec model.HasSLSASpec, after *string, first *int) (*model.HasSLSAConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		if globalID.nodeType != slsaattestation.Table {
			return nil, fmt.Errorf("after cursor is not type SLSA but type: %s", globalID.nodeType)
		}
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse global ID with error: %w", err)
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	slsaQuery := b.client.SLSAAttestation.Query().
		Where(hasSLSAQuery(spec))

	slsaConn, err := getSLSAObject(slsaQuery).
		Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed hasSLSA query with error: %w", err)
	}

	// if not found return nil
	if slsaConn == nil {
		return nil, nil
	}

	var edges []*model.HasSLSAEdge
	for _, edge := range slsaConn.Edges {
		edges = append(edges, &model.HasSLSAEdge{
			Cursor: slsaGlobalID(edge.Cursor.ID.String()),
			Node:   toModelHasSLSA(edge.Node),
		})
	}

	if slsaConn.PageInfo.StartCursor != nil {
		return &model.HasSLSAConnection{
			TotalCount: slsaConn.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: slsaConn.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(slsaGlobalID(slsaConn.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(slsaGlobalID(slsaConn.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}

func (b *EntBackend) HasSlsa(ctx context.Context, spec *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	if spec == nil {
		spec = &model.HasSLSASpec{}
	}

	slsaQuery := b.client.SLSAAttestation.Query().
		Where(hasSLSAQuery(*spec))

	records, err := getSLSAObject(slsaQuery).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed hasSLSA query with error: %w", err)
	}

	return collect(records, toModelHasSLSA), nil
}

func hasSLSAQuery(spec model.HasSLSASpec) predicate.SLSAAttestation {
	predicates := []predicate.SLSAAttestation{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.BuildType, slsaattestation.BuildTypeEQ),
		optionalPredicate(spec.SlsaVersion, slsaattestation.SlsaVersionEQ),
		optionalPredicate(spec.Collector, slsaattestation.CollectorEQ),
		optionalPredicate(spec.Origin, slsaattestation.OriginEQ),
		optionalPredicate(spec.DocumentRef, slsaattestation.DocumentRefEQ),
		optionalPredicate(spec.FinishedOn, slsaattestation.FinishedOnEQ),
		optionalPredicate(spec.StartedOn, slsaattestation.StartedOnEQ),
	}

	if spec.BuiltBy != nil {
		if spec.BuiltBy.ID != nil {
			predicates = append(predicates,
				optionalPredicate(spec.BuiltBy.ID, builderIDEQ))
		} else {
			predicates = append(predicates,
				slsaattestation.HasBuiltByWith(builderQueryPredicate(spec.BuiltBy)))
		}
	}

	if spec.Subject != nil {
		if spec.Subject.ID != nil {
			predicates = append(predicates,
				optionalPredicate(spec.Subject.ID, slsaArtifactIDEQ))
		} else {
			predicates = append(predicates,
				slsaattestation.HasSubjectWith(artifactQueryPredicates(spec.Subject)))
		}
	}

	for _, art := range spec.BuiltFrom {
		predicates = append(predicates, slsaattestation.HasBuiltFromWith(artifactQueryPredicates(art)))
	}
	return slsaattestation.And(predicates...)
}

// getSLSAObject is used recreate the hasSLSA object be eager loading the edges
func getSLSAObject(q *ent.SLSAAttestationQuery) *ent.SLSAAttestationQuery {
	return q.
		WithSubject().
		WithBuiltBy().
		WithBuiltFrom()
}

func (b *EntBackend) deleteSLSA(ctx context.Context, SLSAID uuid.UUID) (bool, error) {
	_, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)

		if err := tx.SLSAAttestation.DeleteOneID(SLSAID).Exec(ctx); err != nil {
			return nil, errors.Wrap(err, "failed to delete hasSLSA with error")
		}
		return nil, nil
	})
	if txErr != nil {
		return false, txErr
	}
	return true, nil
}

func (b *EntBackend) IngestSLSA(ctx context.Context, subject model.IDorArtifactInput, builtFrom []*model.IDorArtifactInput, builtBy model.IDorBuilderInput, slsa model.SLSAInputSpec) (string, error) {
	id, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertSLSA(ctx, ent.TxFromContext(ctx), subject, builtFrom, builtBy, slsa)
	})
	if txErr != nil {
		return "", txErr
	}

	return slsaGlobalID(*id), nil
}

func (b *EntBackend) IngestSLSAs(ctx context.Context, subjects []*model.IDorArtifactInput, builtFromList [][]*model.IDorArtifactInput, builtByList []*model.IDorBuilderInput, slsaList []*model.SLSAInputSpec) ([]string, error) {
	funcName := "IngestSLSAs"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkSLSA(ctx, client, subjects, builtFromList, builtByList, slsaList)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return bulkSLSAGlobalID(*ids), nil
}

func slsaConflictColumns() []string {
	return []string{
		slsaattestation.FieldSubjectID,
		slsaattestation.FieldOrigin,
		slsaattestation.FieldCollector,
		slsaattestation.FieldBuildType,
		slsaattestation.FieldSlsaVersion,
		slsaattestation.FieldBuiltByID,
		slsaattestation.FieldStartedOn,
		slsaattestation.FieldFinishedOn,
		slsaattestation.FieldBuiltFromHash,
		slsaattestation.FieldDocumentRef,
	}
}

func upsertBulkSLSA(ctx context.Context, tx *ent.Tx, subjects []*model.IDorArtifactInput, builtFromList [][]*model.IDorArtifactInput, builtByList []*model.IDorBuilderInput, slsaList []*model.SLSAInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	batches := chunk(slsaList, MaxBatchSize)

	index := 0
	for _, css := range batches {
		creates := make([]*ent.SLSAAttestationCreate, len(css))
		for i, slsa := range css {
			slsa := slsa
			var err error
			var hasSBOMID *uuid.UUID
			creates[i], hasSBOMID, err = generateSLSACreate(ctx, tx, subjects[index], builtFromList[index], builtByList[index], slsa)
			if err != nil {
				return nil, gqlerror.Errorf("generateSLSACreate :: %s", err)
			}
			ids = append(ids, hasSBOMID.String())
			index++
		}

		err := tx.SLSAAttestation.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(slsaConflictColumns()...),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert slsa node")
		}
	}

	return &ids, nil
}

func setDefaultTime(inputTime *time.Time) time.Time {
	if inputTime != nil {
		return inputTime.UTC()
	} else {
		return time.Unix(0, 0).UTC()
	}
}

func generateSLSACreate(ctx context.Context, tx *ent.Tx, subject *model.IDorArtifactInput, builtFrom []*model.IDorArtifactInput, builtBy *model.IDorBuilderInput, slsa *model.SLSAInputSpec) (*ent.SLSAAttestationCreate, *uuid.UUID, error) {
	slsaCreate := tx.SLSAAttestation.Create()

	slsaCreate.
		SetBuildType(slsa.BuildType).
		SetCollector(slsa.Collector).
		SetOrigin(slsa.Origin).
		SetDocumentRef(slsa.DocumentRef).
		SetSlsaVersion(slsa.SlsaVersion).
		SetSlsaPredicate(toSLSAInputPredicate(slsa.SlsaPredicate)).
		SetStartedOn(setDefaultTime(slsa.StartedOn)).
		SetFinishedOn(setDefaultTime(slsa.FinishedOn))

	if builtBy == nil {
		return nil, nil, fmt.Errorf("builtBy not specified for SLSA")
	}
	var buildID uuid.UUID
	if builtBy.BuilderID != nil {
		var err error
		builtGlobalID := fromGlobalID(*builtBy.BuilderID)
		buildID, err = uuid.Parse(builtGlobalID.id)
		if err != nil {
			return nil, nil, fmt.Errorf("uuid conversion from BuilderID failed with error: %w", err)
		}
	} else {
		builder, err := tx.Builder.Query().Where(builderInputQueryPredicate(*builtBy.BuilderInput)).Only(ctx)
		if err != nil {
			return nil, nil, err
		}
		buildID = builder.ID
	}
	slsaCreate.SetBuiltByID(buildID)

	var subjectArtifactID uuid.UUID
	if subject.ArtifactID != nil {
		var err error
		artGlobalID := fromGlobalID(*subject.ArtifactID)
		subjectArtifactID, err = uuid.Parse(artGlobalID.id)
		if err != nil {
			return nil, nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
		}
	} else {
		foundArt, err := tx.Artifact.Query().Where(artifactQueryInputPredicates(*subject.ArtifactInput)).Only(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to query for artifact")
		}
		subjectArtifactID = foundArt.ID
	}
	slsaCreate.SetSubjectID(subjectArtifactID)

	var builtFromIDs []string
	var builtFromHash string

	if len(builtFrom) > 0 {
		for _, bf := range builtFrom {
			if bf.ArtifactID != nil {
				artGlobalID := fromGlobalID(*bf.ArtifactID)
				builtFromIDs = append(builtFromIDs, artGlobalID.id)
			} else {
				foundArt, err := tx.Artifact.Query().Where(artifactQueryInputPredicates(*bf.ArtifactInput)).Only(ctx)
				if err != nil {
					return nil, nil, err
				}
				builtFromIDs = append(builtFromIDs, foundArt.ID.String())
			}
		}

		sortedBuildFromIDs := helper.SortAndRemoveDups(builtFromIDs)

		for _, sbfID := range sortedBuildFromIDs {
			sbfUUID, err := uuid.Parse(sbfID)
			if err != nil {
				return nil, nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
			}
			slsaCreate.AddBuiltFromIDs(sbfUUID)
		}

		builtFromHash = hashListOfSortedKeys(sortedBuildFromIDs)
		slsaCreate.SetBuiltFromHash(builtFromHash)
	} else {
		builtFromHash = hashListOfSortedKeys([]string{""})
		slsaCreate.SetBuiltFromHash(builtFromHash)
	}

	slsaID, err := guacSLSAKey(ptrfrom.String(subjectArtifactID.String()), builtFromHash, ptrfrom.String(buildID.String()), slsa)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create slsa uuid with error: %w", err)
	}

	slsaCreate.SetID(*slsaID)

	return slsaCreate, slsaID, nil
}

func upsertSLSA(ctx context.Context, tx *ent.Tx, subject model.IDorArtifactInput, builtFrom []*model.IDorArtifactInput, builtBy model.IDorBuilderInput, slsa model.SLSAInputSpec) (*string, error) {

	slsaCreate, _, err := generateSLSACreate(ctx, tx, &subject, builtFrom, &builtBy, &slsa)
	if err != nil {
		return nil, gqlerror.Errorf("generateSLSACreate :: %s", err)
	}

	if id, err := slsaCreate.
		OnConflict(
			sql.ConflictColumns(slsaConflictColumns()...),
		).
		Ignore().
		ID(ctx); err != nil {

		return nil, errors.Wrap(err, "upsert slsa node")
	} else {
		return ptrfrom.String(id.String()), nil
	}
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

	slsa := &model.Slsa{
		BuiltFrom:     collect(att.Edges.BuiltFrom, toModelArtifact),
		BuiltBy:       toModelBuilder(att.Edges.BuiltBy),
		BuildType:     att.BuildType,
		SlsaPredicate: att.SlsaPredicate,
		SlsaVersion:   att.SlsaVersion,
		Origin:        att.Origin,
		Collector:     att.Collector,
		DocumentRef:   att.DocumentRef,
	}

	if !att.StartedOn.Equal(time.Unix(0, 0).UTC()) {
		slsa.StartedOn = &att.StartedOn
	}

	if !att.FinishedOn.Equal(time.Unix(0, 0).UTC()) {
		slsa.FinishedOn = &att.FinishedOn
	}

	return &model.HasSlsa{
		ID:      slsaGlobalID(att.ID.String()),
		Subject: toModelArtifact(att.Edges.Subject),
		Slsa:    slsa,
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

	return fmt.Sprintf("%s::%s::%s::%s::%s::%s::%s:%s", slsa.BuildType, fmt.Sprintf("%x", hash.Sum(nil)), slsa.SlsaVersion, startedOn, finishedOn, slsa.Origin, slsa.Collector, slsa.DocumentRef)
}

// guacSLSAKey generates an uuid based on the hash of the inputspec and inputs. slsa ID has to be set for bulk ingestion
// when ingesting multiple edges otherwise you get "violates foreign key constraint" as it creates
// a new ID for slsa node (even when already ingested) that it maps to the edge and fails the look up. This only occurs when using UUID with
// "Default" func to generate a new UUID
func guacSLSAKey(subjectID *string, builtFromHash string, builderID *string, slsa *model.SLSAInputSpec) (*uuid.UUID, error) {
	depIDString := fmt.Sprintf("%s::%s::%s::%s?", *subjectID, builtFromHash, *builderID, canonicalSLSAString(*slsa))

	depID := generateUUIDKey([]byte(depIDString))
	return &depID, nil
}

func (b *EntBackend) hasSlsaNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.SLSAAttestation.Query().
		Where(hasSLSAQuery(model.HasSLSASpec{ID: &nodeID}))

	if allowedEdges[model.EdgeHasSlsaSubject] {
		query.
			WithSubject()
	}
	if allowedEdges[model.EdgeHasSlsaBuiltBy] {
		query.
			WithBuiltBy()
	}
	if allowedEdges[model.EdgeHasSlsaMaterials] {
		query.
			WithBuiltFrom()
	}

	slsaAtts, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for hasSLSA with node ID: %s with error: %w", nodeID, err)
	}

	for _, s := range slsaAtts {
		if s.Edges.Subject != nil {
			out = append(out, toModelArtifact(s.Edges.Subject))
		}
		if s.Edges.BuiltBy != nil {
			out = append(out, toModelBuilder(s.Edges.BuiltBy))
		}
		if len(s.Edges.BuiltFrom) > 0 {
			for _, bf := range s.Edges.BuiltFrom {
				out = append(out, toModelArtifact(bf))
			}
		}
	}
	return out, nil
}
