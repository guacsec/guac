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

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hashequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func hashEqualGlobalID(id string) string {
	return toGlobalID(hashequal.Table, id)
}

func bulkHashEqualGlobalID(ids []string) []string {
	return toGlobalIDs(hashequal.Table, ids)
}

func (b *EntBackend) HashEqualList(ctx context.Context, spec model.HashEqualSpec, after *string, first *int) (*model.HashEqualConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		if globalID.nodeType != hashequal.Table {
			return nil, fmt.Errorf("after cursor is not type hashEqual but type: %s", globalID.nodeType)
		}
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse global ID with error: %w", err)
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	heQuery := b.client.HashEqual.Query().
		Where(hashEqualQueryPredicates(&spec))

	haConn, err := getHashEqualObject(heQuery).
		Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed hashEqual query with error: %w", err)
	}

	// if not found return nil
	if haConn == nil {
		return nil, nil
	}

	var edges []*model.HashEqualEdge
	for _, edge := range haConn.Edges {
		edges = append(edges, &model.HashEqualEdge{
			Cursor: hashEqualGlobalID(edge.Cursor.ID.String()),
			Node:   toModelHashEqual(edge.Node),
		})
	}

	if haConn.PageInfo.StartCursor != nil {
		return &model.HashEqualConnection{
			TotalCount: haConn.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: haConn.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(hashEqualGlobalID(haConn.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(hashEqualGlobalID(haConn.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}

func (b *EntBackend) HashEqual(ctx context.Context, spec *model.HashEqualSpec) ([]*model.HashEqual, error) {
	if spec == nil {
		spec = &model.HashEqualSpec{}
	}

	if len(spec.Artifacts) > 2 {
		return nil, fmt.Errorf("too many artifacts specified in hash equal filter")
	}

	heQuery := b.client.HashEqual.Query().
		Where(hashEqualQueryPredicates(spec))

	records, err := getHashEqualObject(heQuery).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed hashEqual query with error: %w", err)
	}

	return collect(records, toModelHashEqual), nil
}

// getHashEqualObject is used recreate the hashEqual object be eager loading the edges
func getHashEqualObject(q *ent.HashEqualQuery) *ent.HashEqualQuery {
	return q.
		WithArtifactA().
		WithArtifactB()
}

func hashEqualQueryPredicates(spec *model.HashEqualSpec) predicate.HashEqual {
	if spec == nil {
		return NoOpSelector()
	}
	predicates := []predicate.HashEqual{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.Origin, hashequal.OriginEQ),
		optionalPredicate(spec.Collector, hashequal.CollectorEQ),
		optionalPredicate(spec.Justification, hashequal.JustificationEQ),
		optionalPredicate(spec.DocumentRef, hashequal.DocumentRefEQ),
	}

	if len(spec.Artifacts) == 1 {
		predicates = append(predicates, hashequal.Or(hashequal.HasArtifactAWith(artifactQueryPredicates(spec.Artifacts[0])), hashequal.HasArtifactBWith(artifactQueryPredicates(spec.Artifacts[0]))))
	} else if len(spec.Artifacts) == 2 {
		predicates = append(predicates, hashequal.Or(hashequal.HasArtifactAWith(artifactQueryPredicates(spec.Artifacts[0])), hashequal.HasArtifactBWith(artifactQueryPredicates(spec.Artifacts[0]))))
		predicates = append(predicates, hashequal.Or(hashequal.HasArtifactAWith(artifactQueryPredicates(spec.Artifacts[1])), hashequal.HasArtifactBWith(artifactQueryPredicates(spec.Artifacts[1]))))
	}

	return hashequal.And(predicates...)
}

func (b *EntBackend) IngestHashEqual(ctx context.Context, artifact model.IDorArtifactInput, equalArtifact model.IDorArtifactInput, spec model.HashEqualInputSpec) (string, error) {
	record, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)
		return upsertHashEqual(ctx, tx, artifact, equalArtifact, spec)
	})
	if txErr != nil {
		return "", txErr
	}

	return hashEqualGlobalID(*record), nil
}

func (b *EntBackend) IngestHashEquals(ctx context.Context, artifacts []*model.IDorArtifactInput, otherArtifacts []*model.IDorArtifactInput, hashEquals []*model.HashEqualInputSpec) ([]string, error) {
	funcName := "IngestHashEquals"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkHashEqual(ctx, client, artifacts, otherArtifacts, hashEquals)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return bulkHashEqualGlobalID(*ids), nil
}

func hasEqualConflictColumns() []string {
	return []string{
		hashequal.FieldArtID,
		hashequal.FieldEqualArtID,
		hashequal.FieldArtifactsHash,
		hashequal.FieldOrigin,
		hashequal.FieldCollector,
		hashequal.FieldJustification,
		hashequal.FieldDocumentRef,
	}
}

func upsertBulkHashEqual(ctx context.Context, tx *ent.Tx, artifacts []*model.IDorArtifactInput, otherArtifacts []*model.IDorArtifactInput, hashEquals []*model.HashEqualInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	batches := chunk(hashEquals, MaxBatchSize)

	index := 0
	for _, hes := range batches {
		creates := make([]*ent.HashEqualCreate, len(hes))
		for i, he := range hes {
			he := he
			var err error
			creates[i], err = generateHashEqualCreate(ctx, tx, artifacts[index], otherArtifacts[index], he)
			if err != nil {
				return nil, gqlerror.Errorf("generateHashEqualCreate :: %s", err)
			}
			index++
		}

		err := tx.HashEqual.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(hasEqualConflictColumns()...),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert hashEqual node")
		}
	}
	return &ids, nil
}

func generateHashEqualCreate(ctx context.Context, tx *ent.Tx, artifactA *model.IDorArtifactInput, artifactB *model.IDorArtifactInput, he *model.HashEqualInputSpec) (*ent.HashEqualCreate, error) {

	if artifactA == nil {
		return nil, fmt.Errorf("artifactA must be specified for hashEqual")
	}
	if artifactB == nil {
		return nil, fmt.Errorf("artifactB must be specified for hashEqual")
	}

	hashEqualCreate := tx.HashEqual.Create().
		SetJustification(he.Justification).
		SetOrigin(he.Origin).
		SetCollector(he.Collector).
		SetDocumentRef(he.DocumentRef)

	if artifactA.ArtifactID == nil {
		foundArt, err := tx.Artifact.Query().Where(artifactQueryInputPredicates(*artifactA.ArtifactInput)).Only(ctx)
		if err != nil {
			return nil, err
		}
		artifactA.ArtifactID = ptrfrom.String(hashEqualGlobalID(foundArt.ID.String()))
	}

	if artifactB.ArtifactID == nil {
		foundArt, err := tx.Artifact.Query().Where(artifactQueryInputPredicates(*artifactB.ArtifactInput)).Only(ctx)
		if err != nil {
			return nil, err
		}
		artifactB.ArtifactID = ptrfrom.String(hashEqualGlobalID(foundArt.ID.String()))
	}

	sortedArtifacts := []model.IDorArtifactInput{*artifactA, *artifactB}

	sort.SliceStable(sortedArtifacts, func(i, j int) bool { return *sortedArtifacts[i].ArtifactID < *sortedArtifacts[j].ArtifactID })

	var sortedArtIDs []uuid.UUID
	for _, art := range sortedArtifacts {
		if art.ArtifactID == nil {
			return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
		}
		artGlobalID := fromGlobalID(*art.ArtifactID)
		artID, err := uuid.Parse(artGlobalID.id)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
		}
		sortedArtIDs = append(sortedArtIDs, artID)
	}

	hashEqualCreate.SetArtifactAID(sortedArtIDs[0])
	hashEqualCreate.SetArtifactBID(sortedArtIDs[1])

	sortedArtifactHash := hashArtifacts(sortedArtifacts)
	hashEqualCreate.SetArtifactsHash(sortedArtifactHash)

	hashEqualID, err := guacHashEqualKey(sortedArtifactHash, he)
	if err != nil {
		return nil, fmt.Errorf("failed to create hashEqual uuid with error: %w", err)
	}
	hashEqualCreate.SetID(*hashEqualID)

	return hashEqualCreate, nil
}

func upsertHashEqual(ctx context.Context, tx *ent.Tx, artifactA model.IDorArtifactInput, artifactB model.IDorArtifactInput, spec model.HashEqualInputSpec) (*string, error) {

	hashEqualCreate, err := generateHashEqualCreate(ctx, tx, &artifactA, &artifactB, &spec)
	if err != nil {
		return nil, gqlerror.Errorf("generateHashEqualCreate :: %s", err)
	}

	if id, err := hashEqualCreate.
		OnConflict(
			sql.ConflictColumns(
				hasEqualConflictColumns()...,
			),
		).
		Ignore().
		ID(ctx); err != nil {

		return nil, errors.Wrap(err, "upsert hashEqual statement node")
	} else {
		return ptrfrom.String(id.String()), nil
	}
}

// hashArtifacts is used to create a unique key for the M2M edge between HashEquals <-M2M-> artifacts
func hashArtifacts(slc []model.IDorArtifactInput) string {
	arts := slc
	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	for _, v := range arts {
		content.WriteString(*v.ArtifactID)
	}

	hash.Write(content.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func toModelHashEqual(record *ent.HashEqual) *model.HashEqual {

	artifacts := []*ent.Artifact{record.Edges.ArtifactA, record.Edges.ArtifactB}

	return &model.HashEqual{
		ID:            hashEqualGlobalID(record.ID.String()),
		Artifacts:     collect(artifacts, toModelArtifact),
		Justification: record.Justification,
		Collector:     record.Collector,
		Origin:        record.Origin,
		DocumentRef:   record.DocumentRef,
	}
}

func canonicalHashEqualString(he *model.HashEqualInputSpec) string {
	return fmt.Sprintf("%s::%s::%s:%s", he.Justification, he.Origin, he.Collector, he.DocumentRef)
}

// guacHashEqualKey generates an uuid based on the hash of the inputspec and inputs. hashEqual ID has to be set for bulk ingestion
// when ingesting multiple edges otherwise you get "violates foreign key constraint" as it creates
// a new ID for hashEqual node (even when already ingested) that it maps to the edge and fails the look up. This only occurs when using UUID with
// "Default" func to generate a new UUID
func guacHashEqualKey(sortedArtHash string, heInput *model.HashEqualInputSpec) (*uuid.UUID, error) {
	heIDString := fmt.Sprintf("%s::%s?", sortedArtHash, canonicalHashEqualString(heInput))

	heID := generateUUIDKey([]byte(heIDString))
	return &heID, nil
}

func (b *EntBackend) hashEqualNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.HashEqual.Query().
		Where(hashEqualQueryPredicates(&model.HashEqualSpec{ID: &nodeID}))

	if allowedEdges[model.EdgeHashEqualArtifact] {
		query.
			WithArtifactA().
			WithArtifactB()
	}

	hasEquals, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for hashEqual with node ID: %s with error: %w", nodeID, err)
	}

	for _, foundHe := range hasEquals {
		if foundHe.Edges.ArtifactA != nil {
			out = append(out, toModelArtifact(foundHe.Edges.ArtifactA))
		}
		if foundHe.Edges.ArtifactB != nil {
			out = append(out, toModelArtifact(foundHe.Edges.ArtifactB))
		}
	}

	return out, nil
}
