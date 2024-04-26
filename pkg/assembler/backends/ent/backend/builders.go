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
	"context"
	stdsql "database/sql"
	"fmt"

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/builder"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func buildGlobalID(id string) string {
	return toGlobalID(builder.Table, id)
}

func bulkBuildGlobalID(ids []string) []string {
	return toGlobalIDs(builder.Table, ids)
}

func (b *EntBackend) BuildersList(ctx context.Context, builderSpec model.BuilderSpec, after *string, first *int) (*model.BuilderConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		if globalID.nodeType != builder.Table {
			return nil, fmt.Errorf("after cursor is not type builder but type: %s", globalID.nodeType)
		}
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse global ID with error: %w", err)
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	buildConn, err := b.client.Builder.Query().
		Where(builderQueryPredicate(&builderSpec)).
		Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, err
	}

	var edges []*model.BuilderEdge
	for _, edge := range buildConn.Edges {
		edges = append(edges, &model.BuilderEdge{
			Cursor: buildGlobalID(edge.Cursor.ID.String()),
			Node:   toModelBuilder(edge.Node),
		})
	}

	if buildConn.PageInfo.StartCursor != nil {
		return &model.BuilderConnection{
			TotalCount: buildConn.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: buildConn.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(buildGlobalID(buildConn.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(buildGlobalID(buildConn.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}

func (b *EntBackend) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	if builderSpec == nil {
		builderSpec = &model.BuilderSpec{}
	}
	query := b.client.Builder.Query().
		Where(builderQueryPredicate(builderSpec))

	builders, err := query.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed builder query with error: %w", err)
	}

	return collect(builders, toModelBuilder), nil
}

func builderQueryPredicate(spec *model.BuilderSpec) predicate.Builder {
	if spec == nil {
		return NoOpSelector()
	}

	query := []predicate.Builder{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.URI, builder.URI),
	}

	return builder.And(query...)
}

func builderInputQueryPredicate(spec model.BuilderInputSpec) predicate.Builder {
	return builder.URIEqualFold(spec.URI)
}

func (b *EntBackend) IngestBuilder(ctx context.Context, build *model.IDorBuilderInput) (string, error) {
	funcName := "IngestBuilder"
	id, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		client := ent.TxFromContext(ctx)
		return upsertBuilder(ctx, client, build.BuilderInput)
	})
	if txErr != nil {
		return "", errors.Wrap(txErr, funcName)
	}
	return buildGlobalID(*id), nil
}

func (b *EntBackend) IngestBuilders(ctx context.Context, builders []*model.IDorBuilderInput) ([]string, error) {
	funcName := "IngestBuilders"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkBuilder(ctx, client, builders)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return bulkBuildGlobalID(*ids), nil
}

func upsertBulkBuilder(ctx context.Context, tx *ent.Tx, buildInputs []*model.IDorBuilderInput) (*[]string, error) {
	batches := chunk(buildInputs, MaxBatchSize)
	ids := make([]string, 0)

	for _, builders := range batches {
		creates := make([]*ent.BuilderCreate, len(builders))
		for i, build := range builders {
			b := build
			builderID := generateUUIDKey([]byte(b.BuilderInput.URI))
			creates[i] = generateBuilderCreate(tx, &builderID, b.BuilderInput)

			ids = append(ids, builderID.String())
		}

		err := tx.Builder.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(builder.FieldURI),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert builder node")
		}
	}

	return &ids, nil
}

func generateBuilderCreate(tx *ent.Tx, builderID *uuid.UUID, build *model.BuilderInputSpec) *ent.BuilderCreate {
	return tx.Builder.Create().
		SetID(*builderID).
		SetURI(build.URI)
}

func upsertBuilder(ctx context.Context, tx *ent.Tx, spec *model.BuilderInputSpec) (*string, error) {
	builderID := generateUUIDKey([]byte(spec.URI))
	insert := generateBuilderCreate(tx, &builderID, spec)

	err := insert.
		OnConflict(
			sql.ConflictColumns(builder.FieldURI),
		).
		DoNothing().
		Exec(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert builder")
		}
	}

	return ptrfrom.String(builderID.String()), nil
}

func (b *EntBackend) builderNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.Builder.Query().
		Where(builderQueryPredicate(&model.BuilderSpec{ID: &nodeID}))

	if allowedEdges[model.EdgeBuilderHasSlsa] {
		query.
			WithSlsaAttestations(func(q *ent.SLSAAttestationQuery) {
				getSLSAObject(q)
			})
	}

	builders, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed query builder with node ID: %s with error: %w", nodeID, err)
	}

	for _, foundBuilder := range builders {
		for _, foundSLSA := range foundBuilder.Edges.SlsaAttestations {
			out = append(out, toModelHasSLSA(foundSLSA))
		}
	}

	return out, nil
}
