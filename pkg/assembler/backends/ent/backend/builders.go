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

func (b *EntBackend) BuildersList(ctx context.Context, builderSpec model.BuilderSpec, after *string, first *int) (*model.BuilderConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		afterUUID, err := uuid.Parse(*after)
		if err != nil {
			return nil, err
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	query, err := b.client.Builder.Query().
		Where(builderQueryPredicate(&builderSpec)).
		Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, err
	}

	var edges []*model.BuilderEdge
	for _, edge := range query.Edges {
		edges = append(edges, &model.BuilderEdge{
			Cursor: edge.Cursor.ID.String(),
			Node:   toModelBuilder(edge.Node),
		})
	}

	if query.PageInfo.StartCursor != nil {
		return &model.BuilderConnection{
			TotalCount: query.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: query.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(query.PageInfo.StartCursor.ID.String()),
				EndCursor:   ptrfrom.String(query.PageInfo.EndCursor.ID.String()),
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

	builders, err := query.Limit(MaxPageSize).All(ctx)
	if err != nil {
		return nil, err
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
	return toGlobalID(builder.Table, *id), nil
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

	return toGlobalIDs(builder.Table, *ids), nil
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

	query.
		Limit(MaxPageSize)

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
