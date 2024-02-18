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
	"crypto/sha256"
	stdsql "database/sql"

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

func (b *EntBackend) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
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
	id, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		client := ent.TxFromContext(ctx)
		return upsertBuilder(ctx, client, build.BuilderInput)
	})
	if err != nil {
		return "", errors.Wrap(err, funcName)
	}
	return *id, nil
}

func (b *EntBackend) IngestBuilders(ctx context.Context, builders []*model.IDorBuilderInput) ([]string, error) {
	funcName := "IngestBuilders"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkBuilder(ctx, client, builders)
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

func upsertBulkBuilder(ctx context.Context, client *ent.Tx, buildInputs []*model.IDorBuilderInput) (*[]string, error) {
	batches := chunk(buildInputs, 100)
	ids := make([]string, 0)

	for _, builders := range batches {
		creates := make([]*ent.BuilderCreate, len(builders))
		for i, build := range builders {
			builderID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(build.BuilderInput.URI), 5)
			creates[i] = client.Builder.Create().
				SetID(builderID).
				SetURI(build.BuilderInput.URI)

			ids = append(ids, builderID.String())
		}

		err := client.Builder.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(builder.FieldURI),
			).
			UpdateNewValues().
			Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	return &ids, nil
}

func upsertBuilder(ctx context.Context, client *ent.Tx, spec *model.BuilderInputSpec) (*string, error) {
	builderID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(spec.URI), 5)
	id, err := client.Builder.Create().
		SetID(builderID).
		SetURI(spec.URI).OnConflict(
		sql.ConflictColumns(builder.FieldURI),
	).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert builder")
		}
		id = builderID
	}

	return ptrfrom.String(id.String()), nil
}
