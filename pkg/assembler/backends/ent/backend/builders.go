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
	"strconv"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/builder"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
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
	id, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.TxFromContext(ctx)
		return upsertBuilder(ctx, client, build.BuilderInput)
	})
	if err != nil {
		return "", errors.Wrap(err, funcName)
	}
	return strconv.Itoa(*id), nil
}

func (b *EntBackend) IngestBuilders(ctx context.Context, builders []*model.IDorBuilderInput) ([]string, error) {
	buildersID := make([]string, len(builders))
	eg, ctx := errgroup.WithContext(ctx)
	for i := range builders {
		index := i
		bld := builders[index]
		concurrently(eg, func() error {
			id, err := b.IngestBuilder(ctx, bld)
			if err == nil {
				buildersID[index] = id
			}
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return buildersID, nil
}

func upsertBuilder(ctx context.Context, client *ent.Tx, spec *model.BuilderInputSpec) (*int, error) {
	id, err := client.Builder.Create().SetURI(spec.URI).OnConflict(
		sql.ConflictColumns(builder.FieldURI),
	).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert builder")
		}
		id, err = client.Builder.Query().
			Where(builder.URIEQ(spec.URI)).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get builder ID")
		}
	}

	return &id, nil
}
