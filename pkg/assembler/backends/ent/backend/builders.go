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

	"entgo.io/ent/dialect/sql"
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

func (b *EntBackend) IngestBuilder(ctx context.Context, build *model.BuilderInputSpec) (*model.Builder, error) {
	funcName := "IngestBuilder"
	record, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.Builder, error) {
		client := ent.TxFromContext(ctx)
		return upsertBuilder(ctx, client, build)
	})
	if err != nil {
		return nil, errors.Wrap(err, funcName)
	}
	return toModelBuilder(record.Unwrap()), nil
}

func (b *EntBackend) IngestBuilders(ctx context.Context, builders []*model.BuilderInputSpec) ([]*model.Builder, error) {
	var modelBuilders []*model.Builder
	for _, builder := range builders {
		modelBuilder, err := b.IngestBuilder(ctx, builder)
		if err != nil {
			return nil, gqlerror.Errorf("IngestBuilders failed with err: %v", err)
		}
		modelBuilders = append(modelBuilders, modelBuilder)
	}
	return modelBuilders, nil
}

func upsertBuilder(ctx context.Context, client *ent.Tx, spec *model.BuilderInputSpec) (*ent.Builder, error) {
	id, err := client.Builder.Create().SetURI(spec.URI).OnConflict(
		sql.ConflictColumns(builder.FieldURI),
	).
		Ignore().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	return client.Builder.Get(ctx, id)
}
