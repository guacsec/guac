package backend

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/builder"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
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
