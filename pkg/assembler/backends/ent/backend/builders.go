package backend

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/builder"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	query := b.client.Builder.Query().Order(ent.Asc(builder.FieldID))

	if builderSpec != nil {
		query.Where(optionalPredicate(builderSpec.ID, IDEQ))
		query.Where(optionalPredicate(builderSpec.URI, builder.URI))
	} else {
		query.Limit(100)
	}

	builders, err := query.All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(builders, toModelBuilder), nil
}

func (b *EntBackend) IngestBuilder(ctx context.Context, build *model.BuilderInputSpec) (*model.Builder, error) {
	funcName := "IngestBuilder"
	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.FromContext(ctx)

		id, err := client.Builder.Create().
			SetURI(build.URI).
			OnConflict(
				sql.ConflictColumns(
					builder.FieldURI,
				),
			).
			UpdateNewValues().ID(ctx)
		if err != nil {
			return nil, err
		}
		return &id, nil
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}
	record, err := b.client.Builder.Query().
		Where(builder.ID(*recordID)).
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}
	return toModelBuilder(record), nil
}
