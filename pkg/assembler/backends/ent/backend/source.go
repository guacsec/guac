package backend

import (
	"context"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/source"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) IngestSource(ctx context.Context, src model.SourceInputSpec) (*model.Source, error) {
	id, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.FromContext(ctx)
		return ingestSource(ctx, client, src)
	})
	if err != nil {
		return nil, err
	}

	sourceRecord, err := b.client.Source.Query().
		Where(source.IDEQ(*id)).
		WithNamespaces(func(q *ent.SourceNamespaceQuery) {
			q.WithNames()
		}).
		Only(ctx)
	if err != nil {
		return nil, err
	}

	return toModelSource(sourceRecord), nil
}

func ingestSource(ctx context.Context, client *ent.Client, src model.SourceInputSpec) (*int, error) {
	create := client.Source.Create().
		SetType(src.Type).
		SetName(src.Name).
		SetNamespace(src.Namespace)

	if src.Commit != nil {
		create.SetCommit(strings.ToLower(*src.Commit))
	}

	id, err := create.
		SetNillableTag(src.Tag).
		OnConflict(sql.ConflictColumns(
			source.FieldType,
			source.FieldName,
			source.FieldNamespace,
			source.FieldTag,
			source.FieldCommit,
		)).
		UpdateNewValues().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	return &id, nil
}
