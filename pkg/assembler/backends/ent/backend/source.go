package backend

import (
	"context"
	"log"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/source"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcenamespace"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) IngestSource(ctx context.Context, src model.SourceInputSpec) (*model.Source, error) {
	sourceName, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.SourceName, error) {
		client := ent.FromContext(ctx)
		return upsertSource(ctx, client, src)
	})
	if err != nil {
		return nil, err
	}

	sourceRecord, err := sourceName.Unwrap().QueryNamespace().QuerySourceType().Only(ctx)
	if err != nil {
		return nil, err
	}

	return toModelSource(sourceRecord), nil
}

func upsertSource(ctx context.Context, client *ent.Client, src model.SourceInputSpec) (*ent.SourceName, error) {
	sourceTypeID, err := client.Source.Create().
		SetType(src.Type).
		OnConflict(
			sql.ConflictColumns(source.FieldType),
		).
		UpdateNewValues().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	sourceNamespaceID, err := client.SourceNamespace.Create().
		SetSourceTypeID(sourceTypeID).
		SetNamespace(src.Namespace).
		OnConflict(
			sql.ConflictColumns(sourcenamespace.FieldNamespace, sourcenamespace.FieldSourceID),
		).
		UpdateNewValues().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	create := client.SourceName.Create().
		SetNamespaceID(sourceNamespaceID).
		SetName(src.Name).
		SetNillableTag(src.Tag)

	if src.Commit != nil {
		create.SetCommit(strings.ToLower(*src.Commit))
	}
	sourceNameID, err := create.
		OnConflict(
			sql.ConflictColumns(
				sourcename.FieldNamespaceID,
				sourcename.FieldName,
				sourcename.FieldTag,
				sourcename.FieldCommit,
			),
			sql.ConflictWhere(
				sql.Or(
					sql.NotNull(sourcename.FieldTag),
					sql.NotNull(sourcename.FieldCommit),
				),
			),
		).
		UpdateNewValues().
		ID(ctx)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return client.SourceName.Get(ctx, sourceNameID)
}
