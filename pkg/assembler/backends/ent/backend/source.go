package backend

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcetype"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	return nil, nil
}

func (b *EntBackend) IngestHasSourceAt(ctx context.Context, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error) {
	return nil, nil
}

func (b *EntBackend) Sources(ctx context.Context, filter *model.SourceSpec) ([]*model.Source, error) {
	if filter != nil && filter.Commit != nil && filter.Tag != nil {
		if *filter.Commit != "" && *filter.Tag != "" {
			return nil, Errorf("Passing both commit and tag selectors is an error")
		}
	}

	query := []predicate.SourceName{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Commit, sourcename.CommitEqualFold),
		optionalPredicate(filter.Name, sourcename.NameEQ),
		optionalPredicate(filter.Tag, sourcename.TagEQ),
	}

	if filter.Namespace != nil {
		query = append(query, sourcename.HasNamespaceWith(sourcenamespace.NamespaceEQ(*filter.Namespace)))
	}

	if filter.Type != nil {
		query = append(query, sourcename.HasNamespaceWith(sourcenamespace.HasSourceTypeWith(sourcetype.TypeEQ(*filter.Type))))
	}

	records, err := b.client.SourceName.Query().
		Where(query...).
		Limit(MaxPageSize).
		WithNamespace(func(q *ent.SourceNamespaceQuery) {
			q.WithSourceType()
		}).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelSourceName), nil
}

func (b *EntBackend) IngestSource(ctx context.Context, src model.SourceInputSpec) (*model.Source, error) {
	sourceName, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.SourceName, error) {
		return upsertSource(ctx, ent.TxFromContext(ctx), src)
	})
	if err != nil {
		return nil, err
	}

	return toModelSource(backReferenceSourceName(sourceName.Unwrap())), nil
}

func upsertSource(ctx context.Context, client *ent.Tx, src model.SourceInputSpec) (*ent.SourceName, error) {
	sourceTypeID, err := client.SourceType.Create().
		SetType(src.Type).
		OnConflict(
			sql.ConflictColumns(sourcetype.FieldType),
		).
		Ignore().
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
		Ignore().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	create := client.SourceName.Create().
		SetNamespaceID(sourceNamespaceID).
		SetName(src.Name).
		SetNillableTag(src.Tag).
		SetNillableCommit(toLowerPtr(src.Commit))

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
		return nil, err
	}

	return client.SourceName.Query().
		Where(sourcename.ID(sourceNameID)).
		WithNamespace(func(q *ent.SourceNamespaceQuery) {
			q.WithSourceType()
		}).
		Only(ctx)
}
