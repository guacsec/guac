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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hassourceat"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcetype"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) HasSourceAt(ctx context.Context, filter *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	query := []predicate.HasSourceAt{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Collector, hassourceat.CollectorEQ),
		optionalPredicate(filter.Origin, hassourceat.OriginEQ),
		optionalPredicate(filter.Justification, hassourceat.JustificationEQ),
		optionalPredicate(filter.KnownSince, hassourceat.KnownSinceEQ),
	}

	if filter.Package != nil {
		query = append(query,
			hassourceat.Or(
				hassourceat.HasAllVersionsWith(packageNameQuery(pkgNameQueryFromPkgSpec(filter.Package))),
				hassourceat.HasPackageVersionWith(packageVersionQuery(filter.Package)),
			),
		)
	}

	if filter.Source != nil {
		query = append(query, hassourceat.HasSourceWith(sourceQuery(filter.Source)))
	}

	records, err := b.client.HasSourceAt.Query().
		Where(query...).
		WithAllVersions(withPackageNameTree()).
		WithPackageVersion(withPackageVersionTree()).
		WithSource(withSourceNameTreeQuery()).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelHasSourceAt), nil
}

func (b *EntBackend) IngestHasSourceAt(ctx context.Context, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error) {
	record, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.HasSourceAt, error) {
		return upsertHasSourceAt(ctx, ent.TxFromContext(ctx), pkg, pkgMatchType, source, hasSourceAt)
	})
	if err != nil {
		return nil, err
	}

	return toModelHasSourceAt(record.Unwrap()), nil
}

func (b *EntBackend) IngestHasSourceAts(ctx context.Context, pkgs []*model.PkgInputSpec, pkgMatchType *model.MatchFlags, sources []*model.SourceInputSpec, hasSourceAts []*model.HasSourceAtInputSpec) ([]string, error) {
	var result []string
	for i := range hasSourceAts {
		hsa, err := b.IngestHasSourceAt(ctx, *pkgs[i], *pkgMatchType, *sources[i], *hasSourceAts[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestHasSourceAts failed with err: %v", err)
		}
		result = append(result, hsa.ID)
	}
	return result, nil
}

func upsertHasSourceAt(ctx context.Context, client *ent.Tx, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, spec model.HasSourceAtInputSpec) (*ent.HasSourceAt, error) {
	srcID, err := getSourceNameID(ctx, client.Client(), source)
	if err != nil {
		return nil, err
	}

	conflictColumns := []string{hassourceat.FieldSourceID, hassourceat.FieldJustification}
	// conflictWhere MUST match the IndexWhere() defined on the index we plan to use for this query
	var conflictWhere *sql.Predicate

	insert := client.HasSourceAt.Create().
		SetCollector(spec.Collector).
		SetOrigin(spec.Origin).
		SetJustification(spec.Justification).
		SetKnownSince(spec.KnownSince).
		SetSourceID(srcID)

	if pkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
		pkgName, err := client.PackageName.Query().Where(packageNameInputQuery(pkg)).Only(ctx)
		if err != nil {
			return nil, err
		}
		insert.SetAllVersions(pkgName)
		conflictColumns = append(conflictColumns, hassourceat.FieldPackageNameID)
		conflictWhere = sql.And(sql.IsNull(hassourceat.FieldPackageVersionID), sql.NotNull(hassourceat.FieldPackageNameID))
	} else {
		pkgVersion, err := client.PackageVersion.Query().Where(packageVersionInputQuery(pkg)).Only(ctx)
		if err != nil {
			return nil, err
		}
		insert.SetPackageVersion(pkgVersion)
		conflictColumns = append(conflictColumns, hassourceat.FieldPackageVersionID)
		conflictWhere = sql.And(sql.NotNull(hassourceat.FieldPackageVersionID), sql.IsNull(hassourceat.FieldPackageNameID))
	}

	id, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
		sql.ConflictWhere(conflictWhere),
	).
		UpdateNewValues().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	return client.HasSourceAt.Query().
		Where(hassourceat.ID(id)).
		WithSource(withSourceNameTreeQuery()).
		WithAllVersions(withPackageNameTree()).
		WithPackageVersion(withPackageVersionTree()).
		Only(ctx)
}

func (b *EntBackend) Sources(ctx context.Context, filter *model.SourceSpec) ([]*model.Source, error) {
	records, err := b.client.SourceName.Query().
		Where(sourceQuery(filter)).
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

func (b *EntBackend) IngestSourceIDs(ctx context.Context, sources []*model.SourceInputSpec) ([]string, error) {
	ids := make([]string, len(sources))
	for i, src := range sources {
		s, err := b.IngestSourceID(ctx, *src)
		if err != nil {
			return nil, err
		}
		ids[i] = s
	}
	return ids, nil
}

func (b *EntBackend) IngestSourceID(ctx context.Context, source model.SourceInputSpec) (string, error) {
	sourceNameID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		return upsertSource(ctx, ent.TxFromContext(ctx), source)
	})
	if err != nil {
		return "", err
	}

	return strconv.Itoa(*sourceNameID), nil
}

func upsertSource(ctx context.Context, client *ent.Tx, src model.SourceInputSpec) (*int, error) {
	sourceTypeID, err := client.SourceType.Create().
		SetType(src.Type).
		OnConflict(
			sql.ConflictColumns(sourcetype.FieldType),
		).
		DoNothing().
		ID(ctx)

	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert source")
		}
		sourceTypeID, err = client.SourceType.Query().
			Where(sourcetype.TypeEQ(src.Type)).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get source type")
		}
	}

	sourceNamespaceID, err := client.SourceNamespace.Create().
		SetSourceTypeID(sourceTypeID).
		SetNamespace(src.Namespace).
		OnConflict(
			sql.ConflictColumns(sourcenamespace.FieldNamespace, sourcenamespace.FieldSourceID),
		).
		DoNothing().
		ID(ctx)

	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert source namespace")
		}

		sourceNamespaceID, err = client.SourceNamespace.Query().
			Where(
				sourcenamespace.HasSourceTypeWith(sourcetype.IDEQ(sourceTypeID)),
				sourcenamespace.NamespaceEQ(src.Namespace),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get source namespace")
		}
	}

	create := client.SourceName.Create().
		SetNamespaceID(sourceNamespaceID).
		SetName(src.Name).
		SetTag(stringOrEmpty(src.Tag)).
		SetCommit(stringOrEmpty(src.Commit))

	sourceNameID, err := create.
		OnConflict(
			sql.ConflictColumns(
				sourcename.FieldNamespaceID,
				sourcename.FieldName,
				sourcename.FieldTag,
				sourcename.FieldCommit,
			),
		).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert package version")
		}

		sourceNameID, err = client.SourceName.Query().
			Where(
				sourcename.HasNamespaceWith(sourcenamespace.ID(sourceNamespaceID)),
				optionalPredicate(&src.Name, sourcename.NameEQ),
				optionalPredicate(src.Tag, sourcename.TagEQ),
				optionalPredicate(src.Commit, sourcename.CommitEQ),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get sourcename ID")
		}
	}

	return &sourceNameID, nil
}

func sourceInputQuery(filter model.SourceInputSpec) predicate.SourceName {
	return sourceQuery(&model.SourceSpec{
		Commit:    filter.Commit,
		Tag:       filter.Tag,
		Name:      &filter.Name,
		Type:      &filter.Type,
		Namespace: &filter.Namespace,
	})
}

func withSourceNameTreeQuery() func(*ent.SourceNameQuery) {
	return func(q *ent.SourceNameQuery) {
		q.WithNamespace(func(q *ent.SourceNamespaceQuery) {
			q.WithSourceType()
		})
	}
}

func sourceQuery(filter *model.SourceSpec) predicate.SourceName {
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

	return sourcename.And(query...)
}

func toModelHasSourceAt(record *ent.HasSourceAt) *model.HasSourceAt {
	var pkg *model.Package
	if record.Edges.PackageVersion != nil {
		pkg = toModelPackage(backReferencePackageVersion(record.Edges.PackageVersion))
	} else {
		pkg = toModelPackage(backReferencePackageName(record.Edges.AllVersions))
		// in this case, the expected response is package name with an empty package version array
		pkg.Namespaces[0].Names[0].Versions = []*model.PackageVersion{}
	}

	return &model.HasSourceAt{
		Source:        toModelSourceName(record.Edges.Source),
		Package:       pkg,
		ID:            nodeID(record.ID),
		KnownSince:    record.KnownSince,
		Justification: record.Justification,
		Origin:        record.Origin,
		Collector:     record.Collector,
	}
}

func backReferenceSourceName(sn *ent.SourceName) *ent.SourceType {
	if sn.Edges.Namespace != nil {
		sns := sn.Edges.Namespace
		sns.Edges.Names = []*ent.SourceName{sn}
		st := sns.Edges.SourceType
		st.Edges.Namespaces = []*ent.SourceNamespace{sns}
		return st
	}
	return nil
}

func toModelSourceName(s *ent.SourceName) *model.Source {
	return toModelSource(backReferenceSourceName(s))
}

func toModelSource(s *ent.SourceType) *model.Source {
	if s == nil {
		return nil
	}
	return &model.Source{
		ID:   nodeID(s.ID),
		Type: s.Type,
		Namespaces: collect(s.Edges.Namespaces, func(n *ent.SourceNamespace) *model.SourceNamespace {
			return &model.SourceNamespace{
				ID:        nodeID(n.ID),
				Namespace: n.Namespace,
				Names: collect(n.Edges.Names, func(n *ent.SourceName) *model.SourceName {
					return &model.SourceName{
						ID:     nodeID(n.ID),
						Name:   n.Name,
						Tag:    &n.Tag,
						Commit: &n.Commit,
					}
				}),
			}
		}),
	}
}

func getSourceNameID(ctx context.Context, client *ent.Client, s model.SourceInputSpec) (int, error) {
	return client.SourceName.Query().Where(sourceInputQuery(s)).OnlyID(ctx)
}
