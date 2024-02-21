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
	"fmt"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hassourceat"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	srcTypeString      = "srcType"
	srcNamespaceString = "srcNamespace"
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

func (b *EntBackend) IngestHasSourceAt(ctx context.Context, pkg model.IDorPkgInput, pkgMatchType model.MatchFlags, source model.IDorSourceInput, hasSourceAt model.HasSourceAtInputSpec) (string, error) {
	record, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertHasSourceAt(ctx, ent.TxFromContext(ctx), pkg, pkgMatchType, source, hasSourceAt)
	})
	if err != nil {
		return "", err
	}

	return *record, nil
}

func (b *EntBackend) IngestHasSourceAts(ctx context.Context, pkgs []*model.IDorPkgInput, pkgMatchType *model.MatchFlags, sources []*model.IDorSourceInput, hasSourceAts []*model.HasSourceAtInputSpec) ([]string, error) {
	funcName := "IngestHasSourceAts"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkHasSourceAts(ctx, client, pkgs, pkgMatchType, sources, hasSourceAts)
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

func upsertBulkHasSourceAts(ctx context.Context, client *ent.Tx, pkgs []*model.IDorPkgInput, pkgMatchType *model.MatchFlags, sources []*model.IDorSourceInput, hasSourceAts []*model.HasSourceAtInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		hassourceat.FieldSourceID,
		hassourceat.FieldJustification,
		hassourceat.FieldKnownSince,
		hassourceat.FieldCollector,
		hassourceat.FieldOrigin,
	}
	var conflictWhere *sql.Predicate

	if pkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
		conflictColumns = append(conflictColumns, hassourceat.FieldPackageNameID)
		conflictWhere = sql.And(sql.IsNull(hassourceat.FieldPackageVersionID), sql.NotNull(hassourceat.FieldPackageNameID))
	} else {
		conflictColumns = append(conflictColumns, hassourceat.FieldPackageVersionID)
		conflictWhere = sql.And(sql.NotNull(hassourceat.FieldPackageVersionID), sql.IsNull(hassourceat.FieldPackageNameID))
	}

	batches := chunk(hasSourceAts, 100)

	index := 0
	for _, hsas := range batches {
		creates := make([]*ent.HasSourceAtCreate, len(hsas))
		for i, hsa := range hsas {
			creates[i] = client.HasSourceAt.Create().
				SetCollector(hsa.Collector).
				SetOrigin(hsa.Origin).
				SetJustification(hsa.Justification).
				SetKnownSince(hsa.KnownSince.UTC())

			if sources[index].SourceNameID == nil {
				return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
			}
			sourceID, err := uuid.Parse(*sources[index].SourceNameID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
			}
			creates[i].SetSourceID(sourceID)

			if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
				if pkgs[index].PackageVersionID == nil {
					return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
				}
				pkgVersionID, err := uuid.Parse(*pkgs[index].PackageVersionID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from PackageVersionID failed with error: %w", err)
				}
				creates[i].SetNillablePackageVersionID(&pkgVersionID)

			} else {
				if pkgs[index].PackageNameID == nil {
					return nil, fmt.Errorf("packageName ID not specified in IDorPkgInput")
				}
				pkgNameID, err := uuid.Parse(*pkgs[index].PackageNameID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from PackageNameID failed with error: %w", err)
				}
				creates[i].SetNillableAllVersionsID(&pkgNameID)
			}
			index++
		}

		err := client.HasSourceAt.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	return &ids, nil
}

func upsertHasSourceAt(ctx context.Context, client *ent.Tx, pkg model.IDorPkgInput, pkgMatchType model.MatchFlags, source model.IDorSourceInput, spec model.HasSourceAtInputSpec) (*string, error) {

	if source.SourceNameID == nil {
		return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
	}
	sourceID, err := uuid.Parse(*source.SourceNameID)
	if err != nil {
		return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
	}

	conflictColumns := []string{
		hassourceat.FieldSourceID,
		hassourceat.FieldJustification,
		hassourceat.FieldKnownSince,
		hassourceat.FieldCollector,
		hassourceat.FieldOrigin,
	}
	// conflictWhere MUST match the IndexWhere() defined on the index we plan to use for this query
	var conflictWhere *sql.Predicate

	insert := client.HasSourceAt.Create().
		SetCollector(spec.Collector).
		SetOrigin(spec.Origin).
		SetJustification(spec.Justification).
		SetKnownSince(spec.KnownSince.UTC()).
		SetSourceID(sourceID)

	if pkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
		if pkg.PackageNameID == nil {
			return nil, fmt.Errorf("packageName ID not specified in IDorPkgInput")
		}
		pkgNameID, err := uuid.Parse(*pkg.PackageNameID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
		}
		insert.SetNillableAllVersionsID(&pkgNameID)
		conflictColumns = append(conflictColumns, hassourceat.FieldPackageNameID)
		conflictWhere = sql.And(sql.IsNull(hassourceat.FieldPackageVersionID), sql.NotNull(hassourceat.FieldPackageNameID))
	} else {
		if pkg.PackageVersionID == nil {
			return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
		}
		pkgVersionID, err := uuid.Parse(*pkg.PackageVersionID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
		}
		insert.SetNillablePackageVersionID(&pkgVersionID)
		conflictColumns = append(conflictColumns, hassourceat.FieldPackageVersionID)
		conflictWhere = sql.And(sql.NotNull(hassourceat.FieldPackageVersionID), sql.IsNull(hassourceat.FieldPackageNameID))
	}

	id, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
		sql.ConflictWhere(conflictWhere),
	).
		DoNothing().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	return ptrfrom.String(id.String()), nil
}

func (b *EntBackend) Sources(ctx context.Context, filter *model.SourceSpec) ([]*model.Source, error) {
	records, err := b.client.SourceName.Query().
		Where(sourceQuery(filter)).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelSourceName), nil
}

func (b *EntBackend) IngestSources(ctx context.Context, sources []*model.IDorSourceInput) ([]*model.SourceIDs, error) {
	funcName := "IngestSources"
	var collectedSrcIDs []*model.SourceIDs
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]model.SourceIDs, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkSource(ctx, client, sources)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	for _, srcIDs := range *ids {
		collectedSrcIDs = append(collectedSrcIDs, &srcIDs)
	}

	return collectedSrcIDs, nil
}

func (b *EntBackend) IngestSource(ctx context.Context, source model.IDorSourceInput) (*model.SourceIDs, error) {
	sourceNameID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*model.SourceIDs, error) {
		return upsertSource(ctx, ent.TxFromContext(ctx), *source.SourceInput)
	})
	if err != nil {
		return nil, err
	}

	return sourceNameID, nil
}

func upsertBulkSource(ctx context.Context, client *ent.Tx, srcInputs []*model.IDorSourceInput) (*[]model.SourceIDs, error) {
	batches := chunk(srcInputs, 100)
	srcNameIDs := make([]string, 0)

	for _, srcs := range batches {
		srcNameCreates := make([]*ent.SourceNameCreate, len(srcs))

		for i, src := range srcs {
			srcIDs := helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](src.SourceInput, helpers.SrcServerKey)
			srcNameID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(srcIDs.NameId), 5)

			srcNameCreates[i] = client.SourceName.Create().
				SetID(srcNameID).
				SetType(src.SourceInput.Type).
				SetNamespace(src.SourceInput.Namespace).
				SetName(src.SourceInput.Name).
				SetTag(stringOrEmpty(src.SourceInput.Tag)).
				SetCommit(stringOrEmpty(src.SourceInput.Commit))

			srcNameIDs = append(srcNameIDs, srcNameID.String())
		}

		if err := client.SourceName.CreateBulk(srcNameCreates...).
			OnConflict(
				sql.ConflictColumns(
					sourcename.FieldType,
					sourcename.FieldNamespace,
					sourcename.FieldName,
					sourcename.FieldTag,
					sourcename.FieldCommit,
				),
			).
			DoNothing().
			Exec(ctx); err != nil {

			return nil, err
		}
	}
	var collectedSrcIDs []model.SourceIDs
	for i := range srcNameIDs {
		collectedSrcIDs = append(collectedSrcIDs, model.SourceIDs{
			SourceTypeID:      fmt.Sprintf("%s:%s", srcTypeString, srcNameIDs[i]),
			SourceNamespaceID: fmt.Sprintf("%s:%s", srcNamespaceString, srcNameIDs[i]),
			SourceNameID:      srcNameIDs[i]})
	}

	return &collectedSrcIDs, nil
}

func upsertSource(ctx context.Context, client *ent.Tx, src model.SourceInputSpec) (*model.SourceIDs, error) {
	srcIDs := helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](&src, helpers.SrcServerKey)
	srcNameID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(srcIDs.NameId), 5)

	create := client.SourceName.Create().
		SetID(srcNameID).
		SetType(src.Type).
		SetNamespace(src.Namespace).
		SetName(src.Name).
		SetTag(stringOrEmpty(src.Tag)).
		SetCommit(stringOrEmpty(src.Commit))

	_, err := create.
		OnConflict(
			sql.ConflictColumns(
				sourcename.FieldType,
				sourcename.FieldNamespace,
				sourcename.FieldName,
				sourcename.FieldTag,
				sourcename.FieldCommit,
			),
		).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert source name")
		}
	}

	return &model.SourceIDs{
		SourceTypeID:      fmt.Sprintf("%s:%s", srcTypeString, srcNameID.String()),
		SourceNamespaceID: fmt.Sprintf("%s:%s", srcNamespaceString, srcNameID.String()),
		SourceNameID:      srcNameID.String()}, nil
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
	return func(q *ent.SourceNameQuery) {}
}

func sourceQuery(filter *model.SourceSpec) predicate.SourceName {
	query := []predicate.SourceName{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Type, sourcename.TypeEQ),
		optionalPredicate(filter.Namespace, sourcename.NamespaceEQ),
		optionalPredicate(filter.Name, sourcename.NameEQ),
		optionalPredicate(filter.Commit, sourcename.CommitEqualFold),
		optionalPredicate(filter.Tag, sourcename.TagEQ),
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
		ID:            record.ID.String(),
		KnownSince:    record.KnownSince,
		Justification: record.Justification,
		Origin:        record.Origin,
		Collector:     record.Collector,
	}
}

func toModelSourceName(s *ent.SourceName) *model.Source {
	return toModelSource(s)
}

func toModelSource(s *ent.SourceName) *model.Source {
	if s == nil {
		return nil
	}

	sourceName := &model.SourceName{
		ID:   s.ID.String(),
		Name: s.Name,
	}

	if s.Tag != "" {
		sourceName.Tag = &s.Tag
	}
	if s.Commit != "" {
		sourceName.Commit = &s.Commit
	}

	return &model.Source{
		ID:   fmt.Sprintf("%s:%s", srcTypeString, s.ID.String()),
		Type: s.Type,
		Namespaces: []*model.SourceNamespace{{
			ID:        fmt.Sprintf("%s:%s", srcNamespaceString, s.ID.String()),
			Namespace: s.Namespace,
			Names:     []*model.SourceName{sourceName},
		}},
	}
}
