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
	"fmt"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certification"
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
	if filter == nil {
		filter = &model.HasSourceAtSpec{}
	}
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

	hasSourceAtQuery := b.client.HasSourceAt.Query().
		Where(query...)

	records, err := getHasSourceAtObject(hasSourceAtQuery).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelHasSourceAt), nil
}

// getHasSourceAtObject is used recreate the HasSourceAt object be eager loading the edges
func getHasSourceAtObject(q *ent.HasSourceAtQuery) *ent.HasSourceAtQuery {
	return q.
		WithAllVersions(withPackageNameTree()).
		WithPackageVersion(withPackageVersionTree()).
		WithSource(withSourceNameTreeQuery())
}

func (b *EntBackend) IngestHasSourceAt(ctx context.Context, pkg model.IDorPkgInput, pkgMatchType model.MatchFlags, source model.IDorSourceInput, hasSourceAt model.HasSourceAtInputSpec) (string, error) {
	record, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertHasSourceAt(ctx, ent.TxFromContext(ctx), pkg, pkgMatchType, source, hasSourceAt)
	})
	if txErr != nil {
		return "", txErr
	}

	return toGlobalID(hassourceat.Table, *record), nil
}

func (b *EntBackend) IngestHasSourceAts(ctx context.Context, pkgs []*model.IDorPkgInput, pkgMatchType *model.MatchFlags, sources []*model.IDorSourceInput, hasSourceAts []*model.HasSourceAtInputSpec) ([]string, error) {
	funcName := "IngestHasSourceAts"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkHasSourceAts(ctx, client, pkgs, pkgMatchType, sources, hasSourceAts)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return toGlobalIDs(hassourceat.Table, *ids), nil
}

func upsertBulkHasSourceAts(ctx context.Context, tx *ent.Tx, pkgs []*model.IDorPkgInput, pkgMatchType *model.MatchFlags, sources []*model.IDorSourceInput, hasSourceAts []*model.HasSourceAtInputSpec) (*[]string, error) {
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

	batches := chunk(hasSourceAts, MaxBatchSize)

	index := 0
	for _, hsas := range batches {
		creates := make([]*ent.HasSourceAtCreate, len(hsas))
		for i, hsa := range hsas {
			hsa := hsa
			var err error

			creates[i], err = generateHasSourceAtCreate(ctx, tx, pkgs[index], sources[index], *pkgMatchType, hsa)
			if err != nil {
				return nil, gqlerror.Errorf("generateHasSourceAtCreate :: %s", err)
			}
			index++
		}

		err := tx.HasSourceAt.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert hasSourceAt node")
		}
	}

	return &ids, nil
}

func generateHasSourceAtCreate(ctx context.Context, tx *ent.Tx, pkg *model.IDorPkgInput, src *model.IDorSourceInput, pkgMatchType model.MatchFlags, hs *model.HasSourceAtInputSpec) (*ent.HasSourceAtCreate, error) {

	if src == nil {
		return nil, fmt.Errorf("source must be specified for hasSourceAt")
	}
	var sourceID uuid.UUID
	if src.SourceNameID != nil {
		var err error
		srcNameGlobalID := fromGlobalID(*src.SourceNameID)
		sourceID, err = uuid.Parse(srcNameGlobalID.id)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from SourceNameID failed with error: %w", err)
		}
	} else {
		srcID, err := getSourceNameID(ctx, tx.Client(), *src.SourceInput)
		if err != nil {
			return nil, err
		}
		sourceID = srcID
	}

	hasSourceAtCreate := tx.HasSourceAt.Create()

	hasSourceAtCreate.
		SetCollector(hs.Collector).
		SetOrigin(hs.Origin).
		SetJustification(hs.Justification).
		SetKnownSince(hs.KnownSince.UTC()).
		SetSourceID(sourceID)

	if pkg == nil {
		return nil, fmt.Errorf("package must be specified for hasSourceAt")
	}
	if pkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
		var pkgNameID uuid.UUID
		if pkg.PackageNameID != nil {
			var err error
			pkgNameGlobalID := fromGlobalID(*pkg.PackageNameID)
			pkgNameID, err = uuid.Parse(pkgNameGlobalID.id)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from PackageNameID failed with error: %w", err)
			}
		} else {
			pn, err := getPkgName(ctx, tx.Client(), *pkg.PackageInput)
			if err != nil {
				return nil, err
			}
			pkgNameID = pn.ID
		}
		hasSourceAtCreate.SetNillableAllVersionsID(&pkgNameID)
	} else {
		var pkgVersionID uuid.UUID
		if pkg.PackageVersionID != nil {
			var err error
			pkgVersionGlobalID := fromGlobalID(*pkg.PackageVersionID)
			pkgVersionID, err = uuid.Parse(pkgVersionGlobalID.id)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
		} else {
			pv, err := getPkgVersion(ctx, tx.Client(), *pkg.PackageInput)
			if err != nil {
				return nil, fmt.Errorf("getPkgVersion :: %w", err)
			}
			pkgVersionID = pv.ID
		}
		hasSourceAtCreate.SetNillablePackageVersionID(&pkgVersionID)
	}

	return hasSourceAtCreate, nil
}

func upsertHasSourceAt(ctx context.Context, tx *ent.Tx, pkg model.IDorPkgInput, pkgMatchType model.MatchFlags, source model.IDorSourceInput, spec model.HasSourceAtInputSpec) (*string, error) {
	conflictColumns := []string{
		hassourceat.FieldSourceID,
		hassourceat.FieldJustification,
		hassourceat.FieldKnownSince,
		hassourceat.FieldCollector,
		hassourceat.FieldOrigin,
	}
	// conflictWhere MUST match the IndexWhere() defined on the index we plan to use for this query
	var conflictWhere *sql.Predicate

	if pkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
		conflictColumns = append(conflictColumns, hassourceat.FieldPackageNameID)
		conflictWhere = sql.And(sql.IsNull(hassourceat.FieldPackageVersionID), sql.NotNull(hassourceat.FieldPackageNameID))
	} else {
		conflictColumns = append(conflictColumns, hassourceat.FieldPackageVersionID)
		conflictWhere = sql.And(sql.NotNull(hassourceat.FieldPackageVersionID), sql.IsNull(hassourceat.FieldPackageNameID))
	}

	insert, err := generateHasSourceAtCreate(ctx, tx, &pkg, &source, pkgMatchType, &spec)
	if err != nil {
		return nil, gqlerror.Errorf("generateHasSourceAtCreate :: %s", err)
	}
	id, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
		sql.ConflictWhere(conflictWhere),
	).
		Ignore().
		ID(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "upsert hasSourceAt node")
	}

	return ptrfrom.String(id.String()), nil
}

func (b *EntBackend) Sources(ctx context.Context, filter *model.SourceSpec) ([]*model.Source, error) {
	if filter == nil {
		filter = &model.SourceSpec{}
	}
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
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]model.SourceIDs, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkSource(ctx, client, sources)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	for _, srcIDs := range *ids {
		s := srcIDs
		collectedSrcIDs = append(collectedSrcIDs, &s)
	}

	return collectedSrcIDs, nil
}

func (b *EntBackend) IngestSource(ctx context.Context, source model.IDorSourceInput) (*model.SourceIDs, error) {
	sourceNameID, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*model.SourceIDs, error) {
		return upsertSource(ctx, ent.TxFromContext(ctx), source)
	})
	if txErr != nil {
		return nil, txErr
	}

	return sourceNameID, nil
}

func upsertBulkSource(ctx context.Context, tx *ent.Tx, srcInputs []*model.IDorSourceInput) (*[]model.SourceIDs, error) {
	batches := chunk(srcInputs, MaxBatchSize)
	srcNameIDs := make([]string, 0)

	for _, srcs := range batches {
		srcNameCreates := make([]*ent.SourceNameCreate, len(srcs))

		for i, src := range srcs {
			s := src
			srcIDs := helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](s.SourceInput, helpers.SrcServerKey)
			srcNameID := generateUUIDKey([]byte(srcIDs.NameId))

			srcNameCreates[i] = generateSourceNameCreate(tx, &srcNameID, s)
			srcNameIDs = append(srcNameIDs, srcNameID.String())
		}

		if err := tx.SourceName.CreateBulk(srcNameCreates...).
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

			return nil, errors.Wrap(err, "bulk upsert source name node")
		}
	}
	var collectedSrcIDs []model.SourceIDs
	for i := range srcNameIDs {
		collectedSrcIDs = append(collectedSrcIDs, model.SourceIDs{
			SourceTypeID:      toGlobalID(srcTypeString, srcNameIDs[i]),
			SourceNamespaceID: toGlobalID(srcNamespaceString, srcNameIDs[i]),
			SourceNameID:      toGlobalID(sourcename.Table, srcNameIDs[i])})
	}

	return &collectedSrcIDs, nil
}

func generateSourceNameCreate(tx *ent.Tx, srcNameID *uuid.UUID, srcInput *model.IDorSourceInput) *ent.SourceNameCreate {
	return tx.SourceName.Create().
		SetID(*srcNameID).
		SetType(srcInput.SourceInput.Type).
		SetNamespace(srcInput.SourceInput.Namespace).
		SetName(srcInput.SourceInput.Name).
		SetTag(stringOrEmpty(srcInput.SourceInput.Tag)).
		SetCommit(stringOrEmpty(srcInput.SourceInput.Commit))
}

func upsertSource(ctx context.Context, tx *ent.Tx, src model.IDorSourceInput) (*model.SourceIDs, error) {
	srcIDs := helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](src.SourceInput, helpers.SrcServerKey)
	srcNameID := generateUUIDKey([]byte(srcIDs.NameId))

	create := generateSourceNameCreate(tx, &srcNameID, &src)
	err := create.
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
		Exec(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert source name")
		}
	}

	return &model.SourceIDs{
		SourceTypeID:      toGlobalID(srcTypeString, srcNameID.String()),
		SourceNamespaceID: toGlobalID(srcNamespaceString, srcNameID.String()),
		SourceNameID:      toGlobalID(sourcename.Table, srcNameID.String())}, nil
}

func sourceInputQuery(filter model.SourceInputSpec) predicate.SourceName {
	return sourceQuery(&model.SourceSpec{
		Commit:    ptrfrom.String(stringOrEmpty(filter.Commit)),
		Tag:       ptrfrom.String(stringOrEmpty(filter.Tag)),
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
		ID:            toGlobalID(hassourceat.Table, record.ID.String()),
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
		ID:   toGlobalID(sourcename.Table, s.ID.String()),
		Name: s.Name,
	}

	if s.Tag != "" {
		sourceName.Tag = &s.Tag
	}
	if s.Commit != "" {
		sourceName.Commit = &s.Commit
	}

	return &model.Source{
		ID:   toGlobalID(srcTypeString, s.ID.String()),
		Type: s.Type,
		Namespaces: []*model.SourceNamespace{{
			ID:        toGlobalID(srcNamespaceString, s.ID.String()),
			Namespace: s.Namespace,
			Names:     []*model.SourceName{sourceName},
		}},
	}
}

func getSourceNameID(ctx context.Context, client *ent.Client, s model.SourceInputSpec) (uuid.UUID, error) {
	return client.SourceName.Query().Where(sourceInputQuery(s)).OnlyID(ctx)
}

func (b *EntBackend) srcTypeNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node
	if allowedEdges[model.EdgeSourceTypeSourceNamespace] {
		query := b.client.SourceName.Query().
			Where(sourceQuery(&model.SourceSpec{ID: &nodeID})).
			Limit(MaxPageSize)

		srcNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get srcNamespace for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundSrcName := range srcNames {
			out = append(out, &model.Source{
				ID:   toGlobalID(srcTypeString, foundSrcName.ID.String()),
				Type: foundSrcName.Type,
				Namespaces: []*model.SourceNamespace{
					{
						ID:        toGlobalID(srcNamespaceString, foundSrcName.ID.String()),
						Namespace: foundSrcName.Namespace,
						Names:     []*model.SourceName{},
					},
				},
			})
		}
	}
	return out, nil
}

func (b *EntBackend) srcNamespaceNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node
	if allowedEdges[model.EdgeSourceNamespaceSourceName] {
		query := b.client.SourceName.Query().
			Where(sourceQuery(&model.SourceSpec{ID: &nodeID})).
			Limit(MaxPageSize)

		srcNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get srcNames for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundSrcName := range srcNames {
			out = append(out, &model.Source{
				ID:   toGlobalID(srcTypeString, foundSrcName.ID.String()),
				Type: foundSrcName.Type,
				Namespaces: []*model.SourceNamespace{
					{
						ID:        toGlobalID(srcNamespaceString, foundSrcName.ID.String()),
						Namespace: foundSrcName.Namespace,
						Names: []*model.SourceName{
							{
								ID:   toGlobalID(sourcename.Table, foundSrcName.ID.String()),
								Name: foundSrcName.Name,
							},
						},
					},
				},
			})
		}
	}
	if allowedEdges[model.EdgeSourceNamespaceSourceType] {
		query := b.client.SourceName.Query().
			Where(sourceQuery(&model.SourceSpec{ID: &nodeID})).
			Limit(MaxPageSize)

		srcNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get srcNamespace for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundSrcName := range srcNames {
			out = append(out, &model.Source{
				ID:         toGlobalID(srcTypeString, foundSrcName.ID.String()),
				Type:       foundSrcName.Type,
				Namespaces: []*model.SourceNamespace{},
			})
		}
	}
	return out, nil
}

func (b *EntBackend) srcNameNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node
	if allowedEdges[model.EdgeSourceNameSourceNamespace] {
		query := b.client.SourceName.Query().
			Where(sourceQuery(&model.SourceSpec{ID: &nodeID})).
			Limit(MaxPageSize)

		srcNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get srcNamespace for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundSrcName := range srcNames {
			out = append(out, &model.Source{
				ID:   toGlobalID(srcTypeString, foundSrcName.ID.String()),
				Type: foundSrcName.Type,
				Namespaces: []*model.SourceNamespace{
					{
						ID:        toGlobalID(srcNamespaceString, foundSrcName.ID.String()),
						Namespace: foundSrcName.Namespace,
						Names:     []*model.SourceName{},
					},
				},
			})
		}
	}
	if allowedEdges[model.EdgeSourceHasSourceAt] {
		query := b.client.SourceName.Query().
			Where(sourceQuery(&model.SourceSpec{ID: &nodeID})).
			WithHasSourceAt(func(q *ent.HasSourceAtQuery) {
				getHasSourceAtObject(q)
			}).
			Limit(MaxPageSize)

		srcNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get hasSourceAt for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundSrcName := range srcNames {
			for _, hsat := range foundSrcName.Edges.HasSourceAt {
				out = append(out, toModelHasSourceAt(hsat))
			}
		}
	}
	if allowedEdges[model.EdgeSourceCertifyScorecard] {
		query := b.client.SourceName.Query().
			Where(sourceQuery(&model.SourceSpec{ID: &nodeID})).
			WithScorecard(func(q *ent.CertifyScorecardQuery) {
				getScorecardObject(q)
			}).
			Limit(MaxPageSize)

		srcNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get scorecard for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundSrcName := range srcNames {
			for _, scorecard := range foundSrcName.Edges.Scorecard {
				out = append(out, toModelCertifyScorecard(scorecard))
			}
		}
	}
	if allowedEdges[model.EdgeSourceIsOccurrence] {
		query := b.client.SourceName.Query().
			Where(sourceQuery(&model.SourceSpec{ID: &nodeID})).
			WithOccurrences(func(q *ent.OccurrenceQuery) {
				getOccurrenceObject(q)
			}).
			Limit(MaxPageSize)

		srcNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get occurrence for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundSrcName := range srcNames {
			for _, occur := range foundSrcName.Edges.Occurrences {
				out = append(out, toModelIsOccurrenceWithSubject(occur))
			}
		}
	}
	if allowedEdges[model.EdgeSourceCertifyBad] {
		query := b.client.SourceName.Query().
			Where(sourceQuery(&model.SourceSpec{ID: &nodeID})).
			WithCertification(func(q *ent.CertificationQuery) {
				getCertificationObject(q)
			}).
			Limit(MaxPageSize)

		srcNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get certifyBad for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundSrcName := range srcNames {
			for _, cert := range foundSrcName.Edges.Certification {
				if cert.Type == certification.TypeBAD {
					out = append(out, toModelCertifyBad(cert))
				}
			}
		}
	}
	if allowedEdges[model.EdgeSourceCertifyGood] {
		query := b.client.SourceName.Query().
			Where(sourceQuery(&model.SourceSpec{ID: &nodeID})).
			WithCertification(func(q *ent.CertificationQuery) {
				getCertificationObject(q)
			}).
			Limit(MaxPageSize)

		srcNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get certifyGood for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundSrcName := range srcNames {
			for _, cert := range foundSrcName.Edges.Certification {
				if cert.Type == certification.TypeGOOD {
					out = append(out, toModelCertifyGood(cert))
				}
			}
		}
	}
	if allowedEdges[model.EdgeSourceHasMetadata] {
		query := b.client.SourceName.Query().
			Where(sourceQuery(&model.SourceSpec{ID: &nodeID})).
			WithMetadata(func(q *ent.HasMetadataQuery) {
				getHasMetadataObject(q)
			}).
			Limit(MaxPageSize)

		srcNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get hasMetadata for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundSrcName := range srcNames {
			for _, meta := range foundSrcName.Edges.Metadata {
				out = append(out, toModelHasMetadata(meta))
			}
		}
	}
	if allowedEdges[model.EdgeSourcePointOfContact] {
		query := b.client.SourceName.Query().
			Where(sourceQuery(&model.SourceSpec{ID: &nodeID})).
			WithPoc(func(q *ent.PointOfContactQuery) {
				getPointOfContactObject(q)
			}).
			Limit(MaxPageSize)

		srcNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get point of contact for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundSrcName := range srcNames {
			for _, poc := range foundSrcName.Edges.Poc {
				out = append(out, toModelPointOfContact(poc))
			}
		}
	}
	if allowedEdges[model.EdgeSourceCertifyLegal] {
		query := b.client.SourceName.Query().
			Where(sourceQuery(&model.SourceSpec{ID: &nodeID})).
			WithCertifyLegal(func(q *ent.CertifyLegalQuery) {
				getCertifyLegalObject(q)
			}).
			Limit(MaxPageSize)

		srcNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get certifyLegal for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundSrcName := range srcNames {
			for _, cl := range foundSrcName.Edges.CertifyLegal {
				out = append(out, toModelCertifyLegal(cl))
			}
		}
	}

	return out, nil
}
