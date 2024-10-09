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
	"strings"

	"entgo.io/contrib/entgql"
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
	srcTypeString             = "source_types"
	srcNamespaceString        = "source_namespaces"
	guacEmpty          string = "guac-empty-@@"
)

func hasSourceAtGlobalID(id string) string {
	return toGlobalID(hassourceat.Table, id)
}

func bulkHasSourceAtGlobalID(ids []string) []string {
	return toGlobalIDs(hassourceat.Table, ids)
}

func srcTypeGlobalID(id string) string {
	return toGlobalID(srcTypeString, id)
}

func srcNamespaceGlobalID(id string) string {
	return toGlobalID(srcNamespaceString, id)
}

func srcNameGlobalID(id string) string {
	return toGlobalID(sourcename.Table, id)
}

func (b *EntBackend) HasSourceAtList(ctx context.Context, spec model.HasSourceAtSpec, after *string, first *int) (*model.HasSourceAtConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		if globalID.nodeType != hassourceat.Table {
			return nil, fmt.Errorf("after cursor is not type hasSourceAt but type: %s", globalID.nodeType)
		}
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse global ID with error: %w", err)
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	hasSourceAtQuery := b.client.HasSourceAt.Query().
		Where(hasSourceAtQuery(spec))

	hsaConn, err := getHasSourceAtObject(hasSourceAtQuery).
		Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed hasSourceAt query with error: %w", err)
	}

	// if not found return nil
	if hsaConn == nil {
		return nil, nil
	}

	var edges []*model.HasSourceAtEdge
	for _, edge := range hsaConn.Edges {
		edges = append(edges, &model.HasSourceAtEdge{
			Cursor: hasSourceAtGlobalID(edge.Cursor.ID.String()),
			Node:   toModelHasSourceAt(edge.Node),
		})
	}

	if hsaConn.PageInfo.StartCursor != nil {
		return &model.HasSourceAtConnection{
			TotalCount: hsaConn.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: hsaConn.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(hasSourceAtGlobalID(hsaConn.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(hasSourceAtGlobalID(hsaConn.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}

func (b *EntBackend) HasSourceAt(ctx context.Context, filter *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	if filter == nil {
		filter = &model.HasSourceAtSpec{}
	}

	hasSourceAtQuery := b.client.HasSourceAt.Query().
		Where(hasSourceAtQuery(*filter))

	records, err := getHasSourceAtObject(hasSourceAtQuery).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed hasSourceAt query with error: %w", err)
	}

	return collect(records, toModelHasSourceAt), nil
}

func hasSourceAtQuery(filter model.HasSourceAtSpec) predicate.HasSourceAt {
	predicates := []predicate.HasSourceAt{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Collector, hassourceat.CollectorEQ),
		optionalPredicate(filter.Origin, hassourceat.OriginEQ),
		optionalPredicate(filter.DocumentRef, hassourceat.DocumentRefEQ),
		optionalPredicate(filter.Justification, hassourceat.JustificationEQ),
		optionalPredicate(filter.KnownSince, hassourceat.KnownSinceEQ),
	}

	if filter.Package != nil {
		if filter.Package.ID != nil {
			predicates = append(predicates, optionalPredicate(filter.Package.ID, packageVersionOrNameIDEQ))
		} else {
			predicates = append(predicates,
				hassourceat.Or(
					hassourceat.HasAllVersionsWith(packageNameQuery(pkgNameQueryFromPkgSpec(filter.Package))),
					hassourceat.HasPackageVersionWith(packageVersionQuery(filter.Package)),
				),
			)
		}
	}

	if filter.Source != nil {
		if filter.Source.ID != nil {
			predicates = append(predicates,
				optionalPredicate(filter.Source.ID, sourceIDEQ))
		} else {
			predicates = append(predicates,
				hassourceat.HasSourceWith(sourceQuery(filter.Source)))
		}
	}
	return hassourceat.And(predicates...)
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

	return hasSourceAtGlobalID(*record), nil
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

	return bulkHasSourceAtGlobalID(*ids), nil
}

func hasSourceAtConflictColumns() []string {
	return []string{
		hassourceat.FieldSourceID,
		hassourceat.FieldJustification,
		hassourceat.FieldKnownSince,
		hassourceat.FieldCollector,
		hassourceat.FieldOrigin,
		hassourceat.FieldDocumentRef,
	}
}

func upsertBulkHasSourceAts(ctx context.Context, tx *ent.Tx, pkgs []*model.IDorPkgInput, pkgMatchType *model.MatchFlags, sources []*model.IDorSourceInput, hasSourceAts []*model.HasSourceAtInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := hasSourceAtConflictColumns()
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
		SetDocumentRef(hs.DocumentRef).
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
	conflictColumns := hasSourceAtConflictColumns()

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

func (b *EntBackend) hasSourceAtNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.HasSourceAt.Query().
		Where(hasSourceAtQuery(model.HasSourceAtSpec{ID: &nodeID}))

	if allowedEdges[model.EdgeHasSourceAtPackage] {
		query.
			WithPackageVersion(withPackageVersionTree()).
			WithAllVersions()
	}
	if allowedEdges[model.EdgeHasSourceAtSource] {
		query.
			WithSource()
	}

	hasSourceAts, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for hasSourceAt with node ID: %s with error: %w", nodeID, err)
	}

	for _, hs := range hasSourceAts {
		if hs.Edges.PackageVersion != nil {
			out = append(out, toModelPackage(backReferencePackageVersion(hs.Edges.PackageVersion)))
		}
		if hs.Edges.AllVersions != nil {
			out = append(out, toModelPackage(hs.Edges.AllVersions))
		}
		if hs.Edges.Source != nil {
			out = append(out, toModelSource(hs.Edges.Source))
		}
	}

	return out, nil
}

func (b *EntBackend) SourcesList(ctx context.Context, spec model.SourceSpec, after *string, first *int) (*model.SourceConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		if globalID.nodeType != sourcename.Table {
			return nil, fmt.Errorf("after cursor is not type source but type: %s", globalID.nodeType)
		}
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse global ID with error: %w", err)
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	sourceConn, err := b.client.SourceName.Query().
		Where(sourceQuery(&spec)).
		Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed sources query with error: %w", err)
	}

	// if not found return nil
	if sourceConn == nil {
		return nil, nil
	}

	var edges []*model.SourceEdge
	for _, edge := range sourceConn.Edges {
		edges = append(edges, &model.SourceEdge{
			Cursor: srcNameGlobalID(edge.Cursor.ID.String()),
			Node:   toModelSource(edge.Node),
		})
	}

	if sourceConn.PageInfo.StartCursor != nil {
		return &model.SourceConnection{
			TotalCount: sourceConn.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: sourceConn.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(srcNameGlobalID(sourceConn.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(srcNameGlobalID(sourceConn.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}

func (b *EntBackend) Sources(ctx context.Context, filter *model.SourceSpec) ([]*model.Source, error) {
	if filter == nil {
		filter = &model.SourceSpec{}
	}
	records, err := b.client.SourceName.Query().
		Where(sourceQuery(filter)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed sources query with error: %w", err)
	}

	return toModelSourceTrie(records), nil
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
	srcTypes := map[string]string{}
	srcNamespaces := map[string]string{}

	for _, srcs := range batches {
		srcNameCreates := make([]*ent.SourceNameCreate, len(srcs))

		for i, src := range srcs {
			s := src
			srcIDs := helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](s.SourceInput, helpers.SrcServerKey)
			srcNameID := generateUUIDKey([]byte(srcIDs.NameId))

			srcNameCreates[i] = generateSourceNameCreate(tx, &srcNameID, s)
			srcNameIDs = append(srcNameIDs, srcNameID.String())
			srcTypes[srcNameID.String()] = s.SourceInput.Type
			srcNamespaces[srcNameID.String()] = strings.Join([]string{s.SourceInput.Type, s.SourceInput.Namespace}, guacIDSplit)
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
			SourceTypeID:      srcTypeGlobalID(srcTypes[srcNameIDs[i]]),
			SourceNamespaceID: srcNamespaceGlobalID(srcNamespaces[srcNameIDs[i]]),
			SourceNameID:      srcNameGlobalID(srcNameIDs[i])})
	}

	return &collectedSrcIDs, nil
}

func generateSourceNameCreate(tx *ent.Tx, srcNameID *uuid.UUID, srcInput *model.IDorSourceInput) *ent.SourceNameCreate {

	// ensure that guacEmpty does not get added into the DB
	var namespace string
	var tag *string
	var commit *string
	if srcInput.SourceInput.Namespace == guacEmpty {
		namespace = ""
	} else {
		namespace = srcInput.SourceInput.Namespace
	}

	if srcInput.SourceInput.Tag != nil {
		if *srcInput.SourceInput.Tag == guacEmpty {
			tag = ptrfrom.String("")
		} else {
			tag = srcInput.SourceInput.Tag
		}
	}

	if srcInput.SourceInput.Commit != nil {
		if *srcInput.SourceInput.Commit == guacEmpty {
			commit = ptrfrom.String("")
		} else {
			commit = srcInput.SourceInput.Commit
		}
	}

	return tx.SourceName.Create().
		SetID(*srcNameID).
		SetType(srcInput.SourceInput.Type).
		SetNamespace(namespace).
		SetName(srcInput.SourceInput.Name).
		SetTag(stringOrEmpty(tag)).
		SetCommit(stringOrEmpty(commit))
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
		SourceTypeID:      srcTypeGlobalID(src.SourceInput.Type),
		SourceNamespaceID: srcNamespaceGlobalID(strings.Join([]string{src.SourceInput.Type, src.SourceInput.Namespace}, guacIDSplit)),
		SourceNameID:      srcNameGlobalID(srcNameID.String())}, nil
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
		Source:        toModelSource(record.Edges.Source),
		Package:       pkg,
		ID:            hasSourceAtGlobalID(record.ID.String()),
		KnownSince:    record.KnownSince,
		Justification: record.Justification,
		Origin:        record.Origin,
		Collector:     record.Collector,
		DocumentRef:   record.DocumentRef,
	}
}

func toModelSourceTrie(collectedSrcNames []*ent.SourceName) []*model.Source {
	srcTypes := map[string]map[string][]*model.SourceName{}

	for _, srcName := range collectedSrcNames {

		namespaceString := srcName.Namespace + "," + srcNamespaceGlobalID(strings.Join([]string{srcName.Type, srcName.Namespace}, guacIDSplit))
		typeString := srcName.Type + "," + srcTypeGlobalID(srcName.Type)

		sourceName := &model.SourceName{
			ID:   srcNameGlobalID(srcName.ID.String()),
			Name: srcName.Name,
		}
		if srcName.Tag != "" {
			sourceName.Tag = &srcName.Tag
		}
		if srcName.Commit != "" {
			sourceName.Commit = &srcName.Commit
		}
		if srcNamespaces, ok := srcTypes[typeString]; ok {
			srcNamespaces[namespaceString] = append(srcNamespaces[namespaceString], sourceName)
		} else {
			srcNamespaces := map[string][]*model.SourceName{}
			srcNamespaces[namespaceString] = append(srcNamespaces[namespaceString], sourceName)
			srcTypes[typeString] = srcNamespaces
		}
	}
	var sources []*model.Source
	for srcType, namespaces := range srcTypes {
		var sourceNamespaces []*model.SourceNamespace
		for namespace, sourceNames := range namespaces {
			namespaceValues := strings.Split(namespace, ",")
			srcNamespace := &model.SourceNamespace{
				ID:        namespaceValues[1],
				Namespace: namespaceValues[0],
				Names:     sourceNames,
			}
			sourceNamespaces = append(sourceNamespaces, srcNamespace)
		}
		typeValues := strings.Split(srcType, ",")
		source := &model.Source{
			ID:         typeValues[1],
			Type:       typeValues[0],
			Namespaces: sourceNamespaces,
		}
		sources = append(sources, source)
	}

	return sources
}

func toModelSource(s *ent.SourceName) *model.Source {
	if s == nil {
		return nil
	}

	sourceName := &model.SourceName{
		ID:   srcNameGlobalID(s.ID.String()),
		Name: s.Name,
	}

	if s.Tag != "" {
		sourceName.Tag = &s.Tag
	}
	if s.Commit != "" {
		sourceName.Commit = &s.Commit
	}

	return &model.Source{
		ID:   srcTypeGlobalID(s.Type),
		Type: s.Type,
		Namespaces: []*model.SourceNamespace{{
			ID:        srcNamespaceGlobalID(strings.Join([]string{s.Type, s.Namespace}, guacIDSplit)),
			Namespace: s.Namespace,
			Names:     []*model.SourceName{sourceName},
		}},
	}
}

func getSourceNameID(ctx context.Context, client *ent.Client, s model.SourceInputSpec) (uuid.UUID, error) {
	return client.SourceName.Query().Where(sourceInputQuery(s)).OnlyID(ctx)
}

func (b *EntBackend) getSrcNameSpace(ctx context.Context, nodeID string) (*model.Source, error) {
	// split to find the type and namespace value
	splitQueryValue := strings.Split(nodeID, guacIDSplit)
	if len(splitQueryValue) != 2 {
		return nil, fmt.Errorf("invalid query for sourceNamespace with ID %s", nodeID)
	}

	query := b.client.SourceName.Query().
		Where(sourceQuery(&model.SourceSpec{Type: &splitQueryValue[0], Namespace: &splitQueryValue[1]}))

	sn, err := query.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query for sourceNamespace with node ID: %s with error: %w", nodeID, err)
	}

	if len(sn) > 0 {
		srcNamespace := &model.Source{
			ID:   srcTypeGlobalID(sn[0].Type),
			Type: sn[0].Type,
			Namespaces: []*model.SourceNamespace{
				{
					ID:        srcNamespaceGlobalID(strings.Join([]string{sn[0].Type, sn[0].Namespace}, guacIDSplit)),
					Namespace: sn[0].Namespace,
					Names:     []*model.SourceName{},
				},
			},
		}
		return srcNamespace, nil
	} else {
		return nil, fmt.Errorf("failed to get sourceNamespace for node ID: %s", nodeID)
	}
}

func (b *EntBackend) getSrcType(ctx context.Context, nodeID string) (*model.Source, error) {
	query := b.client.SourceName.Query().
		Where(sourceQuery(&model.SourceSpec{Type: &nodeID}))

	sn, err := query.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get source type for node ID: %s with error: %w", nodeID, err)
	}

	if len(sn) > 0 {
		srcType := &model.Source{
			ID:         srcTypeGlobalID(sn[0].Type),
			Type:       sn[0].Type,
			Namespaces: []*model.SourceNamespace{},
		}
		return srcType, nil
	} else {
		return nil, fmt.Errorf("failed to get source type for node ID: %s", nodeID)
	}
}

func (b *EntBackend) srcTypeNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node
	if allowedEdges[model.EdgeSourceTypeSourceNamespace] {
		query := b.client.SourceName.Query().
			Where(sourceQuery(&model.SourceSpec{Type: &nodeID}))

		srcNames, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get sourceType for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundSrcName := range srcNames {
			out = append(out, &model.Source{
				ID:   srcTypeGlobalID(foundSrcName.Type),
				Type: foundSrcName.Type,
				Namespaces: []*model.SourceNamespace{
					{
						ID:        srcNamespaceGlobalID(strings.Join([]string{foundSrcName.Type, foundSrcName.Namespace}, guacIDSplit)),
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

	// split to find the type and namespace value
	splitQueryValue := strings.Split(nodeID, guacIDSplit)
	if len(splitQueryValue) != 2 {
		return out, fmt.Errorf("invalid query for srcNamespaceNeighbors with ID %s", nodeID)
	}

	query := b.client.SourceName.Query().
		Where(sourceQuery(&model.SourceSpec{Type: &splitQueryValue[0], Namespace: &splitQueryValue[1]}))

	srcNames, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for sourceNamespace with node ID: %s with error: %w", nodeID, err)
	}

	if allowedEdges[model.EdgeSourceNamespaceSourceName] {
		for _, foundSrcName := range srcNames {
			out = append(out, &model.Source{
				ID:   srcTypeGlobalID(foundSrcName.Type),
				Type: foundSrcName.Type,
				Namespaces: []*model.SourceNamespace{
					{
						ID:        srcNamespaceGlobalID(strings.Join([]string{foundSrcName.Type, foundSrcName.Namespace}, guacIDSplit)),
						Namespace: foundSrcName.Namespace,
						Names: []*model.SourceName{
							{
								ID:   srcNameGlobalID(foundSrcName.ID.String()),
								Name: foundSrcName.Name,
							},
						},
					},
				},
			})
		}
	}
	if allowedEdges[model.EdgeSourceNamespaceSourceType] {
		for _, foundSrcName := range srcNames {
			out = append(out, &model.Source{
				ID:         srcTypeGlobalID(foundSrcName.Type),
				Type:       foundSrcName.Type,
				Namespaces: []*model.SourceNamespace{},
			})
		}
	}
	return out, nil
}

func (b *EntBackend) srcNameNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.SourceName.Query().
		Where(sourceQuery(&model.SourceSpec{ID: &nodeID}))

	if allowedEdges[model.EdgeSourceHasSourceAt] {
		query.
			WithHasSourceAt(func(q *ent.HasSourceAtQuery) {
				getHasSourceAtObject(q)
			})
	}
	if allowedEdges[model.EdgeSourceCertifyScorecard] {
		query.
			WithScorecard(func(q *ent.CertifyScorecardQuery) {
				getScorecardObject(q)
			})
	}
	if allowedEdges[model.EdgeSourceIsOccurrence] {
		query.
			WithOccurrences(func(q *ent.OccurrenceQuery) {
				getOccurrenceObject(q)
			})
	}
	if allowedEdges[model.EdgeSourceCertifyBad] {
		query.
			WithCertification(func(q *ent.CertificationQuery) {
				q.Where(certification.TypeEQ(certification.TypeBAD))
				getCertificationObject(q)
			})
	}
	if allowedEdges[model.EdgeSourceCertifyGood] {
		query.
			WithCertification(func(q *ent.CertificationQuery) {
				q.Where(certification.TypeEQ(certification.TypeGOOD))
				getCertificationObject(q)
			})
	}
	if allowedEdges[model.EdgeSourceHasMetadata] {
		query.
			WithMetadata(func(q *ent.HasMetadataQuery) {
				getHasMetadataObject(q)
			})
	}
	if allowedEdges[model.EdgeSourcePointOfContact] {
		query.
			WithPoc(func(q *ent.PointOfContactQuery) {
				getPointOfContactObject(q)
			})
	}
	if allowedEdges[model.EdgeSourceCertifyLegal] {
		query.
			WithCertifyLegal(func(q *ent.CertifyLegalQuery) {
				getCertifyLegalObject(q)
			})
	}

	srcNames, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to get source Name for node ID: %s with error: %w", nodeID, err)
	}

	for _, foundSrcName := range srcNames {
		if allowedEdges[model.EdgeSourceNameSourceNamespace] {
			out = append(out, &model.Source{
				ID:   srcTypeGlobalID(foundSrcName.Type),
				Type: foundSrcName.Type,
				Namespaces: []*model.SourceNamespace{
					{
						ID:        srcNamespaceGlobalID(strings.Join([]string{foundSrcName.Type, foundSrcName.Namespace}, guacIDSplit)),
						Namespace: foundSrcName.Namespace,
						Names:     []*model.SourceName{},
					},
				},
			})
		}
		for _, hsat := range foundSrcName.Edges.HasSourceAt {
			out = append(out, toModelHasSourceAt(hsat))
		}
		for _, scorecard := range foundSrcName.Edges.Scorecard {
			out = append(out, toModelCertifyScorecard(scorecard))
		}
		for _, occur := range foundSrcName.Edges.Occurrences {
			out = append(out, toModelIsOccurrenceWithSubject(occur))
		}
		for _, cert := range foundSrcName.Edges.Certification {
			if cert.Type == certification.TypeBAD {
				out = append(out, toModelCertifyBad(cert))
			}
			if cert.Type == certification.TypeGOOD {
				out = append(out, toModelCertifyGood(cert))
			}
		}
		for _, meta := range foundSrcName.Edges.Metadata {
			out = append(out, toModelHasMetadata(meta))
		}
		for _, poc := range foundSrcName.Edges.Poc {
			out = append(out, toModelPointOfContact(poc))
		}
		for _, cl := range foundSrcName.Edges.CertifyLegal {
			out = append(out, toModelCertifyLegal(cl))
		}
	}

	return out, nil
}
