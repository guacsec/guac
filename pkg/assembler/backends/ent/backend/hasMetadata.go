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
	"fmt"

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hasmetadata"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func hasMetadataGlobalID(id string) string {
	return toGlobalID(hasmetadata.Table, id)
}

func bulkHasMetadataGlobalID(ids []string) []string {
	return toGlobalIDs(hasmetadata.Table, ids)
}

func (b *EntBackend) HasMetadataList(ctx context.Context, spec model.HasMetadataSpec, after *string, first *int) (*model.HasMetadataConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		if globalID.nodeType != hasmetadata.Table {
			return nil, fmt.Errorf("after cursor is not type hasMetadata but type: %s", globalID.nodeType)
		}
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse global ID with error: %w", err)
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	hmQuery := b.client.HasMetadata.Query().
		Where(hasMetadataPredicate(&spec))

	hmConnect, err := getHasMetadataObject(hmQuery).
		Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed hasMetadata query with error: %w", err)
	}

	// if not found return nil
	if hmConnect == nil {
		return nil, nil
	}

	var edges []*model.HasMetadataEdge
	for _, edge := range hmConnect.Edges {
		edges = append(edges, &model.HasMetadataEdge{
			Cursor: hasMetadataGlobalID(edge.Cursor.ID.String()),
			Node:   toModelHasMetadata(edge.Node),
		})
	}

	if hmConnect.PageInfo.StartCursor != nil {
		return &model.HasMetadataConnection{
			TotalCount: hmConnect.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: hmConnect.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(hasMetadataGlobalID(hmConnect.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(hasMetadataGlobalID(hmConnect.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}

func (b *EntBackend) HasMetadata(ctx context.Context, filter *model.HasMetadataSpec) ([]*model.HasMetadata, error) {
	if filter == nil {
		filter = &model.HasMetadataSpec{}
	}
	hmQuery := b.client.HasMetadata.Query().
		Where(hasMetadataPredicate(filter))

	records, err := getHasMetadataObject(hmQuery).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed hasMetadata query with error: %w", err)
	}

	return collect(records, toModelHasMetadata), nil
}

// getHasMetadataObject is used recreate the hasMetadata object be eager loading the edges
func getHasMetadataObject(q *ent.HasMetadataQuery) *ent.HasMetadataQuery {
	return q.
		WithSource(withSourceNameTreeQuery()).
		WithArtifact().
		WithPackageVersion(withPackageVersionTree()).
		WithAllVersions(withPackageNameTree())
}

func (b *EntBackend) IngestHasMetadata(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, hasMetadata model.HasMetadataInputSpec) (string, error) {
	recordID, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertHasMetadata(ctx, ent.TxFromContext(ctx), subject, pkgMatchType, hasMetadata)
	})
	if txErr != nil {
		return "", fmt.Errorf("failed to execute IngestHasMetadata :: %s", txErr)
	}

	return hasMetadataGlobalID(*recordID), nil
}

func (b *EntBackend) IngestBulkHasMetadata(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, hasMetadataList []*model.HasMetadataInputSpec) ([]string, error) {
	funcName := "IngestBulkHasMetadata"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkHasMetadata(ctx, client, subjects, pkgMatchType, hasMetadataList)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return bulkHasMetadataGlobalID(*ids), nil
}

func hasMetadataPredicate(filter *model.HasMetadataSpec) predicate.HasMetadata {
	predicates := []predicate.HasMetadata{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Key, hasmetadata.KeyEQ),
		optionalPredicate(filter.Value, hasmetadata.ValueEQ),
		optionalPredicate(filter.Justification, hasmetadata.JustificationEQ),
		optionalPredicate(filter.Origin, hasmetadata.OriginEQ),
		optionalPredicate(filter.Collector, hasmetadata.CollectorEQ),
		optionalPredicate(filter.DocumentRef, hasmetadata.DocumentRefEQ),
	}
	if filter.Since != nil {
		timeSince := *filter.Since
		predicates = append(predicates, optionalPredicate(ptrfrom.Time(timeSince.UTC()), hasmetadata.TimestampGTE))
	}

	if filter.Subject != nil {
		switch {
		case filter.Subject.Artifact != nil:
			if filter.Subject.Artifact.ID != nil {
				predicates = append(predicates,
					optionalPredicate(filter.Subject.Artifact.ID, artifactIDEQ))
			} else {
				predicates = append(predicates,
					hasmetadata.HasArtifactWith(artifactQueryPredicates(filter.Subject.Artifact)))
			}
		case filter.Subject.Package != nil:
			if filter.Subject.Package.ID != nil {
				predicates = append(predicates, optionalPredicate(filter.Subject.Package.ID, packageVersionOrNameIDEQ))
			} else {
				predicates = append(predicates, hasmetadata.Or(
					hasmetadata.HasAllVersionsWith(packageNameQuery(pkgNameQueryFromPkgSpec(filter.Subject.Package))),
					hasmetadata.HasPackageVersionWith(packageVersionQuery(filter.Subject.Package)),
				))
			}

		case filter.Subject.Source != nil:
			if filter.Subject.Source.ID != nil {
				predicates = append(predicates,
					optionalPredicate(filter.Subject.Source.ID, sourceIDEQ))
			} else {
				predicates = append(predicates,
					hasmetadata.HasSourceWith(sourceQuery(filter.Subject.Source)))
			}
		}
	}
	return hasmetadata.And(predicates...)
}

func hasMetadataConflictColumns() []string {
	return []string{
		hasmetadata.FieldKey,
		hasmetadata.FieldValue,
		hasmetadata.FieldJustification,
		hasmetadata.FieldTimestamp,
		hasmetadata.FieldOrigin,
		hasmetadata.FieldCollector,
		hasmetadata.FieldDocumentRef,
	}
}

func upsertHasMetadata(ctx context.Context, tx *ent.Tx, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec model.HasMetadataInputSpec) (*string, error) {

	conflictColumns := hasMetadataConflictColumns()
	var conflictWhere *sql.Predicate

	switch {
	case subject.Artifact != nil:
		conflictColumns = append(conflictColumns, hasmetadata.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(hasmetadata.FieldArtifactID),
			sql.IsNull(hasmetadata.FieldPackageNameID),
			sql.IsNull(hasmetadata.FieldPackageVersionID),
			sql.IsNull(hasmetadata.FieldSourceID),
		)

	case subject.Package != nil:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			conflictColumns = append(conflictColumns, hasmetadata.FieldPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(hasmetadata.FieldArtifactID),
				sql.NotNull(hasmetadata.FieldPackageVersionID),
				sql.IsNull(hasmetadata.FieldPackageNameID),
				sql.IsNull(hasmetadata.FieldSourceID),
			)
		} else {
			conflictColumns = append(conflictColumns, hasmetadata.FieldPackageNameID)
			conflictWhere = sql.And(
				sql.IsNull(hasmetadata.FieldArtifactID),
				sql.IsNull(hasmetadata.FieldPackageVersionID),
				sql.NotNull(hasmetadata.FieldPackageNameID),
				sql.IsNull(hasmetadata.FieldSourceID),
			)
		}

	case subject.Source != nil:
		conflictColumns = append(conflictColumns, hasmetadata.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(hasmetadata.FieldArtifactID),
			sql.IsNull(hasmetadata.FieldPackageVersionID),
			sql.IsNull(hasmetadata.FieldPackageNameID),
			sql.NotNull(hasmetadata.FieldSourceID),
		)
	}

	insert, err := generateHasMetadataCreate(ctx, tx, subject.Package, subject.Source, subject.Artifact, pkgMatchType, &spec)
	if err != nil {
		return nil, gqlerror.Errorf("generateDependencyCreate :: %s", err)
	}

	if id, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
		sql.ConflictWhere(conflictWhere),
	).
		Ignore().
		ID(ctx); err != nil {
		return nil, errors.Wrap(err, "upsert HasMetadata node")

	} else {
		return ptrfrom.String(id.String()), nil
	}
}

func generateHasMetadataCreate(ctx context.Context, tx *ent.Tx, pkg *model.IDorPkgInput, src *model.IDorSourceInput, art *model.IDorArtifactInput, pkgMatchType *model.MatchFlags,
	hm *model.HasMetadataInputSpec) (*ent.HasMetadataCreate, error) {

	hasMetadataCreate := tx.HasMetadata.Create()

	hasMetadataCreate.
		SetKey(hm.Key).
		SetValue(hm.Value).
		SetTimestamp(hm.Timestamp.UTC()).
		SetJustification(hm.Justification).
		SetOrigin(hm.Origin).
		SetCollector(hm.Collector).
		SetDocumentRef(hm.DocumentRef)

	switch {
	case art != nil:
		var artID uuid.UUID
		if art.ArtifactID != nil {
			var err error
			artGlobalID := fromGlobalID(*art.ArtifactID)
			artID, err = uuid.Parse(artGlobalID.id)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
			}
		} else {
			foundArt, err := tx.Artifact.Query().Where(artifactQueryInputPredicates(*art.ArtifactInput)).Only(ctx)
			if err != nil {
				return nil, err
			}
			artID = foundArt.ID
		}
		hasMetadataCreate.SetArtifactID(artID)
	case pkg != nil:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
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
			hasMetadataCreate.SetPackageVersionID(pkgVersionID)
		} else {
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
			hasMetadataCreate.SetAllVersionsID(pkgNameID)
		}
	case src != nil:
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
		hasMetadataCreate.SetSourceID(sourceID)
	}
	return hasMetadataCreate, nil
}

func upsertBulkHasMetadata(ctx context.Context, tx *ent.Tx, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, hasMetadataList []*model.HasMetadataInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := hasMetadataConflictColumns()

	var conflictWhere *sql.Predicate

	switch {
	case len(subjects.Artifacts) > 0:
		conflictColumns = append(conflictColumns, hasmetadata.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(hasmetadata.FieldArtifactID),
			sql.IsNull(hasmetadata.FieldPackageNameID),
			sql.IsNull(hasmetadata.FieldPackageVersionID),
			sql.IsNull(hasmetadata.FieldSourceID),
		)

	case len(subjects.Packages) > 0:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			conflictColumns = append(conflictColumns, hasmetadata.FieldPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(hasmetadata.FieldArtifactID),
				sql.NotNull(hasmetadata.FieldPackageVersionID),
				sql.IsNull(hasmetadata.FieldPackageNameID),
				sql.IsNull(hasmetadata.FieldSourceID),
			)
		} else {
			conflictColumns = append(conflictColumns, hasmetadata.FieldPackageNameID)
			conflictWhere = sql.And(
				sql.IsNull(hasmetadata.FieldArtifactID),
				sql.IsNull(hasmetadata.FieldPackageVersionID),
				sql.NotNull(hasmetadata.FieldPackageNameID),
				sql.IsNull(hasmetadata.FieldSourceID),
			)
		}

	case len(subjects.Sources) > 0:
		conflictColumns = append(conflictColumns, hasmetadata.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(hasmetadata.FieldArtifactID),
			sql.IsNull(hasmetadata.FieldPackageVersionID),
			sql.IsNull(hasmetadata.FieldPackageNameID),
			sql.NotNull(hasmetadata.FieldSourceID),
		)
	}

	batches := chunk(hasMetadataList, MaxBatchSize)

	index := 0
	for _, hms := range batches {
		creates := make([]*ent.HasMetadataCreate, len(hms))
		for i, hm := range hms {
			hm := hm
			var err error
			switch {
			case len(subjects.Artifacts) > 0:
				creates[i], err = generateHasMetadataCreate(ctx, tx, nil, nil, subjects.Artifacts[index], pkgMatchType, hm)
				if err != nil {
					return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
				}
			case len(subjects.Packages) > 0:
				creates[i], err = generateHasMetadataCreate(ctx, tx, subjects.Packages[index], nil, nil, pkgMatchType, hm)
				if err != nil {
					return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
				}
			case len(subjects.Sources) > 0:
				creates[i], err = generateHasMetadataCreate(ctx, tx, nil, subjects.Sources[index], nil, pkgMatchType, hm)
				if err != nil {
					return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
				}
			}
			index++
		}

		err := tx.HasMetadata.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert hasMetadata node")
		}
	}

	return &ids, nil
}

func toModelHasMetadata(v *ent.HasMetadata) *model.HasMetadata {
	var sub model.PackageSourceOrArtifact

	switch {
	case v.Edges.Source != nil:
		sub = toModelSource((v.Edges.Source))
	case v.Edges.PackageVersion != nil:
		sub = toModelPackage(backReferencePackageVersion(v.Edges.PackageVersion))
	case v.Edges.AllVersions != nil:
		pkg := toModelPackage(backReferencePackageName(v.Edges.AllVersions))
		// in this case, the expected response is package name with an empty package version array
		pkg.Namespaces[0].Names[0].Versions = []*model.PackageVersion{}
		sub = pkg
	case v.Edges.Artifact != nil:
		sub = toModelArtifact(v.Edges.Artifact)
	}

	return &model.HasMetadata{
		ID:            hasMetadataGlobalID(v.ID.String()),
		Subject:       sub,
		Key:           v.Key,
		Value:         v.Value,
		Timestamp:     v.Timestamp,
		Justification: v.Justification,
		Origin:        v.Origin,
		Collector:     v.Collector,
		DocumentRef:   v.DocumentRef,
	}
}

func (b *EntBackend) hasMetadataNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.HasMetadata.Query().
		Where(hasMetadataPredicate(&model.HasMetadataSpec{ID: &nodeID}))

	if allowedEdges[model.EdgeHasMetadataPackage] {
		query.
			WithPackageVersion(withPackageVersionTree()).
			WithAllVersions()
	}
	if allowedEdges[model.EdgeHasMetadataArtifact] {
		query.
			WithArtifact()
	}
	if allowedEdges[model.EdgeHasMetadataSource] {
		query.
			WithSource()
	}

	hasMetas, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for hasMetadata with node ID: %s with error: %w", nodeID, err)
	}

	for _, hm := range hasMetas {
		if hm.Edges.PackageVersion != nil {
			out = append(out, toModelPackage(backReferencePackageVersion(hm.Edges.PackageVersion)))
		}
		if hm.Edges.AllVersions != nil {
			out = append(out, toModelPackage(hm.Edges.AllVersions))
		}
		if hm.Edges.Artifact != nil {
			out = append(out, toModelArtifact(hm.Edges.Artifact))
		}
		if hm.Edges.Source != nil {
			out = append(out, toModelSource(hm.Edges.Source))
		}
	}

	return out, nil
}
