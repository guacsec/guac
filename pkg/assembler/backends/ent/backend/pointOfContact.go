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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pointofcontact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func pointOfContactGlobalID(id string) string {
	return toGlobalID(pointofcontact.Table, id)
}

func bulkPointOfContactGlobalID(ids []string) []string {
	return toGlobalIDs(pointofcontact.Table, ids)
}

func (b *EntBackend) PointOfContactList(ctx context.Context, spec model.PointOfContactSpec, after *string, first *int) (*model.PointOfContactConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		if globalID.nodeType != pointofcontact.Table {
			return nil, fmt.Errorf("after cursor is not type Point of Contact but type: %s", globalID.nodeType)
		}
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse global ID with error: %w", err)
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	pocQuery := b.client.PointOfContact.Query().
		Where(pointOfContactPredicate(&spec))

	pocConn, err := getPointOfContactObject(pocQuery).
		Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed PointOfContact query with error: %w", err)
	}

	// if not found return nil
	if pocConn == nil {
		return nil, nil
	}

	var edges []*model.PointOfContactEdge
	for _, edge := range pocConn.Edges {
		edges = append(edges, &model.PointOfContactEdge{
			Cursor: pointOfContactGlobalID(edge.Cursor.ID.String()),
			Node:   toModelPointOfContact(edge.Node),
		})
	}

	if pocConn.PageInfo.StartCursor != nil {
		return &model.PointOfContactConnection{
			TotalCount: pocConn.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: pocConn.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(pointOfContactGlobalID(pocConn.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(pointOfContactGlobalID(pocConn.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}

func (b *EntBackend) PointOfContact(ctx context.Context, filter *model.PointOfContactSpec) ([]*model.PointOfContact, error) {
	if filter == nil {
		filter = &model.PointOfContactSpec{}
	}
	pocQuery := b.client.PointOfContact.Query().
		Where(pointOfContactPredicate(filter))

	records, err := getPointOfContactObject(pocQuery).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed PointOfContact query with error: %w", err)
	}

	return collect(records, toModelPointOfContact), nil
}

// getPointOfContactObject is used recreate the PointOfContact object be eager loading the edges
func getPointOfContactObject(q *ent.PointOfContactQuery) *ent.PointOfContactQuery {
	return q.
		WithSource(withSourceNameTreeQuery()).
		WithArtifact().
		WithPackageVersion(withPackageVersionTree()).
		WithAllVersions(withPackageNameTree())
}

func (b *EntBackend) IngestPointOfContact(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, pointOfContact model.PointOfContactInputSpec) (string, error) {
	recordID, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertPointOfContact(ctx, ent.TxFromContext(ctx), subject, pkgMatchType, pointOfContact)
	})
	if txErr != nil {
		return "", fmt.Errorf("failed to execute IngestPointOfContact :: %s", txErr)
	}

	return pointOfContactGlobalID(*recordID), nil
}

func (b *EntBackend) IngestPointOfContacts(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, pointOfContactList []*model.PointOfContactInputSpec) ([]string, error) {
	funcName := "IngestPointOfContacts"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkPointOfContact(ctx, client, subjects, pkgMatchType, pointOfContactList)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return bulkPointOfContactGlobalID(*ids), nil
}

func pointOfContactPredicate(filter *model.PointOfContactSpec) predicate.PointOfContact {
	predicates := []predicate.PointOfContact{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Email, pointofcontact.EmailEqualFold),
		optionalPredicate(filter.Info, pointofcontact.InfoEqualFold),
		optionalPredicate(filter.Since, pointofcontact.SinceGTE),
		optionalPredicate(filter.Justification, pointofcontact.JustificationEQ),
		optionalPredicate(filter.Origin, pointofcontact.OriginEQ),
		optionalPredicate(filter.Collector, pointofcontact.CollectorEQ),
		optionalPredicate(filter.DocumentRef, pointofcontact.DocumentRefEQ),
	}

	if filter.Subject != nil {
		switch {
		case filter.Subject.Artifact != nil:
			if filter.Subject.Artifact.ID != nil {
				predicates = append(predicates,
					optionalPredicate(filter.Subject.Artifact.ID, artifactIDEQ))
			} else {
				predicates = append(predicates,
					pointofcontact.HasArtifactWith(artifactQueryPredicates(filter.Subject.Artifact)))
			}
		case filter.Subject.Package != nil:
			if filter.Subject.Package.ID != nil {
				predicates = append(predicates, optionalPredicate(filter.Subject.Package.ID, packageVersionOrNameIDEQ))
			} else {
				predicates = append(predicates, pointofcontact.Or(
					pointofcontact.HasAllVersionsWith(packageNameQuery(pkgNameQueryFromPkgSpec(filter.Subject.Package))),
					pointofcontact.HasPackageVersionWith(packageVersionQuery(filter.Subject.Package)),
				))
			}
		case filter.Subject.Source != nil:
			if filter.Subject.Source.ID != nil {
				predicates = append(predicates,
					optionalPredicate(filter.Subject.Source.ID, sourceIDEQ))
			} else {
				predicates = append(predicates,
					pointofcontact.HasSourceWith(sourceQuery(filter.Subject.Source)))
			}
		}
	}
	return pointofcontact.And(predicates...)
}

func pocConflictColumns() []string {
	return []string{
		pointofcontact.FieldEmail,
		pointofcontact.FieldInfo,
		pointofcontact.FieldSince,
		pointofcontact.FieldJustification,
		pointofcontact.FieldOrigin,
		pointofcontact.FieldCollector,
		pointofcontact.FieldDocumentRef,
	}
}

func upsertBulkPointOfContact(ctx context.Context, tx *ent.Tx, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, pointOfContactList []*model.PointOfContactInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := pocConflictColumns()
	var conflictWhere *sql.Predicate

	switch {
	case len(subjects.Artifacts) > 0:
		conflictColumns = append(conflictColumns, pointofcontact.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(pointofcontact.FieldArtifactID),
			sql.IsNull(pointofcontact.FieldPackageNameID),
			sql.IsNull(pointofcontact.FieldPackageVersionID),
			sql.IsNull(pointofcontact.FieldSourceID),
		)
	case len(subjects.Packages) > 0:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			conflictColumns = append(conflictColumns, pointofcontact.FieldPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(pointofcontact.FieldArtifactID),
				sql.NotNull(pointofcontact.FieldPackageVersionID),
				sql.IsNull(pointofcontact.FieldPackageNameID),
				sql.IsNull(pointofcontact.FieldSourceID),
			)
		} else {
			conflictColumns = append(conflictColumns, pointofcontact.FieldPackageNameID)
			conflictWhere = sql.And(
				sql.IsNull(pointofcontact.FieldArtifactID),
				sql.IsNull(pointofcontact.FieldPackageVersionID),
				sql.NotNull(pointofcontact.FieldPackageNameID),
				sql.IsNull(pointofcontact.FieldSourceID),
			)
		}
	case len(subjects.Sources) > 0:
		conflictColumns = append(conflictColumns, pointofcontact.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(pointofcontact.FieldArtifactID),
			sql.IsNull(pointofcontact.FieldPackageVersionID),
			sql.IsNull(pointofcontact.FieldPackageNameID),
			sql.NotNull(pointofcontact.FieldSourceID),
		)
	}

	batches := chunk(pointOfContactList, MaxBatchSize)

	index := 0
	for _, pocs := range batches {
		creates := make([]*ent.PointOfContactCreate, len(pocs))
		for i, poc := range pocs {
			poc := poc
			var err error

			switch {
			case len(subjects.Artifacts) > 0:
				creates[i], err = generatePointOfContactCreate(ctx, tx, nil, nil, subjects.Artifacts[index], pkgMatchType, poc)
				if err != nil {
					return nil, gqlerror.Errorf("generatePointOfContactCreate :: %s", err)
				}
			case len(subjects.Packages) > 0:
				creates[i], err = generatePointOfContactCreate(ctx, tx, subjects.Packages[index], nil, nil, pkgMatchType, poc)
				if err != nil {
					return nil, gqlerror.Errorf("generatePointOfContactCreate :: %s", err)
				}
			case len(subjects.Sources) > 0:
				creates[i], err = generatePointOfContactCreate(ctx, tx, nil, subjects.Sources[index], nil, pkgMatchType, poc)
				if err != nil {
					return nil, gqlerror.Errorf("generatePointOfContactCreate :: %s", err)
				}
			}
			index++
		}

		err := tx.PointOfContact.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert PointOfContact node")
		}
	}

	return &ids, nil
}

func generatePointOfContactCreate(ctx context.Context, tx *ent.Tx, pkg *model.IDorPkgInput, src *model.IDorSourceInput, art *model.IDorArtifactInput, pkgMatchType *model.MatchFlags,
	poc *model.PointOfContactInputSpec) (*ent.PointOfContactCreate, error) {

	pocCreate := tx.PointOfContact.Create()

	pocCreate.
		SetEmail(poc.Email).
		SetInfo(poc.Info).
		SetSince(poc.Since.UTC()).
		SetJustification(poc.Justification).
		SetOrigin(poc.Origin).
		SetCollector(poc.Collector).
		SetDocumentRef(poc.DocumentRef)

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
		pocCreate.SetArtifactID(artID)
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
			pocCreate.SetPackageVersionID(pkgVersionID)
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
			pocCreate.SetAllVersionsID(pkgNameID)
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
		pocCreate.SetSourceID(sourceID)
	}
	return pocCreate, nil
}

func upsertPointOfContact(ctx context.Context, tx *ent.Tx, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec model.PointOfContactInputSpec) (*string, error) {

	conflictColumns := pocConflictColumns()

	var conflictWhere *sql.Predicate

	switch {
	case subject.Artifact != nil:
		conflictColumns = append(conflictColumns, pointofcontact.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(pointofcontact.FieldArtifactID),
			sql.IsNull(pointofcontact.FieldPackageNameID),
			sql.IsNull(pointofcontact.FieldPackageVersionID),
			sql.IsNull(pointofcontact.FieldSourceID),
		)

	case subject.Package != nil:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			conflictColumns = append(conflictColumns, pointofcontact.FieldPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(pointofcontact.FieldArtifactID),
				sql.NotNull(pointofcontact.FieldPackageVersionID),
				sql.IsNull(pointofcontact.FieldPackageNameID),
				sql.IsNull(pointofcontact.FieldSourceID),
			)
		} else {
			conflictColumns = append(conflictColumns, pointofcontact.FieldPackageNameID)
			conflictWhere = sql.And(
				sql.IsNull(pointofcontact.FieldArtifactID),
				sql.IsNull(pointofcontact.FieldPackageVersionID),
				sql.NotNull(pointofcontact.FieldPackageNameID),
				sql.IsNull(pointofcontact.FieldSourceID),
			)
		}
	case subject.Source != nil:
		conflictColumns = append(conflictColumns, pointofcontact.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(pointofcontact.FieldArtifactID),
			sql.IsNull(pointofcontact.FieldPackageVersionID),
			sql.IsNull(pointofcontact.FieldPackageNameID),
			sql.NotNull(pointofcontact.FieldSourceID),
		)
	}

	insert, err := generatePointOfContactCreate(ctx, tx, subject.Package, subject.Source, subject.Artifact, pkgMatchType, &spec)
	if err != nil {
		return nil, gqlerror.Errorf("generatePointOfContactCreate :: %s", err)
	}
	if id, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
		sql.ConflictWhere(conflictWhere),
	).
		Ignore().
		ID(ctx); err != nil {

		return nil, errors.Wrap(err, "upsert PointOfContact node")

	} else {
		return ptrfrom.String(id.String()), nil
	}
}

func toModelPointOfContact(v *ent.PointOfContact) *model.PointOfContact {
	var sub model.PackageSourceOrArtifact

	switch {
	case v.Edges.Source != nil:
		sub = toModelSource(v.Edges.Source)
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

	return &model.PointOfContact{
		ID:            pointOfContactGlobalID(v.ID.String()),
		Subject:       sub,
		Email:         v.Email,
		Info:          v.Info,
		Since:         v.Since,
		Justification: v.Justification,
		Origin:        v.Origin,
		Collector:     v.Collector,
		DocumentRef:   v.DocumentRef,
	}
}

func (b *EntBackend) pointOfContactNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.PointOfContact.Query().
		Where(pointOfContactPredicate(&model.PointOfContactSpec{ID: &nodeID}))

	if allowedEdges[model.EdgePointOfContactPackage] {
		query.
			WithPackageVersion(withPackageVersionTree()).
			WithAllVersions()
	}
	if allowedEdges[model.EdgePointOfContactArtifact] {
		query.
			WithArtifact()
	}
	if allowedEdges[model.EdgePointOfContactSource] {
		query.
			WithSource()
	}

	pocs, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for point of contact with node ID: %s with error: %w", nodeID, err)
	}

	for _, poc := range pocs {
		if poc.Edges.PackageVersion != nil {
			out = append(out, toModelPackage(backReferencePackageVersion(poc.Edges.PackageVersion)))
		}
		if poc.Edges.AllVersions != nil {
			out = append(out, toModelPackage(poc.Edges.AllVersions))
		}
		if poc.Edges.Artifact != nil {
			out = append(out, toModelArtifact(poc.Edges.Artifact))
		}
		if poc.Edges.Source != nil {
			out = append(out, toModelSource(poc.Edges.Source))
		}
	}

	return out, nil
}
