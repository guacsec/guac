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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func dependencyGlobalID(id string) string {
	return toGlobalID(dependency.Table, id)
}

func bulkDependencyGlobalID(ids []string) []string {
	return toGlobalIDs(dependency.Table, ids)
}

func (b *EntBackend) IsDependencyList(ctx context.Context, spec model.IsDependencySpec, after *string, first *int) (*model.IsDependencyConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		if globalID.nodeType != dependency.Table {
			return nil, fmt.Errorf("after cursor is not type dependency but type: %s", globalID.nodeType)
		}
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse global ID with error: %w", err)
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	isDepQuery := b.client.Dependency.Query().
		Where(isDependencyQuery(&spec))

	depConn, err := getIsDepObject(isDepQuery).
		Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed isDependency query with error: %w", err)
	}

	// if not found return nil
	if depConn == nil {
		return nil, nil
	}

	var edges []*model.IsDependencyEdge
	for _, edge := range depConn.Edges {
		edges = append(edges, &model.IsDependencyEdge{
			Cursor: dependencyGlobalID(edge.Cursor.ID.String()),
			Node:   toModelIsDependencyWithBackrefs(edge.Node),
		})
	}

	if depConn.PageInfo.StartCursor != nil {
		return &model.IsDependencyConnection{
			TotalCount: depConn.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: depConn.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(dependencyGlobalID(depConn.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(dependencyGlobalID(depConn.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}

func (b *EntBackend) IsDependency(ctx context.Context, spec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	if spec == nil {
		spec = &model.IsDependencySpec{}
	}

	isDepQuery := b.client.Dependency.Query().
		Where(isDependencyQuery(spec))

	deps, err := getIsDepObject(isDepQuery).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed isDependency query with error: %w", err)
	}

	return collect(deps, toModelIsDependencyWithBackrefs), nil
}

// getIsDepObject is used recreate the isDependency object be eager loading the edges
func getIsDepObject(q *ent.DependencyQuery) *ent.DependencyQuery {
	return q.
		WithPackage(withPackageVersionTree()).
		WithDependentPackageVersion(withPackageVersionTree()).
		Order(ent.Asc(dependency.FieldID))
}

// deleteIsDependency is called by hasSBOM to delete the isDependency nodes that are part of the hasSBOM
func (b *EntBackend) deleteIsDependency(ctx context.Context, hasSBOMID string) error {
	_, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)

		if _, err := tx.Dependency.Delete().Where(dependency.HasIncludedInSbomsWith([]predicate.BillOfMaterials{
			optionalPredicate(&hasSBOMID, IDEQ)}...)).Exec(ctx); err != nil {
			return nil, errors.Wrap(err, "failed to delete isDependency with error")
		}
		return nil, nil
	})
	if txErr != nil {
		return txErr
	}
	return nil
}

func (b *EntBackend) IngestDependencies(ctx context.Context, pkgs []*model.IDorPkgInput, depPkgs []*model.IDorPkgInput, dependencies []*model.IsDependencyInputSpec) ([]string, error) {
	funcName := "IngestDependencies"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkDependencies(ctx, client, pkgs, depPkgs, dependencies)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return bulkDependencyGlobalID(*ids), nil
}

func dependencyConflictColumns() []string {
	return []string{
		dependency.FieldPackageID,
		dependency.FieldDependentPackageVersionID,
		dependency.FieldDependencyType,
		dependency.FieldJustification,
		dependency.FieldOrigin,
		dependency.FieldCollector,
		dependency.FieldDocumentRef,
	}
}

func upsertBulkDependencies(ctx context.Context, tx *ent.Tx, pkgs []*model.IDorPkgInput, depPkgs []*model.IDorPkgInput, dependencies []*model.IsDependencyInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := dependencyConflictColumns()

	batches := chunk(dependencies, MaxBatchSize)

	index := 0
	for _, deps := range batches {
		creates := make([]*ent.DependencyCreate, len(deps))
		for i, dep := range deps {
			dep := dep
			var err error
			var isDependencyID *uuid.UUID
			creates[i], isDependencyID, err = generateDependencyCreate(ctx, tx, pkgs[index], depPkgs[index], dep)
			if err != nil {
				return nil, gqlerror.Errorf("generateDependencyCreate :: %s", err)
			}
			ids = append(ids, isDependencyID.String())

			index++
		}

		err := tx.Dependency.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert dependency node")
		}
	}

	return &ids, nil
}

func generateDependencyCreate(ctx context.Context, tx *ent.Tx, pkg *model.IDorPkgInput, depPkg *model.IDorPkgInput, dep *model.IsDependencyInputSpec) (*ent.DependencyCreate, *uuid.UUID, error) {

	dependencyCreate := tx.Dependency.Create()

	if pkg == nil {
		return nil, nil, Errorf("%v :: %s", "generateDependencyCreate", "package cannot be nil")
	}
	if depPkg == nil {
		return nil, nil, Errorf("%v :: %s", "generateDependencyCreate", "dependency package cannot be nil")
	}

	var pkgVersionID uuid.UUID
	if pkg.PackageVersionID != nil {
		var err error
		pkgVersionGlobalID := fromGlobalID(*pkg.PackageVersionID)
		pkgVersionID, err = uuid.Parse(pkgVersionGlobalID.id)
		if err != nil {
			return nil, nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
		}
	} else {
		pv, err := getPkgVersion(ctx, tx.Client(), *pkg.PackageInput)
		if err != nil {
			return nil, nil, fmt.Errorf("getPkgVersion :: %w", err)
		}
		pkgVersionID = pv.ID
	}

	dependencyCreate.
		SetPackageID(pkgVersionID).
		SetDependencyType(dependencyTypeToEnum(dep.DependencyType)).
		SetJustification(dep.Justification).
		SetOrigin(dep.Origin).
		SetCollector(dep.Collector).
		SetDocumentRef(dep.DocumentRef)

	var depPkgVersionID uuid.UUID
	if depPkg.PackageVersionID != nil {
		var err error
		pkgVersionGlobalID := fromGlobalID(*depPkg.PackageVersionID)
		depPkgVersionID, err = uuid.Parse(pkgVersionGlobalID.id)
		if err != nil {
			return nil, nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
		}
	} else {
		pv, err := getPkgVersion(ctx, tx.Client(), *depPkg.PackageInput)
		if err != nil {
			return nil, nil, fmt.Errorf("getPkgVersion :: %w", err)
		}
		depPkgVersionID = pv.ID
	}
	dependencyCreate.SetDependentPackageVersionID(depPkgVersionID)

	isDependencyID, err := guacDependencyKey(ptrfrom.String(pkgVersionID.String()), ptrfrom.String(depPkgVersionID.String()), *dep)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create isDependency uuid with error: %w", err)
	}
	dependencyCreate.SetID(*isDependencyID)

	return dependencyCreate, isDependencyID, nil
}

func (b *EntBackend) IngestDependency(ctx context.Context, pkg model.IDorPkgInput, depPkg model.IDorPkgInput, dep model.IsDependencyInputSpec) (string, error) {
	funcName := "IngestDependency"

	recordID, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)

		conflictColumns := dependencyConflictColumns()

		insert, _, err := generateDependencyCreate(ctx, tx, &pkg, &depPkg, &dep)
		if err != nil {
			return nil, gqlerror.Errorf("generateDependencyCreate :: %s", err)
		}

		if id, err := insert.
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
			).
			Ignore().
			ID(ctx); err != nil {
			return nil, errors.Wrap(err, "upsert isDependency statement node")
		} else {
			return ptrfrom.String(id.String()), nil
		}
	})
	if txErr != nil {
		return "", errors.Wrap(txErr, funcName)
	}

	return dependencyGlobalID(*recordID), nil
}

func dependencyTypeToEnum(t model.DependencyType) dependency.DependencyType {
	switch t {
	case model.DependencyTypeDirect:
		return dependency.DependencyTypeDIRECT
	case model.DependencyTypeIndirect:
		return dependency.DependencyTypeINDIRECT
	default:
		return dependency.DependencyTypeUNKNOWN
	}
}

func isDependencyQuery(filter *model.IsDependencySpec) predicate.Dependency {
	if filter == nil {
		return NoOpSelector()
	}

	predicates := []predicate.Dependency{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Justification, dependency.Justification),
		optionalPredicate(filter.Origin, dependency.Origin),
		optionalPredicate(filter.Collector, dependency.Collector),
		optionalPredicate(filter.DocumentRef, dependency.DocumentRef),
	}
	if filter.DependencyPackage != nil {
		if filter.DependencyPackage.ID != nil {
			predicates = append(predicates, optionalPredicate(filter.DependencyPackage.ID, dependencyPackageIDEQ))
		} else {
			predicates = append(predicates,
				dependency.HasDependentPackageVersionWith(packageVersionQuery(filter.DependencyPackage)))
		}
	}
	if filter.Package != nil {
		if filter.Package.ID != nil {
			predicates = append(predicates, optionalPredicate(filter.Package.ID, packageIDEQ))
		} else {
			predicates = append(predicates,
				dependency.HasPackageWith(packageVersionQuery(filter.Package)))
		}
	}

	if filter.DependencyType != nil {
		predicates = append(predicates, dependency.DependencyTypeEQ(dependencyTypeToEnum(*filter.DependencyType)))
	}

	return dependency.And(predicates...)
}

func canonicalDependencyString(dep model.IsDependencyInputSpec) string {
	return fmt.Sprintf("%s::%s::%s::%s:%s", dep.DependencyType.String(), dep.Justification, dep.Origin, dep.Collector, dep.DocumentRef)
}

func guacDependencyKey(pkgVersionID *string, depPkgVersionID *string, dep model.IsDependencyInputSpec) (*uuid.UUID, error) {
	if depPkgVersionID == nil {
		return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
	}

	if pkgVersionID == nil {
		return nil, fmt.Errorf("need to specify package ID for isDependency")
	}

	depIDString := fmt.Sprintf("%s::%s::%s?", *pkgVersionID, *depPkgVersionID, canonicalDependencyString(dep))

	depID := generateUUIDKey([]byte(depIDString))
	return &depID, nil
}

func (b *EntBackend) isDependencyNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.Dependency.Query().
		Where(isDependencyQuery(&model.IsDependencySpec{ID: &nodeID}))

	if allowedEdges[model.EdgeIsDependencyPackage] {
		query.
			WithPackage(withPackageVersionTree()).
			WithDependentPackageVersion(withPackageVersionTree())
	}

	deps, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for isDep with node ID: %s with error: %w", nodeID, err)
	}
	for _, foundDep := range deps {
		if foundDep.Edges.Package != nil {
			out = append(out, toModelPackage(backReferencePackageVersion(foundDep.Edges.Package)))
		}
		if foundDep.Edges.DependentPackageVersion != nil {
			out = append(out, toModelPackage(backReferencePackageVersion(foundDep.Edges.DependentPackageVersion)))
		}
	}

	return out, nil
}
