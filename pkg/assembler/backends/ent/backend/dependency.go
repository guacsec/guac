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

func (b *EntBackend) IsDependency(ctx context.Context, spec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	funcName := "IsDependency"
	if spec == nil {
		return nil, nil
	}

	deps, err := b.client.Dependency.Query().
		Where(isDependencyQuery(spec)).
		WithPackage(withPackageVersionTree()).
		WithDependentPackageName(withPackageNameTree()).
		WithDependentPackageVersion(withPackageVersionTree()).
		Order(ent.Asc(dependency.FieldID)).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, funcName)
	}

	return collect(deps, toModelIsDependencyWithBackrefs), nil
}

func (b *EntBackend) IngestDependencies(ctx context.Context, pkgs []*model.IDorPkgInput, depPkgs []*model.IDorPkgInput, depPkgMatchType model.MatchFlags, dependencies []*model.IsDependencyInputSpec) ([]string, error) {
	funcName := "IngestCertifyVulns"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkDependencies(ctx, client, pkgs, depPkgs, depPkgMatchType, dependencies)
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

func upsertBulkDependencies(ctx context.Context, client *ent.Tx, pkgs []*model.IDorPkgInput, depPkgs []*model.IDorPkgInput, depPkgMatchType model.MatchFlags, dependencies []*model.IsDependencyInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		dependency.FieldPackageID,
		dependency.FieldVersionRange,
		dependency.FieldDependencyType,
		dependency.FieldJustification,
		dependency.FieldOrigin,
		dependency.FieldCollector,
	}

	var conflictWhere *sql.Predicate

	if depPkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
		conflictColumns = append(conflictColumns, dependency.FieldDependentPackageNameID)
		conflictWhere = sql.And(
			sql.NotNull(dependency.FieldDependentPackageNameID),
			sql.IsNull(dependency.FieldDependentPackageVersionID),
		)
	} else {
		conflictColumns = append(conflictColumns, dependency.FieldDependentPackageVersionID)
		conflictWhere = sql.And(
			sql.IsNull(dependency.FieldDependentPackageNameID),
			sql.NotNull(dependency.FieldDependentPackageVersionID),
		)
	}

	batches := chunk(dependencies, 100)

	index := 0
	for _, deps := range batches {
		creates := make([]*ent.DependencyCreate, len(deps))
		for i, dep := range deps {
			creates[i] = client.Dependency.Create().
				SetVersionRange(dep.VersionRange).
				SetDependencyType(dependencyTypeToEnum(dep.DependencyType)).
				SetJustification(dep.Justification).
				SetOrigin(dep.Origin).
				SetCollector(dep.Collector)

			if pkgs[index].PackageVersionID == nil {
				return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
			}
			pkgVersionID, err := uuid.Parse(*pkgs[index].PackageVersionID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from PackageVersionID failed with error: %w", err)
			}
			creates[i].SetPackageID(pkgVersionID)

			if depPkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
				if depPkgs[index].PackageVersionID == nil {
					return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
				}
				pkgVersionID, err := uuid.Parse(*depPkgs[index].PackageVersionID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from PackageVersionID failed with error: %w", err)
				}
				creates[i].SetDependentPackageNameID(pkgVersionID)

			} else {
				if depPkgs[index].PackageNameID == nil {
					return nil, fmt.Errorf("packageName ID not specified in IDorPkgInput")
				}
				pkgNameID, err := uuid.Parse(*depPkgs[index].PackageNameID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from PackageNameID failed with error: %w", err)
				}
				creates[i].SetDependentPackageVersionID(pkgNameID)
			}
			index++
		}

		err := client.Dependency.CreateBulk(creates...).
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

func (b *EntBackend) IngestDependency(ctx context.Context, pkg model.IDorPkgInput, depPkg model.IDorPkgInput, depPkgMatchType model.MatchFlags, dep model.IsDependencyInputSpec) (string, error) {
	funcName := "IngestDependency"

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		client := ent.TxFromContext(ctx)
		if pkg.PackageVersionID == nil {
			return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
		}
		pkgVersionID, err := uuid.Parse(*pkg.PackageVersionID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
		}
		query := client.Dependency.Create().
			SetPackageID(pkgVersionID).
			SetVersionRange(dep.VersionRange).
			SetDependencyType(dependencyTypeToEnum(dep.DependencyType)).
			SetJustification(dep.Justification).
			SetOrigin(dep.Origin).
			SetCollector(dep.Collector)

		conflictColumns := []string{
			dependency.FieldPackageID,
			dependency.FieldVersionRange,
			dependency.FieldDependencyType,
			dependency.FieldJustification,
			dependency.FieldOrigin,
			dependency.FieldCollector,
		}

		var conflictWhere *sql.Predicate

		if depPkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
			if depPkg.PackageNameID == nil {
				return nil, fmt.Errorf("packageName ID not specified in IDorPkgInput")
			}
			depPkgNameID, err := uuid.Parse(*depPkg.PackageNameID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from PackageNameID failed with error: %w", err)
			}
			query.SetDependentPackageNameID(depPkgNameID)
			conflictColumns = append(conflictColumns, dependency.FieldDependentPackageNameID)
			conflictWhere = sql.And(
				sql.NotNull(dependency.FieldDependentPackageNameID),
				sql.IsNull(dependency.FieldDependentPackageVersionID),
			)
		} else {
			if depPkg.PackageVersionID == nil {
				return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
			}
			depPkgVersionID, err := uuid.Parse(*depPkg.PackageVersionID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
			query.SetDependentPackageVersionID(depPkgVersionID)
			conflictColumns = append(conflictColumns, dependency.FieldDependentPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(dependency.FieldDependentPackageNameID),
				sql.NotNull(dependency.FieldDependentPackageVersionID),
			)
		}

		if _, err := query.
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			Ignore().
			ID(ctx); err != nil {
			return nil, err
		}
		return ptrfrom.String(""), nil
	})
	if err != nil {
		return "", errors.Wrap(err, funcName)
	}

	return *recordID, nil
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
		optionalPredicate(filter.VersionRange, dependency.VersionRange),
		optionalPredicate(filter.Justification, dependency.Justification),
		optionalPredicate(filter.Origin, dependency.Origin),
		optionalPredicate(filter.Collector, dependency.Collector),
	}
	if filter.DependencyPackage != nil {
		if filter.DependencyPackage.Version == nil {
			predicates = append(predicates,
				dependency.Or(
					dependency.HasDependentPackageNameWith(packageNameQuery(filter.DependencyPackage)),
					dependency.HasDependentPackageVersionWith(packageVersionQuery(filter.DependencyPackage)),
				),
			)
		} else {
			predicates = append(predicates, dependency.HasDependentPackageVersionWith(packageVersionQuery(filter.DependencyPackage)))
		}
	}
	if filter.Package != nil {
		predicates = append(predicates, dependency.HasPackageWith(packageVersionQuery(filter.Package)))
	}

	if filter.DependencyType != nil {
		predicates = append(predicates, dependency.DependencyTypeEQ(dependencyTypeToEnum(*filter.DependencyType)))
	}

	return dependency.And(predicates...)
}
