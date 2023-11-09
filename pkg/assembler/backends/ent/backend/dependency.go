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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
)

func (b *EntBackend) IsDependency(ctx context.Context, spec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	funcName := "IsDependency"
	if spec == nil {
		return nil, nil
	}

	query := b.client.Dependency.Query().Order(ent.Asc(dependency.FieldID)).Limit(MaxPageSize)
	query.Where(
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.VersionRange, dependency.VersionRange),
		optionalPredicate(spec.Justification, dependency.Justification),
		optionalPredicate(spec.Origin, dependency.Origin),
		optionalPredicate(spec.Collector, dependency.Collector),
	)
	if spec.DependentPackage != nil {
		if spec.DependentPackage.Version == nil {
			query.Where(
				dependency.Or(
					dependency.HasDependentPackageNameWith(packageNameQuery(spec.DependentPackage)),
					dependency.HasDependentPackageVersionWith(packageVersionQuery(spec.DependentPackage)),
				),
			)
		} else {
			query.Where(dependency.HasDependentPackageVersionWith(packageVersionQuery(spec.DependentPackage)))
		}
	}
	if spec.Package != nil {
		query.Where(dependency.HasPackageWith(packageVersionQuery(spec.Package)))
	}

	if spec.DependencyType != nil {
		query.Where(dependency.DependencyTypeEQ(dependencyTypeToEnum(*spec.DependencyType)))
	}

	deps, err := query.
		WithPackage(withPackageVersionTree()).
		WithDependentPackageName(withPackageNameTree()).
		WithDependentPackageVersion(withPackageVersionTree()).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, funcName)
	}

	return collect(deps, toModelIsDependencyWithBackrefs), nil
}

func (b *EntBackend) IngestDependencyIDs(ctx context.Context, pkgs []*model.PkgInputSpec, depPkgs []*model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependencies []*model.IsDependencyInputSpec) ([]string, error) {

	var ids []string
	for i := range dependencies {
		isDependency, err := b.IngestDependencyID(ctx, *pkgs[i], *depPkgs[i], depPkgMatchType, *dependencies[i])
		if err != nil {
			return nil, Errorf("IngestDependency failed with err: %v", err)
		}
		ids = append(ids, isDependency)
	}
	return ids, nil
}

func (b *EntBackend) IngestDependencyID(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, depPkgMatchType model.MatchFlags, dep model.IsDependencyInputSpec) (string, error) {
	funcName := "IngestDependency"

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.TxFromContext(ctx)
		p, err := getPkgVersion(ctx, client.Client(), pkg)
		if err != nil {
			return nil, err
		}
		query := client.Dependency.Create().
			SetPackage(p).
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
		var dpn *ent.PackageName
		var dpv *ent.PackageVersion
		if depPkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
			dpn, err = getPkgName(ctx, client.Client(), depPkg)
			if err != nil {
				return nil, err
			}
			query.SetDependentPackageName(dpn)
			conflictColumns = append(conflictColumns, dependency.FieldDependentPackageNameID)
			conflictWhere = sql.And(
				sql.NotNull(dependency.FieldDependentPackageNameID),
				sql.IsNull(dependency.FieldDependentPackageVersionID),
			)
		} else {
			dpv, err = getPkgVersion(ctx, client.Client(), depPkg)
			if err != nil {
				return nil, err
			}
			query.SetDependentPackageVersion(dpv)
			conflictColumns = append(conflictColumns, dependency.FieldDependentPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(dependency.FieldDependentPackageNameID),
				sql.NotNull(dependency.FieldDependentPackageVersionID),
			)
		}

		id, err := query.
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			ID(ctx)

		if err != nil {
			if err != stdsql.ErrNoRows {
				return nil, errors.Wrap(err, "Ingest dependency ID")
			}
			predicates := []predicate.Dependency{
				dependency.PackageIDEQ(p.ID),
				dependency.VersionRangeEQ(dep.VersionRange),
				dependency.DependencyTypeEQ(dependencyTypeToEnum(dep.DependencyType)),
				dependency.JustificationEQ(dep.Justification),
				dependency.OriginEQ(dep.Origin),
				dependency.CollectorEQ(dep.Collector),
			}

			if depPkgMatchType.Pkg == model.PkgMatchTypeAllVersions {

				predicates = append(predicates, dependency.DependentPackageNameIDEQ(dpn.ID))

			} else {

				predicates = append(predicates, dependency.DependentPackageVersionIDEQ(dpv.ID))
			}

			id, err = client.Dependency.Query().
				Where(predicates...).
				OnlyID(ctx)

			if err != nil {
				return nil, errors.Wrap(err, "Ingest dependency ID")
			}
		}
		return &id, nil
	})
	if err != nil {
		return "", errors.Wrap(err, funcName)
	}

	return strconv.Itoa(*recordID), nil
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
