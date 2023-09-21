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

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
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
	if spec.DependencyPackage != nil {
		if spec.DependencyPackage.Version == nil {
			query.Where(
				dependency.Or(
					dependency.HasDependentPackageNameWith(packageNameQuery(spec.DependencyPackage)),
					dependency.HasDependentPackageVersionWith(packageVersionQuery(spec.DependencyPackage)),
				),
			)
		} else {
			query.Where(dependency.HasDependentPackageVersionWith(packageVersionQuery(spec.DependencyPackage)))
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

func (b *EntBackend) IngestDependencies(ctx context.Context, pkgs []*model.PkgInputSpec, depPkgs []*model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependencies []*model.IsDependencyInputSpec) ([]*model.IsDependency, error) {
	// TODO: This looks like a good candidate for using BulkCreate()

	var modelIsDependencies []*model.IsDependency
	for i := range dependencies {
		isDependency, err := b.IngestDependency(ctx, *pkgs[i], *depPkgs[i], depPkgMatchType, *dependencies[i])
		if err != nil {
			return nil, Errorf("IngestDependency failed with err: %v", err)
		}
		modelIsDependencies = append(modelIsDependencies, isDependency)
	}
	return modelIsDependencies, nil
}

func (b *EntBackend) IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, depPkgMatchType model.MatchFlags, dep model.IsDependencyInputSpec) (*model.IsDependency, error) {
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

		if depPkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
			dpn, err := getPkgName(ctx, client.Client(), depPkg)
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
			dpv, err := getPkgVersion(ctx, client.Client(), depPkg)
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
			Ignore().
			ID(ctx)
		if err != nil {
			return nil, err
		}
		return &id, nil
	})
	if err != nil {
		return nil, errors.Wrap(err, funcName)
	}

	return &model.IsDependency{ID: nodeID(*recordID)}, nil
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
