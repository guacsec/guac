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
	"bytes"
	"context"
	"crypto/sha1"
	"fmt"
	"sort"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pkgequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) PkgEqual(ctx context.Context, spec *model.PkgEqualSpec) ([]*model.PkgEqual, error) {
	records, err := b.client.PkgEqual.Query().
		Where(pkgEqualQueryPredicates(spec)).
		WithPackages(withPackageVersionTree()).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelPkgEqual), nil
}

func (b *EntBackend) IngestPkgEqual(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec) (*model.PkgEqual, error) {
	record, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.PkgEqual, error) {
		return upsertPackageEqual(ctx, ent.TxFromContext(ctx), pkg, depPkg, pkgEqual)
	})
	if err != nil {
		return nil, err
	}

	return toModelPkgEqual(record), nil
}

func (b *EntBackend) IngestPkgEquals(ctx context.Context, pkgs []*model.PkgInputSpec, otherPackages []*model.PkgInputSpec, pkgEquals []*model.PkgEqualInputSpec) ([]string, error) {
	var ids []string
	for i, pkgEqual := range pkgEquals {
		pe, err := b.IngestPkgEqual(ctx, *pkgs[i], *otherPackages[i], *pkgEqual)
		if err != nil {
			return nil, gqlerror.Errorf("IngestPkgEquals failed with err: %v", err)
		}
		ids = append(ids, pe.ID)
	}
	return ids, nil
}

func upsertPackageEqual(ctx context.Context, client *ent.Tx, pkgA model.PkgInputSpec, pkgB model.PkgInputSpec, spec model.PkgEqualInputSpec) (*ent.PkgEqual, error) {
	pkgARecord, err := client.PackageVersion.Query().Where(packageVersionInputQuery(pkgA)).Only(ctx)
	if err != nil {
		return nil, err
	}
	pkgBRecord, err := client.PackageVersion.Query().Where(packageVersionInputQuery(pkgB)).Only(ctx)
	if err != nil {
		return nil, err
	}

	if pkgARecord.ID == pkgBRecord.ID {
		return nil, fmt.Errorf("cannot create a PkgEqual between the same package")
	}

	sortedPackages := []*ent.PackageVersion{pkgARecord, pkgBRecord}
	sort.Slice(sortedPackages, func(i, j int) bool {
		return sortedPackages[i].ID < sortedPackages[j].ID
	})

	id, err := client.PkgEqual.Create().
		// SetPackage(sortedPackages[0]).
		// SetDependantPackage(sortedPackages[1]).
		AddPackages(sortedPackages...).
		SetPackagesHash(hashPackages(sortedPackages)).
		SetCollector(spec.Collector).
		SetJustification(spec.Justification).
		SetOrigin(spec.Origin).
		OnConflict(
			sql.ConflictColumns(
				// pkgequal.FieldPackageVersionID,
				// pkgequal.FieldEqualPackageID,

				pkgequal.FieldPackagesHash,
				pkgequal.FieldOrigin,
				pkgequal.FieldCollector,
				pkgequal.FieldJustification,
			),
		).
		Ignore().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	pkgEqual, err := client.PkgEqual.Query().Where(
		pkgequal.ID(id),
		// pkgequal.HasPackageWith(packageversion.ID(pkgARecord.ID)),
		// pkgequal.HasDependantPackageWith(packageversion.ID(pkgBRecord.ID)),
	).
		WithPackages(withPackageVersionTree()).
		// WithDependantPackage(withPackageVersionTree()).WithPackage(withPackageVersionTree()).
		Only(ctx)
	if err != nil {
		return nil, err
	}

	return pkgEqual, nil
}

func pkgEqualQueryPredicates(spec *model.PkgEqualSpec) predicate.PkgEqual {
	if spec == nil {
		return NoOpSelector()
	}
	predicates := []predicate.PkgEqual{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.Origin, pkgequal.OriginEQ),
		optionalPredicate(spec.Collector, pkgequal.CollectorEQ),
		optionalPredicate(spec.Justification, pkgequal.JustificationEQ),
	}

	for _, pkg := range spec.Packages {
		predicates = append(predicates, pkgequal.HasPackagesWith(packageVersionQuery(pkg)))
	}

	return pkgequal.And(predicates...)
}

//func pkgEqualInputQueryPredicates(spec model.PkgEqualInputSpec) predicate.PkgEqual {
//	return pkgequal.And(
//		pkgequal.OriginEQ(spec.Origin),
//		pkgequal.CollectorEQ(spec.Collector),
//		pkgequal.JustificationEQ(spec.Justification),
//	)
//}

func toModelPkgEqual(record *ent.PkgEqual) *model.PkgEqual {
	packages := collect(record.Edges.Packages, backReferencePackageVersion)

	// packages := []*ent.PackageVersion{
	// 	record.Edges.Package,
	// 	record.Edges.DependantPackage,
	// }

	return &model.PkgEqual{
		ID:            nodeID(record.ID),
		Origin:        record.Origin,
		Collector:     record.Collector,
		Justification: record.Justification,
		Packages:      collect(packages, toModelPackage),
		// Packages: collect(packages, func(record *ent.PackageVersion) *model.Package {
		// 	return toModelPackage(backReferencePackageVersion(record))
		// }),
	}
}

// hashPackages is used to create a unique key for the M2M edge between PkgEquals <-M2M-> PackageVersions
func hashPackages(slc ent.PackageVersions) string {
	pkgs := slc
	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].ID < pkgs[j].ID })

	for _, v := range pkgs {
		content.WriteString(fmt.Sprintf("%d", v.ID))
	}

	hash.Write(content.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
}
