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
	stdsql "database/sql"
	"fmt"
	"sort"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pkgequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
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

func (b *EntBackend) IngestPkgEqual(ctx context.Context, pkg model.IDorPkgInput, depPkg model.IDorPkgInput, pkgEqual model.PkgEqualInputSpec) (string, error) {
	id, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertPackageEqual(ctx, ent.TxFromContext(ctx), pkg, depPkg, pkgEqual)
	})
	if err != nil {
		return "", err
	}

	return *id, nil
}

func (b *EntBackend) IngestPkgEquals(ctx context.Context, pkgs []*model.IDorPkgInput, otherPackages []*model.IDorPkgInput, pkgEquals []*model.PkgEqualInputSpec) ([]string, error) {
	funcName := "IngestPkgEquals"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkPkgEquals(ctx, client, pkgs, otherPackages, pkgEquals)
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

func upsertBulkPkgEquals(ctx context.Context, client *ent.Tx, pkgs []*model.IDorPkgInput, otherPackages []*model.IDorPkgInput, pkgEquals []*model.PkgEqualInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		pkgequal.FieldPackagesHash,
		pkgequal.FieldOrigin,
		pkgequal.FieldCollector,
		pkgequal.FieldJustification,
	}

	batches := chunk(pkgEquals, 100)

	index := 0
	for _, pes := range batches {
		creates := make([]*ent.PkgEqualCreate, len(pes))
		for i, pe := range pes {

			sortedPkgs := []model.IDorPkgInput{*pkgs[index], *otherPackages[index]}

			sort.SliceStable(sortedPkgs, func(i, j int) bool { return *sortedPkgs[i].PackageVersionID < *sortedPkgs[j].PackageVersionID })

			var sortedPkgIDs []uuid.UUID
			for _, pkg := range sortedPkgs {
				if pkg.PackageVersionID == nil {
					return nil, fmt.Errorf("PackageVersionID not specified in IDorPkgInput")
				}
				pkgID, err := uuid.Parse(*pkg.PackageVersionID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from PackageVersionID failed with error: %w", err)
				}
				sortedPkgIDs = append(sortedPkgIDs, pkgID)
			}

			creates[i] = client.PkgEqual.Create().
				AddPackageIDs(sortedPkgIDs...).
				SetPackagesHash(hashPackages(sortedPkgs)).
				SetCollector(pe.Collector).
				SetJustification(pe.Justification).
				SetOrigin(pe.Origin)

			index++
		}

		err := client.PkgEqual.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, err
		}
	}
	return &ids, nil
}

func upsertPackageEqual(ctx context.Context, client *ent.Tx, pkgA model.IDorPkgInput, pkgB model.IDorPkgInput, spec model.PkgEqualInputSpec) (*string, error) {

	sortedPkgs := []model.IDorPkgInput{pkgA, pkgB}

	sort.SliceStable(sortedPkgs, func(i, j int) bool { return *sortedPkgs[i].PackageVersionID < *sortedPkgs[j].PackageVersionID })

	var sortedPkgIDs []uuid.UUID
	for _, pkg := range sortedPkgs {
		if pkg.PackageVersionID == nil {
			return nil, fmt.Errorf("PackageVersionID not specified in IDorPkgInput")
		}
		pkgID, err := uuid.Parse(*pkg.PackageVersionID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from PackageVersionID failed with error: %w", err)
		}
		sortedPkgIDs = append(sortedPkgIDs, pkgID)
	}

	_, err := client.PkgEqual.Create().
		AddPackageIDs(sortedPkgIDs...).
		SetPackagesHash(hashPackages(sortedPkgs)).
		SetCollector(spec.Collector).
		SetJustification(spec.Justification).
		SetOrigin(spec.Origin).
		OnConflict(
			sql.ConflictColumns(
				pkgequal.FieldPackagesHash,
				pkgequal.FieldOrigin,
				pkgequal.FieldCollector,
				pkgequal.FieldJustification,
			),
		).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsertPackageEqual")
		}
	}

	return ptrfrom.String(""), nil
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
		ID:            record.ID.String(),
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
func hashPackages(slc []model.IDorPkgInput) string {
	pkgs := slc
	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	for _, v := range pkgs {
		content.WriteString(fmt.Sprintf("%d", v.PackageVersionID))
	}

	hash.Write(content.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
}
