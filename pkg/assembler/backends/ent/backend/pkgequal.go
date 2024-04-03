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
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pkgequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) PkgEqual(ctx context.Context, spec *model.PkgEqualSpec) ([]*model.PkgEqual, error) {

	if len(spec.Packages) > 2 {
		return nil, fmt.Errorf("too many packages specified in pkg equal filter")
	}

	peQuery := b.client.PkgEqual.Query().
		Where(pkgEqualQueryPredicates(spec))

	records, err := getPkgEqualObject(peQuery).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelPkgEqual), nil
}

// getPkgEqualObject is used recreate the pkgEqual object be eager loading the edges
func getPkgEqualObject(q *ent.PkgEqualQuery) *ent.PkgEqualQuery {
	return q.
		WithPackageA(withPackageVersionTree()).
		WithPackageB(withPackageVersionTree())
}

func (b *EntBackend) IngestPkgEqual(ctx context.Context, pkg model.IDorPkgInput, depPkg model.IDorPkgInput, pkgEqual model.PkgEqualInputSpec) (string, error) {
	id, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertPackageEqual(ctx, ent.TxFromContext(ctx), pkg, depPkg, pkgEqual)
	})
	if txErr != nil {
		return "", txErr
	}

	return toGlobalID(pkgequal.Table, *id), nil
}

func (b *EntBackend) IngestPkgEquals(ctx context.Context, pkgs []*model.IDorPkgInput, otherPackages []*model.IDorPkgInput, pkgEquals []*model.PkgEqualInputSpec) ([]string, error) {
	funcName := "IngestPkgEquals"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkPkgEquals(ctx, client, pkgs, otherPackages, pkgEquals)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return toGlobalIDs(pkgequal.Table, *ids), nil
}

func upsertBulkPkgEquals(ctx context.Context, tx *ent.Tx, pkgs []*model.IDorPkgInput, otherPackages []*model.IDorPkgInput, pkgEquals []*model.PkgEqualInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		pkgequal.FieldPkgID,
		pkgequal.FieldEqualPkgID,
		pkgequal.FieldPackagesHash,
		pkgequal.FieldOrigin,
		pkgequal.FieldCollector,
		pkgequal.FieldJustification,
	}

	batches := chunk(pkgEquals, MaxBatchSize)

	index := 0
	for _, pes := range batches {
		creates := make([]*ent.PkgEqualCreate, len(pes))
		for i, pe := range pes {
			pe := pe
			var err error

			creates[i], err = generatePkgEqualCreate(ctx, tx, pkgs[index], otherPackages[index], pe)
			if err != nil {
				return nil, gqlerror.Errorf("generatePkgEqualCreate :: %s", err)
			}
			index++
		}

		err := tx.PkgEqual.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert pkgEquals node")
		}
	}
	return &ids, nil
}

func generatePkgEqualCreate(ctx context.Context, tx *ent.Tx, pkgA *model.IDorPkgInput, pkgB *model.IDorPkgInput, pkgEqualInput *model.PkgEqualInputSpec) (*ent.PkgEqualCreate, error) {

	if pkgA == nil {
		return nil, fmt.Errorf("pkgA must be specified for pkgEqual")
	}
	if pkgB == nil {
		return nil, fmt.Errorf("pkgB must be specified for pkgEqual")
	}

	pkgEqalCreate := tx.PkgEqual.Create().
		SetCollector(pkgEqualInput.Collector).
		SetJustification(pkgEqualInput.Justification).
		SetOrigin(pkgEqualInput.Origin)

	if pkgA.PackageVersionID == nil {
		pv, err := getPkgVersion(ctx, tx.Client(), *pkgA.PackageInput)
		if err != nil {
			return nil, fmt.Errorf("getPkgVersion :: %w", err)
		}
		pkgA.PackageVersionID = ptrfrom.String(toGlobalID(packageversion.Table, pv.ID.String()))
	}

	if pkgB.PackageVersionID == nil {
		pv, err := getPkgVersion(ctx, tx.Client(), *pkgB.PackageInput)
		if err != nil {
			return nil, fmt.Errorf("getPkgVersion :: %w", err)
		}
		pkgB.PackageVersionID = ptrfrom.String(toGlobalID(packageversion.Table, pv.ID.String()))
	}

	sortedPkgs := []model.IDorPkgInput{*pkgA, *pkgB}

	sort.SliceStable(sortedPkgs, func(i, j int) bool { return *sortedPkgs[i].PackageVersionID < *sortedPkgs[j].PackageVersionID })

	var sortedPkgIDs []uuid.UUID
	for _, pkg := range sortedPkgs {
		if pkg.PackageVersionID == nil {
			return nil, fmt.Errorf("PackageVersionID not specified in IDorPkgInput")
		}
		pkgVersionGlobalID := fromGlobalID(*pkg.PackageVersionID)
		pkgID, err := uuid.Parse(pkgVersionGlobalID.id)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from PackageVersionID failed with error: %w", err)
		}
		sortedPkgIDs = append(sortedPkgIDs, pkgID)
	}

	pkgEqalCreate.SetPackageAID(sortedPkgIDs[0])
	pkgEqalCreate.SetEqualPkgID(sortedPkgIDs[1])

	sortedPkgHash := hashPackages(sortedPkgs)

	pkgEqalCreate.SetPackagesHash(sortedPkgHash)

	pkgEqualID, err := guacPkgEqualKey(sortedPkgHash, pkgEqualInput)
	if err != nil {
		return nil, fmt.Errorf("failed to create pkgEqual uuid with error: %w", err)
	}
	pkgEqalCreate.SetID(*pkgEqualID)

	return pkgEqalCreate, nil
}

func upsertPackageEqual(ctx context.Context, tx *ent.Tx, pkgA model.IDorPkgInput, pkgB model.IDorPkgInput, spec model.PkgEqualInputSpec) (*string, error) {

	pkgEqualCreate, err := generatePkgEqualCreate(ctx, tx, &pkgA, &pkgB, &spec)
	if err != nil {
		return nil, gqlerror.Errorf("generatePkgEqualCreate :: %s", err)
	}
	if id, err := pkgEqualCreate.
		OnConflict(
			sql.ConflictColumns(
				pkgequal.FieldPkgID,
				pkgequal.FieldEqualPkgID,
				pkgequal.FieldPackagesHash,
				pkgequal.FieldOrigin,
				pkgequal.FieldCollector,
				pkgequal.FieldJustification,
			),
		).
		Ignore().
		ID(ctx); err != nil {
		return nil, errors.Wrap(err, "upsert pkgEqual node")
	} else {
		return ptrfrom.String(id.String()), nil
	}
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

	if len(spec.Packages) == 1 {
		predicates = append(predicates, pkgequal.Or(pkgequal.HasPackageAWith(packageVersionQuery(spec.Packages[0])), pkgequal.HasPackageBWith(packageVersionQuery(spec.Packages[0]))))
	} else if len(spec.Packages) == 2 {
		predicates = append(predicates, pkgequal.Or(pkgequal.HasPackageAWith(packageVersionQuery(spec.Packages[0])), pkgequal.HasPackageAWith(packageVersionQuery(spec.Packages[1]))))
		predicates = append(predicates, pkgequal.Or(pkgequal.HasPackageBWith(packageVersionQuery(spec.Packages[0])), pkgequal.HasPackageBWith(packageVersionQuery(spec.Packages[1]))))
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
	equalPkgs := []*ent.PackageVersion{record.Edges.PackageA, record.Edges.PackageB}
	packages := collect(equalPkgs, backReferencePackageVersion)

	return &model.PkgEqual{
		ID:            toGlobalID(pkgequal.Table, record.ID.String()),
		Origin:        record.Origin,
		Collector:     record.Collector,
		Justification: record.Justification,
		Packages:      collect(packages, toModelPackage),
	}
}

// hashPackages is used to create a unique key for the M2M edge between PkgEquals <-M2M-> PackageVersions
func hashPackages(slc []model.IDorPkgInput) string {
	pkgs := slc
	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	for _, v := range pkgs {
		content.WriteString(*v.PackageVersionID)
	}

	hash.Write(content.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func canonicalPkgEqualString(pe *model.PkgEqualInputSpec) string {
	return fmt.Sprintf("%s::%s::%s", pe.Justification, pe.Origin, pe.Collector)
}

// guacPkgEqualKey generates an uuid based on the hash of the inputspec and inputs. pkgEqual ID has to be set for bulk ingestion
// when ingesting multiple edges otherwise you get "violates foreign key constraint" as it creates
// a new ID for pkgEqual node (even when already ingested) that it maps to the edge and fails the look up. This only occurs when using UUID with
// "Default" func to generate a new UUID
func guacPkgEqualKey(sortedPkgHash string, peInput *model.PkgEqualInputSpec) (*uuid.UUID, error) {
	peIDString := fmt.Sprintf("%s::%s?", sortedPkgHash, canonicalPkgEqualString(peInput))

	peID := generateUUIDKey([]byte(peIDString))
	return &peID, nil
}
