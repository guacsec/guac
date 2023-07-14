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

func upsertPackageEqual(ctx context.Context, client *ent.Tx, pkgA model.PkgInputSpec, pkgB model.PkgInputSpec, spec model.PkgEqualInputSpec) (*ent.PkgEqual, error) {
	pkgARecord, err := client.PackageVersion.Query().Where(packageVersionQuery(&pkgA)).Only(ctx)
	if err != nil {
		return nil, err
	}
	pkgBRecord, err := client.PackageVersion.Query().Where(packageVersionQuery(&pkgB)).Only(ctx)
	if err != nil {
		return nil, err
	}

	id, err := client.PkgEqual.Create().
		AddPackages(pkgARecord, pkgBRecord).
		SetPackagesHash(hashPackages([]*ent.PackageVersion{pkgARecord, pkgBRecord})).
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
		UpdateNewValues().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	pkgEqual, err := client.PkgEqual.Get(ctx, id)
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
		predicates = append(predicates, pkgequal.HasPackagesWith(pkgVersionPredicates(pkg)))
	}

	return pkgequal.And(predicates...)
}

func pkgEqualInputQueryPredicates(spec model.PkgEqualInputSpec) predicate.PkgEqual {
	return pkgequal.And(
		pkgequal.OriginEQ(spec.Origin),
		pkgequal.CollectorEQ(spec.Collector),
		pkgequal.JustificationEQ(spec.Justification),
	)
}

func toModelPkgEqual(record *ent.PkgEqual) *model.PkgEqual {
	packages := collect(record.Edges.Packages, backReferencePackageVersion)
	return &model.PkgEqual{
		ID:            nodeID(record.ID),
		Origin:        record.Origin,
		Collector:     record.Collector,
		Justification: record.Justification,
		Packages:      collect(packages, toModelPackage),
	}
}

func hashPackages(slc []*ent.PackageVersion) string {
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
