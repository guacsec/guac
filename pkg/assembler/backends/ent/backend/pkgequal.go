package backend

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pkgequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) PkgEqual(ctx context.Context, spec *model.PkgEqualSpec) ([]*model.PkgEqual, error) {
	records, err := b.client.PkgEqual.Query().
		Where(
			pkgEqualQueryPredicates(spec),
		).
		WithPackageA(withPackageVersionTree()).
		WithPackageB(withPackageVersionTree()).
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

	pkgEql, err := client.PkgEqual.Query().
		Where(
			pkgequal.Or(
				pkgequal.And(
					pkgequal.HasPackageAWith(pkgVersionInputPredicates(&pkgA)),
					pkgequal.HasPackageBWith(pkgVersionInputPredicates(&pkgB)),
				),
				pkgequal.And(
					pkgequal.HasPackageAWith(pkgVersionInputPredicates(&pkgB)),
					pkgequal.HasPackageBWith(pkgVersionInputPredicates(&pkgA)),
				),
			),
		).
		Only(ctx)
	if ent.MaskNotFound(err) != nil {
		return nil, err
	}
	if pkgEql != nil {
		return pkgEql, nil
	}

	pkgARecord, err := client.PackageVersion.Query().Where(pkgVersionInputPredicates(&pkgA)).Only(ctx)
	if err != nil {
		return nil, err
	}
	pkgBRecord, err := client.PackageVersion.Query().Where(pkgVersionInputPredicates(&pkgB)).Only(ctx)
	if err != nil {
		return nil, err
	}

	// pkqEqual, err := pkgARecord.QuerySimilar().Where(pkgVersionInputPredicates(&pkgB)).QueryEqual().Where(pkgEqualInputQueryPredicates(spec)).Only(ctx)
	// if ent.MaskNotFound(err) != nil {
	// 	return nil, err
	// }

	// if pkqEqual == nil {
	// 	pkgBRecord, err := client.PackageVersion.Query().Where(pkgVersionInputPredicates(&pkgB)).Only(ctx)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	pkqEqual, err := client.PkgEqual.Create().
		SetPackageA(pkgARecord).
		SetPackageB(pkgBRecord).
		SetCollector(spec.Collector).
		SetJustification(spec.Justification).
		SetOrigin(spec.Origin).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return pkqEqual, nil

	// 	// OnConflict(
	// 	// 	sql.ConflictColumns(
	// 	// 		pkgequal.FieldPackageVersionID,
	// 	// 		pkgequal.FieldSimilarID,
	// 	// 	),
	// 	// ).
	// 	// DoNothing().
	// 	// Exec(ctx)

	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }

	// pkgBRecord, err := pkgARecord.
	// 	QuerySimilar().
	// 	Where(
	// 		pkgVersionInputPredicates(&pkgB),
	// 		packageversion.HasEqualWith(pkgEqualInputQueryPredicates(spec)),
	// 	).
	// 	Only(ctx)
	// if err != nil {
	// 	return nil, err
	// }

	return pkqEqual, nil
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

	// FIXME: (ivanvanderbyl) We could probably make this more efficient by querying the package first, then getting the Equal records
	for _, pkg := range spec.Packages {
		predicates = append(predicates, pkgequal.HasPackageAWith(
			packageversion.HasSimilarWith(
				pkgVersionPredicates(pkg),
			),
		))

		// 	predicates = append(predicates, pkgequal.Or(
		// 		pkgequal.HasPackageAWith(pkgVersionPredicates(pkg)),
		// 		pkgequal.HasPackageBWith(pkgVersionPredicates(pkg)),
		// 	))
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
	pkgA := backReferencePackageVersion(record.Edges.PackageA)
	pkgB := backReferencePackageVersion(record.Edges.PackageB)
	packages := make([]*ent.PackageType, 2)
	packages[0] = pkgA
	packages[1] = pkgB
	return &model.PkgEqual{
		ID:            nodeID(record.ID),
		Origin:        record.Origin,
		Collector:     record.Collector,
		Justification: record.Justification,
		Packages:      collect(packages, toModelPackage),
	}
}
