package backend

import (
	"context"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	isdependency "github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	funcName := "IsDependency"
	query := b.client.Dependency.Query().Order(ent.Asc(isdependency.FieldID))

	if isDependencySpec != nil {
		query.Where(
			optionalPredicate(isDependencySpec.ID, IDEQ),
			isdependency.HasPackageWith(pkgVersionPredicates(isDependencySpec.Package)...),
			isdependency.HasDependentPackageWith(pkgNamePredicates(isDependencySpec.DependentPackage)...),
			optionalPredicate(isDependencySpec.VersionRange, isdependency.VersionRange),
			optionalPredicate(isDependencySpec.Justification, isdependency.Justification),
			optionalPredicate(isDependencySpec.Origin, isdependency.Origin),
			optionalPredicate(isDependencySpec.Collector, isdependency.Collector),
		)
		if isDependencySpec.DependencyType != nil {
			query.Where(isdependency.DependencyType(string(*isDependencySpec.DependencyType)))
		}
	} else {
		query.Limit(100)
	}

	ids, err := query.
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.Limit(1)
		}).
		WithDependentPackage().
		All(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	rv, err := collectErr(ctx, ids, toModelIsDependency)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}
	return rv, nil
}

func (b *EntBackend) IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {
	funcName := "IngestDependency"

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.FromContext(ctx)
		p, err := getPkgVersion(ctx, client, &pkg)
		if err != nil {
			return nil, err
		}
		dp, err := getPkgName(ctx, client, &depPkg)
		if err != nil {
			return nil, err
		}
		id, err := client.Dependency.Create().
			SetPackage(p). // Should I be using SetPackageID() here?
			SetDependentPackage(dp).
			SetVersionRange(dependency.VersionRange).
			SetDependencyType(string(dependency.DependencyType)).
			SetJustification(dependency.Justification).
			SetOrigin(dependency.Origin).
			SetCollector(dependency.Collector).
			OnConflict(
				entsql.ConflictColumns(
					isdependency.FieldPackageID,
					isdependency.FieldDependentPackageID,
					isdependency.FieldVersionRange,
					isdependency.FieldDependencyType,
					isdependency.FieldJustification,
					isdependency.FieldOrigin,
					isdependency.FieldCollector,
				),
			).
			UpdateNewValues().ID(ctx)
		if err != nil {
			return nil, err
		}
		return &id, nil
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	// Upsert only gets ID, so need to query the object
	record, err := b.client.Dependency.Query().
		Where(isdependency.ID(*recordID)).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.Limit(1)
		}).
		WithDependentPackage().
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	return toModelIsDependency(ctx, record)
}

// func (b *EntBackend) IngestOccurrence_Jeff(ctx context.Context, subject model.PackageOrSourceInput, art model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error) {
// 	funcName := "IngestOccurrence"
// 	if err := helper.ValidatePackageOrSourceInput(&subject, "IngestOccurrence"); err != nil {
// 		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
// 	}

// 	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
// 		client := ent.FromContext(ctx)
// 		// var p *ent.PackageVersion
// 		//var s *ent.SourceName
// 		// if subject.Package != nil {
// 		// 	var err error
// 		// 	p, err = b.getPkgVersion(ctx, subject.Package)
// 		// 	if err != nil {
// 		// 		return nil, err
// 		// 	}
// 		// }
// 		a, err := b.getArtifact(ctx, &art)
// 		if err != nil {
// 			return nil, err
// 		}

// 		if subject.Source != nil {
// 			id, err := client.SourceOccurrence.Create().
// 				SetSource(src).
// 				SetArtifact(a).
// 				SetJustification(occurrence.Justification).
// 				SetOrigin(occurrence.Origin).
// 				SetCollector(occurrence.Collector).
// 				OnConflict(
// 					entsql.ConflictColumns(
// 						isoccurrence.FieldPackageID,
// 						isoccurrence.FieldSourceID,
// 						isoccurrence.FieldArtifactID,
// 						isoccurrence.FieldJustification,
// 						isoccurrence.FieldOrigin,
// 						isoccurrence.FieldCollector,
// 					),
// 				).
// 				UpdateNewValues().ID(ctx)
// 			if err != nil {
// 				return nil, err
// 			}
// 			return &id, nil
// 		} else {
// 			id, err := client.PackageOccurrence.Create().
// 				SetPackage(p).
// 				SetArtifact(a).
// 				SetJustification(occurrence.Justification).
// 				SetOrigin(occurrence.Origin).
// 				SetCollector(occurrence.Collector).
// 				OnConflict(
// 					entsql.ConflictColumns(
// 						isoccurrence.FieldPackageID,
// 						isoccurrence.FieldArtifactID,
// 						isoccurrence.FieldJustification,
// 						isoccurrence.FieldOrigin,
// 						isoccurrence.FieldCollector,
// 					),
// 				).
// 				UpdateNewValues().ID(ctx)
// 			if err != nil {
// 				return nil, err
// 			}
// 			return &id, nil
// 		}
// 	})
// 	if err != nil {
// 		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
// 	}

// 	// Upsert only gets ID, so need to query the object
// 	record, err := b.client.Occurrence.Query().
// 		Where(isoccurrence.ID(*recordID)).
// 		WithArtifact().
// 		// WithPackage().
// 		Only(ctx)
// 	if err != nil {
// 		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
// 	}

// 	return toModelIsOccurrenceErr(ctx, record)
// }

// func toModelIsOccurrenceErr(ctx context.Context, o *ent.Occurrence) (*model.IsOccurrence, error) {
// 	var sub model.PackageOrSource
// 	if o.PackageID != nil { // how do we indicate that this is linked to pkg and not src??
// 		top, err := pkgTreeFromVersion(ctx, o.Edges.PackageVersion)
// 		if err != nil {
// 			return nil, err
// 		}
// 		sub = toModelPackage(top)
// 	}
// 	// if o.SourceID != 0 { // ?? how do we do this?
// 	// 	sub = toModelSource(o.Edges.Source)
// 	// }
// 	return &model.IsOccurrence{
// 		ID:            nodeID(o.ID),
// 		Subject:       sub,
// 		Artifact:      toModelArtifact(o.Edges.Artifact),
// 		Justification: o.Justification,
// 		Origin:        o.Origin,
// 		Collector:     o.Collector,
// 	}, nil
// }
