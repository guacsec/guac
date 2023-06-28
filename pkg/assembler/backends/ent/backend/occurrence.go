package backend

import (
	"context"
	"log"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IsOccurrence(ctx context.Context, query *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {
	funcName := "IsOccurrence"
	if query != nil {
		if err := helper.ValidatePackageOrSourceQueryFilter(query.Subject); err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
	}

	records, err := b.client.Debug().Occurrence.Query().
		Where(
			optionalPredicate(query.Justification, occurrence.JustificationEQ),
			optionalPredicate(query.Origin, occurrence.OriginEQ),
			optionalPredicate(query.Collector, occurrence.CollectorEQ),
			occurrence.HasArtifactWith(func(s *sql.Selector) {
				if query.Artifact != nil {
					optionalPredicate(query.Artifact.Digest, artifact.DigestEQ)(s)
					optionalPredicate(query.Artifact.Algorithm, artifact.AlgorithmEQ)(s)
					optionalPredicate(query.Artifact.ID, IDEQ)(s)
				}
			}),
			occurrence.HasPackageWith(
				packageversion.VersionEQ(*query.Subject.Package.Version),
			),

		// 	occurrence.HasSubjectWith(func(s *sql.Selector) {
		// 		if query.Subject != nil {
		// 			if query.Subject.Package != nil {
		// 				occurrencesubject.HasPackageWith(
		// 					packageversion.VersionEQ(""),
		// 					// optionalPredicate(query.Subject.Package.Version, packageversion.VersionEQ),
		// 				)(s)

		// 				// occurrencesubject.HasPackageWith(func(s *sql.Selector) {
		// 				// 	optionalPredicate(query.Subject.Package.Version, packageversion.VersionEQ)(s)
		// 				// 	if query.Subject.Package.Name != nil {
		// 				// 		packageversion.HasNameWith(packagename.NameEQ(*query.Subject.Package.Name))(s)
		// 				// 	}
		// 				// 	if query.Subject.Package.Namespace != nil {
		// 				// 		packageversion.HasNameWith(
		// 				// 			packagename.HasNamespaceWith(packagenamespace.NamespaceEQ(*query.Subject.Package.Namespace)),
		// 				// 		)(s)
		// 				// 		// packageversion.HasNameWith(packagename.NameEQ(*query.Subject.Package.Name))(s)
		// 				// 	}

		// 				// 	// optionalPredicate(query.Subject.Package.Name, occurrencesubject.HasPackageWith(
		// 				// 	// 	packageversion.HasPackageWith(),
		// 				// 	// ))(s)
		// 				// 	// optionalPredicate(query.Subject.Package.Name, occurrencesubject.PackageNameEQ)(s)
		// 				// 	// optionalPredicate(query.Subject.Package.Version, occurrencesubject.PackageVersionEQ)(s)
		// 				// })
		// 				// optionalPredicate(query.Subject.Package.Name, occurrencesubject.PackageNameEQ)(s)
		// 			}
		// 		}
		// 	}),
		).
		WithArtifact().
		WithPackage().
		// WithSubject(func(q *ent.OccurrenceSubjectQuery) {
		// 	q.WithPackage()
		// 	q.WithSource()

		// }).
		All(ctx)
	if err != nil {
		return nil, err
	}

	log.Println("Query End")

	models := make([]*model.IsOccurrence, len(records))
	for i, record := range records {

		var sub model.PackageOrSource

		if pv := record.Edges.Package; pv != nil {
			p, err := pkgTreeFromVersion(ctx, pv)
			if err != nil {
				return nil, err
			}

			sub = toModelPackage(p)
		}

		// var sub model.PackageOrSource

		// if record.Edges.Package != nil {
		// 	sub, err = b.buildPackageResponse(ctx, record.Edges.PackageVersion.ID, model.PkgSpec{})
		// 	if err != nil {
		// 		return nil, err
		// 	}
		// } else if record.Edges.Source != nil {
		// 	// sub, err = b.buildSourceResponse(ctx, record.Edges.Source.ID, model.SourceSpec{})
		// 	// if err != nil {
		// 	// 	return nil, err
		// 	// }
		// }

		models[i] = toModelIsOccurrence(record, sub)
	}

	return models, nil
}

func (b *EntBackend) IngestOccurrence(ctx context.Context,
	subject model.PackageOrSourceInput,
	art model.ArtifactInputSpec,
	spec model.IsOccurrenceInputSpec,
) (*model.IsOccurrence, error) {
	funcName := "IngestOccurrence"
	if err := helper.ValidatePackageOrSourceInput(&subject, "IngestOccurrence"); err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.FromContext(ctx)
		var err error

		artRecord, err := client.Artifact.Query().
			Order(ent.Asc(artifact.FieldID)). // is order important here?
			Where(artifactQueryFromInputSpec(art)).
			Only(ctx) // should already be ingested
		if err != nil {
			return nil, err
		}
		var pkgVersion *ent.PackageVersion
		if subject.Package != nil {
			pkgVersion, err = upsertPackage(ctx, client, *subject.Package)
			if err != nil {
				return nil, err
			}
			// subjectID, err := client.OccurrenceSubject.Create().
			// 	SetPackage(pkgVersion).
			// 	SetOccurrenceID(id).
			// 	OnConflict(
			// 		sql.ConflictColumns(
			// 			occurrencesubject.FieldOccurrenceID,
			// 			// occurrencesubject.FieldPackageID,
			// 		),
			// 	).
			// 	UpdateNewValues().
			// 	ID(ctx)
			// if err != nil {
			// 	return nil, err
			// }
		}

		id, err := client.Occurrence.Create().
			SetArtifact(artRecord).
			SetPackageID(pkgVersion.ID).
			SetJustification(spec.Justification).
			SetOrigin(spec.Origin).
			SetCollector(spec.Collector).
			OnConflict(
				sql.ConflictColumns(
					occurrence.FieldArtifactID,
					occurrence.FieldPackageID,
					occurrence.FieldJustification,
					occurrence.FieldOrigin,
					occurrence.FieldCollector,
				),
			).
			UpdateNewValues().
			ID(ctx)
		if err != nil {
			return nil, err
		}

		return &id, nil
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	// TODO: Prepare response using a resusable resolver that accounts for preloads.

	record, err := b.client.Occurrence.Query().
		Where(occurrence.ID(*recordID)).
		WithArtifact().
		// WithSubject(func(q *ent.OccurrenceSubjectQuery) {
		WithPackage(func(q *ent.PackageVersionQuery) {
			// q.WithName(func(q *ent.PackageNameQuery) {
			// 	q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
			// 		q.WithPackage(func(q *ent.PackageNodeQuery) {
			// 			// buildPackageTreeQuery(q, ns string, packageName string, pv *ent.PackageVersion)
			// 		})
			// 	})
			// })
		}).
		// q.WithSource(func(q *ent.SourceNameQuery) {
		// 	q.WithNamespace(func(q *ent.SourceNamespaceQuery) {
		// 		q.WithSource()
		// 	})
		// })
		// }).
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	var sub model.PackageOrSource

	if pv := record.Edges.Package; pv != nil {
		p, err := pkgTreeFromVersion(ctx, pv)
		if err != nil {
			return nil, err
		}

		sub = toModelPackage(p)

		// pName, err := pv.QueryName().Only(ctx)
		// if err != nil {
		// 	return nil, err
		// }

		// pNs, err := pName.QueryNamespace().Only(ctx)
		// if err != nil {
		// 	return nil, err
		// }

		// p, err := pNs.QueryPackage().Only(ctx)
		// if err != nil {
		// 	return nil, err
		// }

		// p.Edges.Namespaces = []*ent.PackageNamespace{pNs}
		// pNs.Edges.Names = []*ent.PackageName{pName}
		// pNs.Edges.Package = p
		// pName.Edges.Versions = []*ent.PackageVersion{pv}
		// pName.Edges.Namespace = pNs
		// pv.Edges.Name = pName

		// pv.Edges.Name = pName
		// pName.Edges.Versions = []*ent.PackageVersion{pv}
		// pNs.Edges.Names = []*ent.PackageName{pName}
		// p.Edges.Namespaces = []*ent.PackageNamespace{pNs}
		// record.Edges.Subject.Edges.Package.Edges.Name = pName
	}

	return toModelIsOccurrence(record, sub), nil
}
