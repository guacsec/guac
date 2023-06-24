package backend

import (
	"context"
	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IsOccurrence(ctx context.Context, query *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {
	if query.Subject == nil {
		return nil, gqlerror.Errorf("IsOccurrence :: subject is required")
	}

	if query.Subject.Package != nil {
	}

	records, err := b.client.Occurrence.Query().
		Where().
		WithArtifact().
		WithSubject().
		All(ctx)
	if err != nil {
		return nil, err
	}

	models := make([]*model.IsOccurrence, len(records))
	for i, record := range records {
		var sub model.PackageOrSource

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

		art, err := client.Artifact.Query().
			Order(ent.Asc(artifact.FieldID)). // is order important here?
			Where(artifact.Algorithm(art.Algorithm), artifact.Digest(art.Digest)).
			Only(ctx) // should already be ingested
		if err != nil {
			return nil, err
		}

		var packageID int
		var sourceID *int
		if subject.Package != nil {
			packageID, err = upsertPackage(ctx, client, *subject.Package)
			if err != nil {
				return nil, err
			}
		} else if subject.Source != nil {
			sourceID, err = ingestSource(ctx, client, *subject.Source)
			if err != nil {
				return nil, err
			}
		}

		occurrenceSubject, err := client.OccurrenceSubject.Create().
			SetNillablePackageID(&packageID).
			SetNillableSourceID(sourceID).
			Save(ctx)
		if err != nil {
			return nil, err
		}
		id, err := client.Occurrence.Create().
			SetArtifact(art).
			SetJustification(spec.Justification).
			SetOrigin(spec.Origin).
			SetCollector(spec.Collector).
			SetSubject(occurrenceSubject).
			OnConflict(
				sql.ConflictColumns(
					occurrence.FieldArtifactID,
					occurrence.FieldSubjectID,
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
		WithSubject(func(q *ent.OccurrenceSubjectQuery) {
			q.WithPackage(func(q *ent.PackageVersionQuery) {
				q.WithName(func(q *ent.PackageNameQuery) {
					q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
						q.WithPackage()
					})
				})
			}).
			WithSource(func(q *ent.SourceNameQuery) {
				q.WithNamespace(func(q *ent.SourceNamespaceQuery) {
					q.WithSource()
				})
			})
		}).
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	//var sub model.PackageOrSource
	//if record.Edges.Subject != nil {
		// 	sub, err = b.buildPackageResponse(ctx, record.Edges.Package.ID, model.PkgSpec{})
		// 	if err != nil {
		// 		return nil, err
		// 	}
	//}

	return toModelIsOccurrenceWithSubject(record), nil
}
