package backend

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageoccurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourceoccurrence"
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

	records, err := b.client.PackageOccurrence.Query().
		Where().
		WithArtifact().
		// WithSource().
		WithPackage().
		All(ctx)
	if err != nil {
		return nil, err
	}

	models := make([]*model.IsOccurrence, len(records))
	for i, record := range records {
		var sub model.PackageOrSource

		if record.Edges.Package != nil {
			sub, err = b.buildPackageResponse(ctx, record.Edges.PackageVersion.ID, model.PkgSpec{})
			if err != nil {
				return nil, err
			}
		} else if record.Edges.Source != nil {
			// sub, err = b.buildSourceResponse(ctx, record.Edges.Source.ID, model.SourceSpec{})
			// if err != nil {
			// 	return nil, err
			// }
		}

		models[i] = normalizePackageOccurrence(record, sub)
	}

	return models, nil
}

func buildOccurrenceQuery(ctx context.Context, client *ent.Client, query *model.IsOccurrenceSpec) (ent.SourceOccurrenceQuery, error) {

}

func (b *EntBackend) IngestOccurrence(ctx context.Context,
	subject model.PackageOrSourceInput,
	art model.ArtifactInputSpec,
	occurrence model.IsOccurrenceInputSpec,
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

		if subject.Package != nil {
			packageID, err := upsertPackage(ctx, client, *subject.Package)
			if err != nil {
				return nil, err
			}

			id, err := client.PackageOccurrence.Create().
				SetPackageID(packageID).
				SetArtifact(art).
				SetJustification(occurrence.Justification).
				SetOrigin(occurrence.Origin).
				SetCollector(occurrence.Collector).
				OnConflict(
					sql.ConflictColumns(
						packageoccurrence.FieldArtifactID,
						packageoccurrence.FieldPackageID,
						packageoccurrence.FieldJustification,
						packageoccurrence.FieldOrigin,
						packageoccurrence.FieldCollector,
					),
				).
				UpdateNewValues().
				ID(ctx)
			if err != nil {
				return nil, err
			}
			return &id, nil
		} else if subject.Source != nil {
			sourceID, err := ingestSource(ctx, client, *subject.Source)
			if err != nil {
				return nil, err
			}

			id, err := client.SourceOccurrence.Create().
				SetSourceID(*sourceID).
				SetArtifact(art).
				SetJustification(occurrence.Justification).
				SetOrigin(occurrence.Origin).
				SetCollector(occurrence.Collector).
				OnConflict(
					sql.ConflictColumns(
						sourceoccurrence.FieldArtifactID,
						sourceoccurrence.FieldSourceID,
						sourceoccurrence.FieldJustification,
						sourceoccurrence.FieldOrigin,
						sourceoccurrence.FieldCollector,
					),
				).
				UpdateNewValues().
				ID(ctx)
			if err != nil {
				return nil, err
			}
			return &id, nil
		}

		return nil, fmt.Errorf("subject is required")
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	// TODO: Prepare response using a resusable resolver that accounts for preloads.

	record, err := b.client.PackageOccurrence.Query().
		Where(packageoccurrence.ID(*recordID)).
		WithArtifact().
		WithPackage().
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	var sub model.PackageOrSource
	if record.Edges.Package != nil {
		sub, err = b.buildPackageResponse(ctx, record.Edges.Package.ID, model.PkgSpec{})
		if err != nil {
			return nil, err
		}
	}

	return normalizePackageOccurrence(record, sub), nil
}
