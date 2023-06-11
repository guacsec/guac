package backend

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/isoccurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

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

		var pvID *int
		var err error
		var srcID *int
		if subject.Package != nil {
			id, err := ingestPackage(ctx, client, *subject.Package)
			if err != nil {
				return nil, err
			}
			pvID = &id
		} else if subject.Source != nil {
			// Ingest source
			id, err := ingestSource(ctx, client, *subject.Source)
			if err != nil {
				return nil, err
			}
			srcID = id
		}
		// if subject.Source != nil {
		// 	s, err = // query for source name object
		// }
		art, err := client.Artifact.Query().
			Order(ent.Asc(artifact.FieldID)). // is order important here?
			Where(artifact.Algorithm(art.Algorithm)).
			Where(artifact.Digest(art.Digest)).
			Only(ctx) // should already be ingested
		if err != nil {
			return nil, err
		}
		id, err := client.IsOccurrence.Create().
			SetNillablePackageVersionID(pvID).
			SetNillableSourceID(srcID).
			SetArtifact(art).
			SetJustification(occurrence.Justification).
			SetOrigin(occurrence.Origin).
			SetCollector(occurrence.Collector).
			OnConflict(
				sql.ConflictColumns(
					isoccurrence.FieldArtifactID,
					isoccurrence.FieldPackageID,
					// isoccurrence.FieldSourceID,
					isoccurrence.FieldJustification,
					isoccurrence.FieldOrigin,
					isoccurrence.FieldCollector,
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

	record, err := b.client.IsOccurrence.Query().
		Where(isoccurrence.ID(*recordID)).
		WithArtifact().
		WithPackageVersion().
		WithSource().
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	var sub model.PackageOrSource
	if record.Edges.PackageVersion != nil {
		sub, err = b.buildPackageResponse(ctx, record.Edges.PackageVersion.ID, model.PkgSpec{})
		if err != nil {
			return nil, err
		}
	}

	return toModelIsOccurrence(record, sub), nil
}
