package ent

import (
	"context"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/isoccurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, art model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error) {
	funcName := "IngestOccurrence"
	if err := helper.ValidatePackageOrSourceInput(&subject, "IngestOccurrence"); err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := FromContext(ctx)
		var p *PackageVersion
		//var s *ent.SourceName
		if subject.Package != nil {
			//p, err = // query for package version object
		}
		// if subject.Source != nil {
		// 	s, err = // query for source name object
		// }
		a, err := client.Artifact.Query().
			Order(Asc(artifact.FieldID)). // is order important here?
			Where(artifact.Algorithm(art.Algorithm)).
			Where(artifact.Digest(art.Digest)).
			Only(ctx) // should already be ingested
		if err != nil {
			return nil, err
		}
		id, err := client.IsOccurrence.Create().
			SetPackage(p).
			SetArtifact(a).
			SetJustification(occurrence.Justification).
			SetOrigin(occurrence.Origin).
			SetCollector(occurrence.Collector).
			OnConflict(
				entsql.ConflictColumns(
					isoccurrence.FieldPackageID,
					isoccurrence.FieldSourceID,
					isoccurrence.FieldArtifactID,
					isoccurrence.FieldJustification,
					isoccurrence.FieldOrigin,
					isoccurrence.FieldCollector,
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

	record, err := b.client.IsOccurrence.Query().
		Where(isoccurrence.ID(*recordID)).
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	return toModelIsOccurrence(record), nil
}

func toModelIsOccurrence(o *IsOccurrence) *model.IsOccurrence {
	var sub model.PackageOrSource
	if o.PackageID != 0 { // ?? how do we do this?
		//sub = toModelPackage(o.Edges.Package) // doesnt compile
	}
	// if o.SourceID != 0 { // ?? how do we do this?
	// 	sub = toModelSource(o.Edges.Source)
	// }
	return &model.IsOccurrence{
		ID:            nodeid(o.ID),
		Subject:       sub,
		Artifact:      toModelArtifact(o.Edges.Artifact),
		Justification: o.Justification,
		Origin:        o.Origin,
		Collector:     o.Collector,
	}
}
