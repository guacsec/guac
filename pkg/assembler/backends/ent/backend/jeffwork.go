package backend

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
