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
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IsOccurrence(ctx context.Context, query *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {

	records, err := b.client.Occurrence.Query().
		Where(isOccurrenceQuery(query)).
		WithArtifact().
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
		}).
		WithSource(func(q *ent.SourceNameQuery) {}).
		All(ctx)
	if err != nil {
		return nil, err
	}

	models := make([]*model.IsOccurrence, len(records))
	for i, record := range records {
		models[i] = toModelIsOccurrenceWithSubject(record)
	}

	return models, nil
}

func (b *EntBackend) IngestOccurrences(ctx context.Context, subjects model.PackageOrSourceInputs, artifacts []*model.IDorArtifactInput, occurrences []*model.IsOccurrenceInputSpec) ([]string, error) {
	funcName := "IngestOccurrences"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkOccurrences(ctx, client, subjects, artifacts, occurrences)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	return *ids, nil
}

func upsertBulkOccurrences(ctx context.Context, client *ent.Tx, subjects model.PackageOrSourceInputs, artifacts []*model.IDorArtifactInput, occurrences []*model.IsOccurrenceInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	occurrenceConflictColumns := []string{
		occurrence.FieldArtifactID,
		occurrence.FieldJustification,
		occurrence.FieldOrigin,
		occurrence.FieldCollector,
	}

	var conflictWhere *sql.Predicate

	switch {
	case len(subjects.Packages) > 0:
		occurrenceConflictColumns = append(occurrenceConflictColumns, occurrence.FieldPackageID)
		conflictWhere = sql.And(
			sql.NotNull(occurrence.FieldPackageID),
			sql.IsNull(occurrence.FieldSourceID),
		)
	case len(subjects.Sources) > 0:
		occurrenceConflictColumns = append(occurrenceConflictColumns, occurrence.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(occurrence.FieldPackageID),
			sql.NotNull(occurrence.FieldSourceID),
		)
	}

	batches := chunk(occurrences, 100)

	index := 0
	for _, occurs := range batches {
		creates := make([]*ent.OccurrenceCreate, len(occurs))
		for i, occur := range occurs {
			creates[i] = client.Occurrence.Create().
				SetJustification(occur.Justification).
				SetOrigin(occur.Origin).
				SetCollector(occur.Collector)

			if artifacts[index].ArtifactID == nil {
				return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
			}
			artID, err := uuid.Parse(*artifacts[index].ArtifactID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
			}
			creates[i].SetArtifactID(artID)

			switch {
			case len(subjects.Packages) > 0:
				if subjects.Packages[index].PackageVersionID == nil {
					return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
				}
				pkgVersionID, err := uuid.Parse(*subjects.Packages[index].PackageVersionID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from PackageVersionID failed with error: %w", err)
				}
				creates[i].SetPackageID(pkgVersionID)
			case len(subjects.Sources) > 0:
				if subjects.Sources[index].SourceNameID == nil {
					return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
				}
				sourceID, err := uuid.Parse(*subjects.Sources[index].SourceNameID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
				}
				creates[i].SetSourceID(sourceID)
			}
			index++
		}

		err := client.Occurrence.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(occurrenceConflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	return &ids, nil
}

func (b *EntBackend) IngestOccurrence(ctx context.Context,
	subject model.PackageOrSourceInput,
	art model.IDorArtifactInput,
	spec model.IsOccurrenceInputSpec,
) (string, error) {
	funcName := "IngestOccurrence"

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)
		client := tx.Client()
		var err error

		if art.ArtifactID == nil {
			return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
		}
		artID, err := uuid.Parse(*art.ArtifactID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
		}

		occurrenceCreate := client.Occurrence.Create().
			SetArtifactID(artID).
			SetJustification(spec.Justification).
			SetOrigin(spec.Origin).
			SetCollector(spec.Collector)

		occurrenceConflictColumns := []string{
			occurrence.FieldArtifactID,
			occurrence.FieldJustification,
			occurrence.FieldOrigin,
			occurrence.FieldCollector,
		}

		var conflictWhere *sql.Predicate

		if subject.Package != nil {
			if subject.Package.PackageVersionID == nil {
				return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
			}
			pkgVersionID, err := uuid.Parse(*subject.Package.PackageVersionID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
			occurrenceCreate.SetPackageID(pkgVersionID)
			occurrenceConflictColumns = append(occurrenceConflictColumns, occurrence.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(occurrence.FieldPackageID),
				sql.IsNull(occurrence.FieldSourceID),
			)
		} else if subject.Source != nil {
			if subject.Source.SourceNameID == nil {
				return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
			}
			sourceID, err := uuid.Parse(*subject.Source.SourceNameID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from SourceNameID failed with error: %w", err)
			}
			occurrenceCreate.SetSourceID(sourceID)
			occurrenceConflictColumns = append(occurrenceConflictColumns, occurrence.FieldSourceID)
			conflictWhere = sql.And(
				sql.IsNull(occurrence.FieldPackageID),
				sql.NotNull(occurrence.FieldSourceID),
			)
		} else {
			return nil, gqlerror.Errorf("%v :: %s", funcName, "subject must be either a package or source")
		}

		if _, err := occurrenceCreate.
			OnConflict(
				sql.ConflictColumns(occurrenceConflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			UpdateNewValues().
			ID(ctx); err != nil {
			return nil, err
		}

		return ptrfrom.String(""), nil
	})
	if err != nil {
		return "", gqlerror.Errorf("%v :: %s", funcName, err)
	}

	return *recordID, nil
}

func isOccurrenceQuery(filter *model.IsOccurrenceSpec) predicate.Occurrence {
	if filter == nil {
		return NoOpSelector()
	}
	predicates := []predicate.Occurrence{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Justification, occurrence.JustificationEQ),
		optionalPredicate(filter.Origin, occurrence.OriginEQ),
		optionalPredicate(filter.Collector, occurrence.CollectorEQ),
	}

	if filter.Artifact != nil {
		predicates = append(predicates,
			occurrence.HasArtifactWith(func(s *sql.Selector) {
				if filter.Artifact != nil {
					optionalPredicate(filter.Artifact.Digest, artifact.DigestEQ)(s)
					optionalPredicate(filter.Artifact.Algorithm, artifact.AlgorithmEQ)(s)
					optionalPredicate(filter.Artifact.ID, IDEQ)(s)
				}
			}),
		)
	}

	if filter.Subject != nil {
		if filter.Subject.Package != nil {
			predicates = append(predicates, occurrence.HasPackageWith(packageVersionQuery(filter.Subject.Package)))
		} else if filter.Subject.Source != nil {
			predicates = append(predicates,
				occurrence.HasSourceWith(
					optionalPredicate(filter.Subject.Source.ID, IDEQ),
					optionalPredicate(filter.Subject.Source.Namespace, sourcename.NamespaceEQ),
					optionalPredicate(filter.Subject.Source.Type, sourcename.TypeEQ),
					optionalPredicate(filter.Subject.Source.Name, sourcename.NameEQ),
					optionalPredicate(filter.Subject.Source.Commit, sourcename.CommitEQ),
					optionalPredicate(filter.Subject.Source.Tag, sourcename.TagEQ),
				),
			)
		}
	}
	return occurrence.And(predicates...)
}
