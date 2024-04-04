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
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IsOccurrence(ctx context.Context, query *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {
	if query == nil {
		query = &model.IsOccurrenceSpec{}
	}
	occurQuery := b.client.Occurrence.Query().
		Where(isOccurrenceQuery(query))

	records, err := getOccurrenceObject(occurQuery).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelIsOccurrenceWithSubject), nil
}

// getOccurrenceObject is used recreate the occurrence object be eager loading the edges
func getOccurrenceObject(q *ent.OccurrenceQuery) *ent.OccurrenceQuery {
	return q.
		WithArtifact().
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
		}).
		WithSource(func(q *ent.SourceNameQuery) {})
}

func (b *EntBackend) IngestOccurrences(ctx context.Context, subjects model.PackageOrSourceInputs, artifacts []*model.IDorArtifactInput, occurrences []*model.IsOccurrenceInputSpec) ([]string, error) {
	funcName := "IngestOccurrences"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkOccurrences(ctx, client, subjects, artifacts, occurrences)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return toGlobalIDs(occurrence.Table, *ids), nil
}

func upsertBulkOccurrences(ctx context.Context, tx *ent.Tx, subjects model.PackageOrSourceInputs, artifacts []*model.IDorArtifactInput, occurrences []*model.IsOccurrenceInputSpec) (*[]string, error) {
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
	default:
		return nil, gqlerror.Errorf("%v :: %s", "upsertBulkOccurrences", "subject must be either a package or source")
	}

	batches := chunk(occurrences, MaxBatchSize)

	index := 0
	for _, occurs := range batches {
		creates := make([]*ent.OccurrenceCreate, len(occurs))
		for i, occur := range occurs {
			occur := occur
			switch {
			case len(subjects.Packages) > 0:
				var err error
				var isOccurrenceID *uuid.UUID
				creates[i], isOccurrenceID, err = generateOccurrenceCreate(ctx, tx, subjects.Packages[index], nil, artifacts[index], occur)
				if err != nil {
					return nil, gqlerror.Errorf("generateDependencyCreate :: %s", err)
				}
				ids = append(ids, isOccurrenceID.String())

			case len(subjects.Sources) > 0:
				var err error
				var isOccurrenceID *uuid.UUID
				creates[i], isOccurrenceID, err = generateOccurrenceCreate(ctx, tx, nil, subjects.Sources[index], artifacts[index], occur)
				if err != nil {
					return nil, gqlerror.Errorf("generateDependencyCreate :: %s", err)
				}
				ids = append(ids, isOccurrenceID.String())
			default:
				return nil, gqlerror.Errorf("%v :: %s", "upsertBulkOccurrences", "subject must be either a package or source")
			}
			index++
		}

		err := tx.Occurrence.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(occurrenceConflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert Occurrence node")
		}
	}

	return &ids, nil
}

func generateOccurrenceCreate(ctx context.Context, tx *ent.Tx, pkg *model.IDorPkgInput, src *model.IDorSourceInput, art *model.IDorArtifactInput, occur *model.IsOccurrenceInputSpec) (*ent.OccurrenceCreate, *uuid.UUID, error) {

	occurrenceCreate := tx.Occurrence.Create()

	if art == nil {
		return nil, nil, fmt.Errorf("artifact must be specified for isOccurrence")
	}
	var artID uuid.UUID
	if art.ArtifactID != nil {
		var err error
		artGlobalID := fromGlobalID(*art.ArtifactID)
		artID, err = uuid.Parse(artGlobalID.id)
		if err != nil {
			return nil, nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
		}
	} else {
		foundArt, err := tx.Artifact.Query().Where(artifactQueryInputPredicates(*art.ArtifactInput)).Only(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to query for artifact")
		}
		artID = foundArt.ID
	}

	occurrenceCreate.
		SetArtifactID(artID).
		SetJustification(occur.Justification).
		SetOrigin(occur.Origin).
		SetCollector(occur.Collector)

	var isOccurrenceID *uuid.UUID
	if pkg != nil {
		var pkgVersionID uuid.UUID
		if pkg.PackageVersionID != nil {
			var err error
			pkgVersionGlobalID := fromGlobalID(*pkg.PackageVersionID)
			pkgVersionID, err = uuid.Parse(pkgVersionGlobalID.id)
			if err != nil {
				return nil, nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
		} else {
			pv, err := getPkgVersion(ctx, tx.Client(), *pkg.PackageInput)
			if err != nil {
				return nil, nil, fmt.Errorf("getPkgVersion :: %w", err)
			}
			pkgVersionID = pv.ID
		}
		occurrenceCreate.SetPackageID(pkgVersionID)

		var err error
		isOccurrenceID, err = guacOccurrenceKey(ptrfrom.String(pkgVersionID.String()), nil, ptrfrom.String(artID.String()), *occur)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create occurrence uuid with error: %w", err)
		}
		occurrenceCreate.SetID(*isOccurrenceID)
	} else if src != nil {
		var sourceID uuid.UUID
		if src.SourceNameID != nil {
			var err error
			srcNameGlobalID := fromGlobalID(*src.SourceNameID)
			sourceID, err = uuid.Parse(srcNameGlobalID.id)
			if err != nil {
				return nil, nil, fmt.Errorf("uuid conversion from SourceNameID failed with error: %w", err)
			}
		} else {
			srcID, err := getSourceNameID(ctx, tx.Client(), *src.SourceInput)
			if err != nil {
				return nil, nil, err
			}
			sourceID = srcID
		}
		occurrenceCreate.SetSourceID(sourceID)

		var err error
		isOccurrenceID, err = guacOccurrenceKey(nil, ptrfrom.String(sourceID.String()), ptrfrom.String(artID.String()), *occur)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create occurrence uuid with error: %w", err)
		}
		occurrenceCreate.SetID(*isOccurrenceID)
	} else {
		return nil, nil, gqlerror.Errorf("%v :: %s", "generateOccurrenceCreate", "subject must be either a package or source")
	}

	return occurrenceCreate, isOccurrenceID, nil
}

func (b *EntBackend) IngestOccurrence(ctx context.Context,
	subject model.PackageOrSourceInput,
	art model.IDorArtifactInput,
	spec model.IsOccurrenceInputSpec,
) (string, error) {
	funcName := "IngestOccurrence"

	recordID, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)

		occurrenceConflictColumns := []string{
			occurrence.FieldArtifactID,
			occurrence.FieldJustification,
			occurrence.FieldOrigin,
			occurrence.FieldCollector,
		}

		var conflictWhere *sql.Predicate

		if subject.Package != nil {
			occurrenceConflictColumns = append(occurrenceConflictColumns, occurrence.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(occurrence.FieldPackageID),
				sql.IsNull(occurrence.FieldSourceID),
			)
		} else if subject.Source != nil {
			occurrenceConflictColumns = append(occurrenceConflictColumns, occurrence.FieldSourceID)
			conflictWhere = sql.And(
				sql.IsNull(occurrence.FieldPackageID),
				sql.NotNull(occurrence.FieldSourceID),
			)
		} else {
			return nil, gqlerror.Errorf("%v :: %s", funcName, "subject must be either a package or source")
		}

		insert, _, err := generateOccurrenceCreate(ctx, tx, subject.Package, subject.Source, &art, &spec)
		if err != nil {
			return nil, gqlerror.Errorf("generateDependencyCreate :: %s", err)
		}

		if id, err := insert.
			OnConflict(
				sql.ConflictColumns(occurrenceConflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			Ignore().
			ID(ctx); err != nil {
			return nil, errors.Wrap(err, "upsert isOccurrence node")
		} else {
			return ptrfrom.String(id.String()), nil
		}
	})
	if txErr != nil {
		return "", gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return toGlobalID(occurrence.Table, *recordID), nil
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

func canonicalOccurrenceString(occur model.IsOccurrenceInputSpec) string {
	return fmt.Sprintf("%s::%s::%s", occur.Justification, occur.Origin, occur.Collector)
}

func guacOccurrenceKey(pkgVersionID *string, srcNameID *string, artID *string, occur model.IsOccurrenceInputSpec) (*uuid.UUID, error) {
	var subjectID string
	if pkgVersionID != nil {
		subjectID = *pkgVersionID
	} else if srcNameID != nil {
		subjectID = *srcNameID
	} else {
		return nil, gqlerror.Errorf("%v :: %s", "guacOccurrenceKey", "subject must be either a package or source")
	}

	if artID == nil {
		return nil, gqlerror.Errorf("%v :: %s", "guacOccurrenceKey", "artifact must be specified")
	}

	occurIDString := fmt.Sprintf("%s::%s::%s?", subjectID, *artID, canonicalOccurrenceString(occur))

	occurID := generateUUIDKey([]byte(occurIDString))
	return &occurID, nil
}
