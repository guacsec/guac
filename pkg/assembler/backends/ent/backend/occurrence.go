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
	"crypto/sha256"
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

	batches := chunk(occurrences, 100)

	index := 0
	for _, occurs := range batches {
		creates := make([]*ent.OccurrenceCreate, len(occurs))
		for i, occur := range occurs {
			occur := occur
			switch {
			case len(subjects.Packages) > 0:
				var err error
				isOccurrenceID, err := guacOccurrenceKey(subjects.Packages[index], nil, *artifacts[index], *occur)
				if err != nil {
					return nil, fmt.Errorf("failed to create isDependency uuid with error: %w", err)
				}
				creates[i], err = generateOccurrenceCreate(tx, isOccurrenceID, subjects.Packages[index], nil, artifacts[index], occur)
				if err != nil {
					return nil, gqlerror.Errorf("generateDependencyCreate :: %s", err)
				}
				ids = append(ids, isOccurrenceID.String())

			case len(subjects.Sources) > 0:
				var err error
				isOccurrenceID, err := guacOccurrenceKey(nil, subjects.Sources[index], *artifacts[index], *occur)
				if err != nil {
					return nil, fmt.Errorf("failed to create isDependency uuid with error: %w", err)
				}
				creates[i], err = generateOccurrenceCreate(tx, isOccurrenceID, nil, subjects.Sources[index], artifacts[index], occur)
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
			return nil, err
		}
	}

	return &ids, nil
}

func generateOccurrenceCreate(tx *ent.Tx, isOccurrenceID *uuid.UUID, pkg *model.IDorPkgInput, src *model.IDorSourceInput, art *model.IDorArtifactInput, occur *model.IsOccurrenceInputSpec) (*ent.OccurrenceCreate, error) {

	occurrenceCreate := tx.Occurrence.Create()

	if art == nil {
		return nil, fmt.Errorf("artifact must be specified for isOccurrence")

	}
	if art.ArtifactID == nil {
		return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
	}
	artID, err := uuid.Parse(*art.ArtifactID)
	if err != nil {
		return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
	}

	occurrenceCreate.
		SetID(*isOccurrenceID).
		SetArtifactID(artID).
		SetJustification(occur.Justification).
		SetOrigin(occur.Origin).
		SetCollector(occur.Collector)

	if pkg != nil {
		if pkg.PackageVersionID == nil {
			return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
		}
		pkgVersionID, err := uuid.Parse(*pkg.PackageVersionID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
		}
		occurrenceCreate.SetPackageID(pkgVersionID)
	} else if src != nil {
		if src.SourceNameID == nil {
			return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
		}
		sourceID, err := uuid.Parse(*src.SourceNameID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from SourceNameID failed with error: %w", err)
		}
		occurrenceCreate.SetSourceID(sourceID)
	} else {
		return nil, gqlerror.Errorf("%v :: %s", "generateOccurrenceCreate", "subject must be either a package or source")
	}

	return occurrenceCreate, nil
}

func (b *EntBackend) IngestOccurrence(ctx context.Context,
	subject model.PackageOrSourceInput,
	art model.IDorArtifactInput,
	spec model.IsOccurrenceInputSpec,
) (string, error) {
	funcName := "IngestOccurrence"

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
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

		isOccurrenceID, err := guacOccurrenceKey(subject.Package, subject.Source, art, spec)
		if err != nil {
			return nil, fmt.Errorf("failed to create isDependency uuid with error: %w", err)
		}

		insert, err := generateOccurrenceCreate(tx, isOccurrenceID, subject.Package, subject.Source, &art, &spec)
		if err != nil {
			return nil, gqlerror.Errorf("generateDependencyCreate :: %s", err)
		}

		if _, err := insert.
			OnConflict(
				sql.ConflictColumns(occurrenceConflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			ID(ctx); err != nil {
			return nil, err
		}

		return ptrfrom.String(isOccurrenceID.String()), nil
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

func canonicalOccurrenceString(occur model.IsOccurrenceInputSpec) string {
	return fmt.Sprintf("%s::%s::%s", occur.Justification, occur.Origin, occur.Collector)
}

func guacOccurrenceKey(pkg *model.IDorPkgInput, src *model.IDorSourceInput, art model.IDorArtifactInput, occur model.IsOccurrenceInputSpec) (*uuid.UUID, error) {
	var subjectID string
	if pkg != nil {
		if pkg.PackageVersionID == nil {
			return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
		}
		subjectID = *pkg.PackageVersionID
	} else if src != nil {
		if src.SourceNameID == nil {
			return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
		}
		subjectID = *src.SourceNameID
	} else {
		return nil, gqlerror.Errorf("%v :: %s", "guacOccurrenceKey", "subject must be either a package or source")
	}

	occurIDString := fmt.Sprintf("%s::%s::%s?", subjectID, *art.ArtifactID, canonicalOccurrenceString(occur))

	occurID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(occurIDString), 5)
	return &occurID, nil
}
