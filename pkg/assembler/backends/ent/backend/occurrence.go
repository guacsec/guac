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

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IsOccurrence(ctx context.Context, query *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {

	predicates := []predicate.Occurrence{
		optionalPredicate(query.ID, IDEQ),
		optionalPredicate(query.Justification, occurrence.JustificationEQ),
		optionalPredicate(query.Origin, occurrence.OriginEQ),
		optionalPredicate(query.Collector, occurrence.CollectorEQ),
	}

	if query.Artifact != nil {
		predicates = append(predicates,
			occurrence.HasArtifactWith(func(s *sql.Selector) {
				if query.Artifact != nil {
					optionalPredicate(query.Artifact.Digest, artifact.DigestEQ)(s)
					optionalPredicate(query.Artifact.Algorithm, artifact.AlgorithmEQ)(s)
					optionalPredicate(query.Artifact.ID, IDEQ)(s)
				}
			}),
		)
	}

	if query.Subject != nil {
		if query.Subject.Package != nil {
			predicates = append(predicates,
				occurrence.HasPackageWith(
					packageversion.VersionEQ(*query.Subject.Package.Version),
				),
			)
		} else if query.Subject.Source != nil {
			predicates = append(predicates,
				occurrence.HasSourceWith(
					optionalPredicate(query.Subject.Source.Name, sourcename.NameEQ),
					optionalPredicate(query.Subject.Source.Commit, sourcename.CommitEQ),
					optionalPredicate(query.Subject.Source.Tag, sourcename.TagEQ),
				),
			)
		}
	}

	records, err := b.client.Occurrence.Query().
		Where(predicates...).
		WithArtifact().
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {
				q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
					q.WithPackage()
				})
			})
		}).
		WithSource(func(q *ent.SourceNameQuery) {
			q.WithNamespace(func(q *ent.SourceNamespaceQuery) {
				q.WithSourceType()
			})
		}).
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

func (b *EntBackend) IngestOccurrences(ctx context.Context, subjects model.PackageOrSourceInputs, artifacts []*model.ArtifactInputSpec, occurrences []*model.IsOccurrenceInputSpec) ([]*model.IsOccurrence, error) {
	var models []*model.IsOccurrence
	for i := range occurrences {
		var subject model.PackageOrSourceInput
		if len(subjects.Packages) > 0 {
			subject = model.PackageOrSourceInput{Package: subjects.Packages[i]}
		} else {
			subject = model.PackageOrSourceInput{Source: subjects.Sources[i]}
		}
		modelOccurrence, err := b.IngestOccurrence(ctx, subject, *artifacts[i], *occurrences[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestOccurrences failed with element #%v with err: %v", i, err)
		}
		models = append(models, modelOccurrence)
	}
	return models, nil
}

func (b *EntBackend) IngestOccurrence(ctx context.Context,
	subject model.PackageOrSourceInput,
	art model.ArtifactInputSpec,
	spec model.IsOccurrenceInputSpec,
) (*model.IsOccurrence, error) {
	funcName := "IngestOccurrence"

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		tx := ent.TxFromContext(ctx)
		client := tx.Client()
		var err error

		artRecord, err := client.Artifact.Query().
			Order(ent.Asc(artifact.FieldID)). // is order important here?
			Where(artifactQueryInputPredicates(art)).
			Only(ctx) // should already be ingested
		if err != nil {
			return nil, err
		}

		occurrenceCreate := client.Occurrence.Create().
			SetArtifact(artRecord).
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
			pkgVersion, err := getPkgVersion(ctx, client, *subject.Package)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get package version")
			}
			occurrenceCreate.SetPackage(pkgVersion)
			occurrenceConflictColumns = append(occurrenceConflictColumns, occurrence.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(occurrence.FieldPackageID),
				sql.IsNull(occurrence.FieldSourceID),
			)
		} else if subject.Source != nil {
			srcName, err := upsertSource(ctx, tx, *subject.Source)
			if err != nil {
				return nil, err
			}
			occurrenceCreate.SetSource(srcName)
			occurrenceConflictColumns = append(occurrenceConflictColumns, occurrence.FieldSourceID)
			conflictWhere = sql.And(
				sql.IsNull(occurrence.FieldPackageID),
				sql.NotNull(occurrence.FieldSourceID),
			)
		} else {
			return nil, gqlerror.Errorf("%v :: %s", funcName, "subject must be either a package or source")
		}

		id, err := occurrenceCreate.
			OnConflict(
				sql.ConflictColumns(occurrenceConflictColumns...),
				sql.ConflictWhere(conflictWhere),
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
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {
				q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
					q.WithPackage()
				})
			})
		}).
		WithSource(func(q *ent.SourceNameQuery) {
			q.WithNamespace(func(q *ent.SourceNamespaceQuery) {
				q.WithSourceType()
			})
		}).
		Only(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, err)
	}

	return toModelIsOccurrenceWithSubject(record), nil
}
