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
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) HasSBOM(ctx context.Context, spec *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	funcName := "HasSBOM"
	predicates := []predicate.BillOfMaterials{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(toLowerPtr(spec.Algorithm), billofmaterials.AlgorithmEQ),
		optionalPredicate(toLowerPtr(spec.Digest), billofmaterials.DigestEQ),
		optionalPredicate(spec.URI, billofmaterials.URI),
		optionalPredicate(spec.Collector, billofmaterials.CollectorEQ),
		optionalPredicate(spec.DownloadLocation, billofmaterials.DownloadLocationEQ),
		optionalPredicate(spec.Origin, billofmaterials.OriginEQ),
		optionalPredicate(spec.KnownSince, billofmaterials.KnownSinceEQ),
		// billofmaterials.AnnotationsMatchSpec(spec.Annotations),
	}

	if spec.Subject != nil {
		if spec.Subject.Package != nil {
			predicates = append(predicates, billofmaterials.HasPackageWith(packageVersionQuery(spec.Subject.Package)))
		} else if spec.Subject.Artifact != nil {
			predicates = append(predicates, billofmaterials.HasArtifactWith(artifactQueryPredicates(spec.Subject.Artifact)))
		}
	}

	records, err := b.client.BillOfMaterials.Query().
		Where(predicates...).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {
				q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
					q.WithPackage()
				})
			})
		}).
		WithArtifact().
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, funcName)
	}

	return collect(records, toModelHasSBOM), nil
}

func (b *EntBackend) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, spec model.HasSBOMInputSpec, includes model.HasSBOMIncludesInputSpec) (*model.HasSbom, error) {
	// TODO(knrc) - handle includes
	funcName := "IngestHasSbom"

	sbomId, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.TxFromContext(ctx)

		sbomCreate := client.BillOfMaterials.Create().
			SetURI(spec.URI).
			SetAlgorithm(strings.ToLower(spec.Algorithm)).
			SetDigest(strings.ToLower(spec.Digest)).
			SetDownloadLocation(spec.DownloadLocation).
			SetOrigin(spec.Origin).
			SetCollector(spec.Collector).
			SetKnownSince(spec.KnownSince.UTC())

		// If a new column is included in the conflict columns, it must be added to the Indexes() function in the schema
		conflictColumns := []string{
			billofmaterials.FieldURI,
			billofmaterials.FieldAlgorithm,
			billofmaterials.FieldDigest,
			billofmaterials.FieldDownloadLocation,
			billofmaterials.FieldKnownSince,
		}

		var conflictWhere *sql.Predicate

		if subject.Package != nil {
			var err error
			p, err := getPkgVersion(ctx, client.Client(), *subject.Package)
			if err != nil {
				return nil, Errorf("%v ::  %s", funcName, err)
			}
			sbomCreate.SetPackage(p)
			conflictColumns = append(conflictColumns, billofmaterials.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(billofmaterials.FieldPackageID),
				sql.IsNull(billofmaterials.FieldArtifactID),
			)
		} else if subject.Artifact != nil {
			var err error
			art, err := client.Artifact.Query().
				Where(artifactQueryInputPredicates(*subject.Artifact)).
				Only(ctx)
			if err != nil {
				return nil, Errorf("%v ::  %s", funcName, err)
			}
			sbomCreate.SetArtifact(art)
			conflictColumns = append(conflictColumns, billofmaterials.FieldArtifactID)
			conflictWhere = sql.And(
				sql.IsNull(billofmaterials.FieldPackageID),
				sql.NotNull(billofmaterials.FieldArtifactID),
			)
		} else {
			return nil, Errorf("%v :: %s", funcName, "subject must be either a package or artifact")
		}

		id, err := sbomCreate.
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			Ignore().
			ID(ctx)
		if err != nil {
			return nil, Errorf("%v ::  %s", funcName, err)
		}
		return &id, nil
	})
	if err != nil {
		return nil, Errorf("%v :: %s", funcName, err)
	}

	sbom, err := b.client.BillOfMaterials.Query().
		Where(billofmaterials.ID(*sbomId)).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {
				q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
					q.WithPackage()
				})
			})
		}).
		WithArtifact().
		Only(ctx)
	if err != nil {
		return nil, Errorf("%v :: %s", funcName, err)
	}
	return toModelHasSBOM(sbom), nil
}

func (b *EntBackend) IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) ([]*model.HasSbom, error) {
	var modelHasSboms []*model.HasSbom
	for i, hasSbom := range hasSBOMs {
		var subject model.PackageOrArtifactInput
		if len(subjects.Artifacts) > 0 {
			subject = model.PackageOrArtifactInput{Artifact: subjects.Artifacts[i]}
		} else {
			subject = model.PackageOrArtifactInput{Package: subjects.Packages[i]}
		}
		// TODO(knrc) - handle includes
		modelHasSbom, err := b.IngestHasSbom(ctx, subject, *hasSbom, model.HasSBOMIncludesInputSpec{})
		if err != nil {
			return nil, gqlerror.Errorf("IngestHasSBOMs failed with err: %v", err)
		}
		modelHasSboms = append(modelHasSboms, modelHasSbom)
	}
	return modelHasSboms, nil
}
