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
	stdsql "database/sql"
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
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

	for i := range spec.IncludedSoftware {
		if spec.IncludedSoftware[i].Package != nil {
			predicates = append(predicates, billofmaterials.HasIncludedSoftwarePackagesWith(packageVersionQuery(spec.IncludedSoftware[i].Package)))
		} else {
			predicates = append(predicates, billofmaterials.HasIncludedSoftwareArtifactsWith(artifactQueryPredicates(spec.IncludedSoftware[i].Artifact)))
		}
	}
	for i := range spec.IncludedDependencies {
		predicates = append(predicates, billofmaterials.HasIncludedDependenciesWith(isDependencyQuery(spec.IncludedDependencies[i])))
	}
	for i := range spec.IncludedOccurrences {
		predicates = append(predicates, billofmaterials.HasIncludedOccurrencesWith(isOccurrenceQuery(spec.IncludedOccurrences[i])))
	}

	records, err := b.client.BillOfMaterials.Query().
		Where(predicates...).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
		}).
		WithArtifact().
		WithIncludedSoftwareArtifacts().
		WithIncludedSoftwarePackages(withPackageVersionTree()).
		WithIncludedDependencies(func(q *ent.DependencyQuery) {
			q.WithPackage(withPackageVersionTree()).
				WithDependentPackageName(withPackageNameTree()).
				WithDependentPackageVersion(withPackageVersionTree())
		}).
		WithIncludedOccurrences(func(q *ent.OccurrenceQuery) {
			q.WithArtifact().
				WithPackage(withPackageVersionTree()).
				WithSource(withSourceNameTreeQuery())
		}).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, errors.Wrap(err, funcName)
	}

	return collect(records, toModelHasSBOM), nil
}

func (b *EntBackend) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, spec model.HasSBOMInputSpec, includes model.HasSBOMIncludesInputSpec) (string, error) {
	funcName := "IngestHasSbom"

	sbomId, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
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
			if subject.Package.PackageVersionID == nil {
				return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
			}
			pkgVersionID, err := uuid.Parse(*subject.Package.PackageVersionID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
			sbomCreate.SetPackageID(pkgVersionID)
			conflictColumns = append(conflictColumns, billofmaterials.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(billofmaterials.FieldPackageID),
				sql.IsNull(billofmaterials.FieldArtifactID),
			)
		} else if subject.Artifact != nil {
			if subject.Artifact.ArtifactID == nil {
				return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
			}
			artID, err := uuid.Parse(*subject.Artifact.ArtifactID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
			}
			sbomCreate.SetArtifactID(artID)
			conflictColumns = append(conflictColumns, billofmaterials.FieldArtifactID)
			conflictWhere = sql.And(
				sql.IsNull(billofmaterials.FieldPackageID),
				sql.NotNull(billofmaterials.FieldArtifactID),
			)
		} else {
			return nil, Errorf("%v :: %s", funcName, "subject must be either a package or artifact")
		}

		sortedPkgIDs := helper.SortAndRemoveDups(includes.Packages)
		sortedArtIDs := helper.SortAndRemoveDups(includes.Artifacts)
		sortedDependencyIDs := helper.SortAndRemoveDups(includes.Dependencies)
		sortedOccurrenceIDs := helper.SortAndRemoveDups(includes.Occurrences)

		for _, pkgID := range sortedPkgIDs {
			pkgIncludesID, err := uuid.Parse(pkgID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
			sbomCreate.AddIncludedSoftwarePackageIDs(pkgIncludesID)
		}

		for _, artID := range sortedArtIDs {
			artIncludesID, err := uuid.Parse(artID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
			}
			sbomCreate.AddIncludedSoftwareArtifactIDs(artIncludesID)
		}

		for _, isDependencyID := range sortedDependencyIDs {
			isDepIncludesID, err := uuid.Parse(isDependencyID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from isDependencyID failed with error: %w", err)
			}
			sbomCreate.AddIncludedDependencyIDs(isDepIncludesID)
		}

		for _, isOccurrenceID := range sortedOccurrenceIDs {
			isOccurIncludesID, err := uuid.Parse(isOccurrenceID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from isOccurrenceID failed with error: %w", err)
			}
			sbomCreate.AddIncludedOccurrenceIDs(isOccurIncludesID)
		}

		_, err := sbomCreate.
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			ID(ctx)
		if err != nil {
			if err != stdsql.ErrNoRows {
				return nil, errors.Wrap(err, "IngestHasSbom")
			}
		}
		return ptrfrom.String(""), nil
	})
	if err != nil {
		return "", Errorf("%v :: %s", funcName, err)
	}

	return *sbomId, nil
}

func (b *EntBackend) IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) ([]string, error) {
	funcName := "IngestHasSBOMs"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkHasSBOM(ctx, client, subjects, hasSBOMs, includes)
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

func upsertBulkHasSBOM(ctx context.Context, client *ent.Tx, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		billofmaterials.FieldURI,
		billofmaterials.FieldAlgorithm,
		billofmaterials.FieldDigest,
		billofmaterials.FieldDownloadLocation,
		billofmaterials.FieldKnownSince,
	}

	var conflictWhere *sql.Predicate

	switch {
	case len(subjects.Packages) > 0:
		conflictColumns = append(conflictColumns, billofmaterials.FieldPackageID)
		conflictWhere = sql.And(
			sql.NotNull(billofmaterials.FieldPackageID),
			sql.IsNull(billofmaterials.FieldArtifactID),
		)
	case len(subjects.Artifacts) > 0:
		conflictColumns = append(conflictColumns, billofmaterials.FieldArtifactID)
		conflictWhere = sql.And(
			sql.IsNull(billofmaterials.FieldPackageID),
			sql.NotNull(billofmaterials.FieldArtifactID),
		)
	}

	batches := chunk(hasSBOMs, 100)

	index := 0
	for _, hsboms := range batches {
		creates := make([]*ent.BillOfMaterialsCreate, len(hsboms))
		for i, hsbom := range hsboms {

			creates[i] = client.BillOfMaterials.Create().
				SetURI(hsbom.URI).
				SetAlgorithm(strings.ToLower(hsbom.Algorithm)).
				SetDigest(strings.ToLower(hsbom.Digest)).
				SetDownloadLocation(hsbom.DownloadLocation).
				SetOrigin(hsbom.Origin).
				SetCollector(hsbom.Collector).
				SetKnownSince(hsbom.KnownSince.UTC())

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
			case len(subjects.Artifacts) > 0:
				if subjects.Artifacts[index].ArtifactID == nil {
					return nil, fmt.Errorf("ArtifactID not specified in IDorArtifactInput")
				}
				artID, err := uuid.Parse(*subjects.Artifacts[index].ArtifactID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
				}
				creates[i].SetArtifactID(artID)
			}

			sortedPkgIDs := helper.SortAndRemoveDups(includes[index].Packages)
			sortedArtIDs := helper.SortAndRemoveDups(includes[index].Artifacts)
			sortedDependencyIDs := helper.SortAndRemoveDups(includes[index].Dependencies)
			sortedOccurrenceIDs := helper.SortAndRemoveDups(includes[index].Occurrences)

			for _, pkgID := range sortedPkgIDs {
				pkgIncludesID, err := uuid.Parse(pkgID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
				}
				creates[i].AddIncludedSoftwarePackageIDs(pkgIncludesID)
			}

			for _, artID := range sortedArtIDs {
				artIncludesID, err := uuid.Parse(artID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
				}
				creates[i].AddIncludedSoftwareArtifactIDs(artIncludesID)
			}

			for _, isDependencyID := range sortedDependencyIDs {
				isDepIncludesID, err := uuid.Parse(isDependencyID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from isDependencyID failed with error: %w", err)
				}
				creates[i].AddIncludedDependencyIDs(isDepIncludesID)
			}

			for _, isOccurrenceID := range sortedOccurrenceIDs {
				isOccurIncludesID, err := uuid.Parse(isOccurrenceID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from isOccurrenceID failed with error: %w", err)
				}
				creates[i].AddIncludedOccurrenceIDs(isOccurIncludesID)
			}

			index++
		}

		err := client.BillOfMaterials.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
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
