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

	sbomId, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)

		id, err := upsertHasSBOM(ctx, tx, subject.Package, subject.Artifact, &includes, &spec)
		if err != nil {
			return nil, gqlerror.Errorf("generateSBOMCreate :: %s", err)
		}
		return id, nil
	})
	if txErr != nil {
		return "", Errorf("%v :: %s", funcName, txErr)
	}

	return *sbomId, nil
}

func (b *EntBackend) IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) ([]string, error) {
	var modelHasSboms []string
	for i, hasSbom := range hasSBOMs {
		var subject model.PackageOrArtifactInput
		if len(subjects.Artifacts) > 0 {
			subject = model.PackageOrArtifactInput{Artifact: subjects.Artifacts[i]}
		} else {
			subject = model.PackageOrArtifactInput{Package: subjects.Packages[i]}
		}
		modelHasSbom, err := b.IngestHasSbom(ctx, subject, *hasSbom, *includes[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestHasSBOMs failed with err: %v", err)
		}
		modelHasSboms = append(modelHasSboms, modelHasSbom)
	}
	return modelHasSboms, nil
}

func upsertHasSBOM(ctx context.Context, tx *ent.Tx, pkg *model.IDorPkgInput, art *model.IDorArtifactInput, includes *model.HasSBOMIncludesInputSpec, hasSBOM *model.HasSBOMInputSpec) (*string, error) {

	// If a new column is included in the conflict columns, it must be added to the Indexes() function in the schema
	conflictColumns := []string{
		billofmaterials.FieldURI,
		billofmaterials.FieldAlgorithm,
		billofmaterials.FieldDigest,
		billofmaterials.FieldDownloadLocation,
		billofmaterials.FieldKnownSince,
		billofmaterials.FieldIncludedPackagesHash,
		billofmaterials.FieldIncludedArtifactsHash,
		billofmaterials.FieldIncludedDependenciesHash,
		billofmaterials.FieldIncludedOccurrencesHash,
	}

	var conflictWhere *sql.Predicate

	if pkg != nil {
		conflictColumns = append(conflictColumns, billofmaterials.FieldPackageID)
		conflictWhere = sql.And(
			sql.NotNull(billofmaterials.FieldPackageID),
			sql.IsNull(billofmaterials.FieldArtifactID),
		)
	} else if art != nil {
		conflictColumns = append(conflictColumns, billofmaterials.FieldArtifactID)
		conflictWhere = sql.And(
			sql.IsNull(billofmaterials.FieldPackageID),
			sql.NotNull(billofmaterials.FieldArtifactID),
		)
	} else {
		return nil, Errorf("%v :: %s", "upsertHasSBOM", "subject must be either a package or artifact")
	}

	sbomCreate := tx.BillOfMaterials.Create().
		SetURI(hasSBOM.URI).
		SetAlgorithm(strings.ToLower(hasSBOM.Algorithm)).
		SetDigest(strings.ToLower(hasSBOM.Digest)).
		SetDownloadLocation(hasSBOM.DownloadLocation).
		SetOrigin(hasSBOM.Origin).
		SetCollector(hasSBOM.Collector).
		SetKnownSince(hasSBOM.KnownSince.UTC())

	sortedPkgIDs := helper.SortAndRemoveDups(includes.Packages)
	sortedArtIDs := helper.SortAndRemoveDups(includes.Artifacts)
	sortedDependencyIDs := helper.SortAndRemoveDups(includes.Dependencies)
	sortedOccurrenceIDs := helper.SortAndRemoveDups(includes.Occurrences)
	var sortedPkgHash string
	var sortedArtHash string
	var sortedDepHash string
	var sortedOccurHash string

	var sortedPkgUUIDs []uuid.UUID
	var sortedArtUUIDs []uuid.UUID
	var sortedIsDepUUIDs []uuid.UUID
	var sortedIsOccurrenceUUIDs []uuid.UUID

	if len(sortedPkgIDs) > 0 {
		for _, pkgID := range sortedPkgIDs {
			pkgIncludesID, err := uuid.Parse(pkgID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
			sortedPkgUUIDs = append(sortedPkgUUIDs, pkgIncludesID)
		}
		sortedPkgHash = hashListOfSortedKeys(sortedPkgIDs)
		sbomCreate.SetIncludedPackagesHash(sortedPkgHash)
	} else {
		sortedPkgHash = hashListOfSortedKeys([]string{""})
		sbomCreate.SetIncludedPackagesHash(sortedPkgHash)
	}

	if len(sortedArtIDs) > 0 {
		for _, artID := range sortedArtIDs {
			artIncludesID, err := uuid.Parse(artID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
			}
			sortedArtUUIDs = append(sortedArtUUIDs, artIncludesID)
		}

		sortedArtHash = hashListOfSortedKeys(sortedArtIDs)
		sbomCreate.SetIncludedArtifactsHash(sortedArtHash)
	} else {
		sortedArtHash = hashListOfSortedKeys([]string{""})
		sbomCreate.SetIncludedArtifactsHash(sortedArtHash)
	}

	if len(sortedDependencyIDs) > 0 {
		for _, isDependencyID := range sortedDependencyIDs {
			isDepIncludesID, err := uuid.Parse(isDependencyID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from isDependencyID failed with error: %w", err)
			}
			sortedIsDepUUIDs = append(sortedIsDepUUIDs, isDepIncludesID)
		}

		sortedDepHash = hashListOfSortedKeys(sortedDependencyIDs)
		sbomCreate.SetIncludedDependenciesHash(sortedDepHash)
	} else {
		sortedDepHash = hashListOfSortedKeys([]string{""})
		sbomCreate.SetIncludedDependenciesHash(sortedDepHash)
	}

	if len(sortedOccurrenceIDs) > 0 {
		for _, isOccurrenceID := range sortedOccurrenceIDs {
			isOccurIncludesID, err := uuid.Parse(isOccurrenceID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from isOccurrenceID failed with error: %w", err)
			}
			sortedIsOccurrenceUUIDs = append(sortedIsOccurrenceUUIDs, isOccurIncludesID)
		}

		sortedOccurHash = hashListOfSortedKeys(sortedOccurrenceIDs)
		sbomCreate.SetIncludedOccurrencesHash(sortedOccurHash)
	} else {
		sortedOccurHash = hashListOfSortedKeys([]string{""})
		sbomCreate.SetIncludedOccurrencesHash(sortedOccurHash)
	}

	var createdHasSBOMID uuid.UUID

	if pkg != nil {
		var pkgVersionID uuid.UUID
		if pkg.PackageVersionID != nil {
			var err error
			pkgVersionID, err = uuid.Parse(*pkg.PackageVersionID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
		} else {
			pv, err := getPkgVersion(ctx, tx.Client(), *pkg.PackageInput)
			if err != nil {
				return nil, fmt.Errorf("getPkgVersion :: %w", err)
			}
			pkgVersionID = pv.ID
		}
		hasSBOMID, err := guacHasSBOMKey(ptrfrom.String(pkgVersionID.String()), nil, sortedPkgHash, sortedArtHash, sortedDepHash, sortedOccurHash, hasSBOM)
		if err != nil {
			return nil, fmt.Errorf("failed to create hasSBOM uuid with error: %w", err)
		}
		createdHasSBOMID = *hasSBOMID
		sbomCreate.SetID(*hasSBOMID)
		sbomCreate.SetPackageID(pkgVersionID)
	} else if art != nil {
		var artID uuid.UUID
		if art.ArtifactID != nil {
			var err error
			artID, err = uuid.Parse(*art.ArtifactID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
			}
		} else {
			foundArt, err := tx.Artifact.Query().Where(artifactQueryInputPredicates(*art.ArtifactInput)).Only(ctx)
			if err != nil {
				return nil, err
			}
			artID = foundArt.ID
		}
		hasSBOMID, err := guacHasSBOMKey(nil, ptrfrom.String(artID.String()), sortedPkgHash, sortedArtHash, sortedDepHash, sortedOccurHash, hasSBOM)
		if err != nil {
			return nil, fmt.Errorf("failed to create hasSBOM uuid with error: %w", err)
		}
		createdHasSBOMID = *hasSBOMID
		sbomCreate.SetID(*hasSBOMID)
		sbomCreate.SetArtifactID(artID)
	} else {
		return nil, Errorf("%v :: %s", "generateSBOMCreate", "subject must be either a package or artifact")
	}

	_, err := sbomCreate.
		OnConflict(
			sql.ConflictColumns(conflictColumns...),
			sql.ConflictWhere(conflictWhere),
		).
		DoNothing().
		ID(ctx)
	if err != nil {
		// err "no rows in select set" appear when ingesting and the node already exists. This is non-error produced by "DoNothing"
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert hasSBOM node")
		}
	}

	if err := updateHasSBOMWithIncludePackageIDs(ctx, tx.Client(), createdHasSBOMID, sortedPkgUUIDs); err != nil {
		return nil, errors.Wrap(err, "updateHasSBOMWithIncludePackageIDs")
	}

	if err := updateHasSBOMWithIncludeArtifacts(ctx, tx.Client(), createdHasSBOMID, sortedArtUUIDs); err != nil {
		return nil, errors.Wrap(err, "updateHasSBOMWithIncludeArtifacts")
	}

	if err := updateHasSBOMWithIncludeDependencies(ctx, tx.Client(), createdHasSBOMID, sortedIsDepUUIDs); err != nil {
		return nil, errors.Wrap(err, "updateHasSBOMWithIncludeDependencies")
	}

	if err := updateHasSBOMWithIncludeOccurrences(ctx, tx.Client(), createdHasSBOMID, sortedIsOccurrenceUUIDs); err != nil {
		return nil, errors.Wrap(err, "updateHasSBOMWithIncludeOccurrences")
	}

	return ptrfrom.String(createdHasSBOMID.String()), nil
}

func updateHasSBOMWithIncludePackageIDs(ctx context.Context, client *ent.Client, hasSBOMID uuid.UUID, sortedPkgUUIDs []uuid.UUID) error {
	batches := chunk(sortedPkgUUIDs, 10000)

	for _, batchedPkgUUIDs := range batches {
		err := client.BillOfMaterials.
			UpdateOneID(hasSBOMID).
			AddIncludedSoftwarePackageIDs(batchedPkgUUIDs...).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("update for IncludedSoftwarePackageIDs hasSBOM node failed with error: %w", err)
		}
	}
	return nil
}

func updateHasSBOMWithIncludeArtifacts(ctx context.Context, client *ent.Client, hasSBOMID uuid.UUID, sortedArtUUIDs []uuid.UUID) error {
	batches := chunk(sortedArtUUIDs, 10000)

	for _, batchedArtUUIDs := range batches {
		err := client.BillOfMaterials.
			UpdateOneID(hasSBOMID).
			AddIncludedSoftwareArtifactIDs(batchedArtUUIDs...).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("update for IncludedSoftwareArtifactIDs hasSBOM node failed with error: %w", err)
		}
	}
	return nil
}

func updateHasSBOMWithIncludeDependencies(ctx context.Context, client *ent.Client, hasSBOMID uuid.UUID, sortedIsDepUUIDs []uuid.UUID) error {
	batches := chunk(sortedIsDepUUIDs, 10000)

	for _, batchedIsDepUUIDs := range batches {
		err := client.BillOfMaterials.
			UpdateOneID(hasSBOMID).
			AddIncludedDependencyIDs(batchedIsDepUUIDs...).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("update for IncludedDependencyIDs hasSBOM node failed with error: %w", err)
		}
	}
	return nil
}

func updateHasSBOMWithIncludeOccurrences(ctx context.Context, client *ent.Client, hasSBOMID uuid.UUID, sortedIsOccurrenceUUIDs []uuid.UUID) error {
	batches := chunk(sortedIsOccurrenceUUIDs, 10000)

	for _, batchedIsOccurUUIDs := range batches {
		err := client.BillOfMaterials.
			UpdateOneID(hasSBOMID).
			AddIncludedOccurrenceIDs(batchedIsOccurUUIDs...).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("update for IncludedOccurrenceIDs hasSBOM node failed with error: %w", err)
		}
	}
	return nil
}

func canonicalHasSBOMString(hasSBOM *model.HasSBOMInputSpec) string {
	return fmt.Sprintf("%s::%s::%s::%s::%s::%s::%s", hasSBOM.URI, hasSBOM.Algorithm, hasSBOM.Digest, hasSBOM.DownloadLocation, hasSBOM.Origin, hasSBOM.Collector, hasSBOM.KnownSince.UTC())
}

// guacHasSBOMKey generates an uuid based on the hash of the inputspec and inputs. hasSBOM ID has to be set for bulk ingestion
// when ingesting multiple edges otherwise you get "violates foreign key constraint" as it creates
// a new ID for hasSBOM node (even when already ingested) that it maps to the edge and fails the look up. This only occurs when using UUID with
// "Default" func to generate a new UUID
func guacHasSBOMKey(pkgVersionID *string, artID *string, includedPkgHash, includedArtHash, includedDepHash, includedOccurHash string,
	hasSBOM *model.HasSBOMInputSpec) (*uuid.UUID, error) {

	var subjectID string
	if pkgVersionID != nil {
		subjectID = *pkgVersionID
	} else if artID != nil {
		subjectID = *artID
	} else {
		return nil, gqlerror.Errorf("%v :: %s", "guacHasSBOMKey", "subject must be either a package or artifact")
	}
	hsIDString := fmt.Sprintf("%s::%s::%s::%s::%s::%s?", subjectID, includedPkgHash, includedArtHash, includedDepHash, includedOccurHash, canonicalHasSBOMString(hasSBOM))

	hsID := generateUUIDKey([]byte(hsIDString))
	return &hsID, nil
}
