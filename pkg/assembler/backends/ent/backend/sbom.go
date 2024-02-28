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
		tx := ent.TxFromContext(ctx)

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

		if subject.Package != nil {
			conflictColumns = append(conflictColumns, billofmaterials.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(billofmaterials.FieldPackageID),
				sql.IsNull(billofmaterials.FieldArtifactID),
			)
		} else if subject.Artifact != nil {
			conflictColumns = append(conflictColumns, billofmaterials.FieldArtifactID)
			conflictWhere = sql.And(
				sql.IsNull(billofmaterials.FieldPackageID),
				sql.NotNull(billofmaterials.FieldArtifactID),
			)
		} else {
			return nil, Errorf("%v :: %s", funcName, "subject must be either a package or artifact")
		}

		sbomCreate, err := generateSBOMCreate(ctx, tx, subject.Package, subject.Artifact, &includes, &spec)
		if err != nil {
			return nil, gqlerror.Errorf("generateSBOMCreate :: %s", err)
		}
		if id, err := sbomCreate.
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			Ignore().
			ID(ctx); err != nil {
			return nil, errors.Wrap(err, "upsert hasSBOM node")
		} else {
			return ptrfrom.String(id.String()), nil
		}
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

func generateSBOMCreate(ctx context.Context, tx *ent.Tx, pkg *model.IDorPkgInput, art *model.IDorArtifactInput, includes *model.HasSBOMIncludesInputSpec, hasSBOM *model.HasSBOMInputSpec) (*ent.BillOfMaterialsCreate, error) {

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

	if len(sortedPkgIDs) > 0 {
		for _, pkgID := range sortedPkgIDs {
			pkgIncludesID, err := uuid.Parse(pkgID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
			sbomCreate.AddIncludedSoftwarePackageIDs(pkgIncludesID)
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
			sbomCreate.AddIncludedSoftwareArtifactIDs(artIncludesID)
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
			sbomCreate.AddIncludedDependencyIDs(isDepIncludesID)
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
			sbomCreate.AddIncludedOccurrenceIDs(isOccurIncludesID)
		}
		sortedOccurHash = hashListOfSortedKeys(sortedOccurrenceIDs)
		sbomCreate.SetIncludedOccurrencesHash(sortedOccurHash)
	} else {
		sortedOccurHash = hashListOfSortedKeys([]string{""})
		sbomCreate.SetIncludedOccurrencesHash(sortedOccurHash)
	}

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
		sbomCreate.SetID(*hasSBOMID)
		sbomCreate.SetArtifactID(artID)
	} else {
		return nil, Errorf("%v :: %s", "generateSBOMCreate", "subject must be either a package or artifact")
	}

	return sbomCreate, nil
}

func upsertBulkHasSBOM(ctx context.Context, tx *ent.Tx, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) (*[]string, error) {
	ids := make([]string, 0)

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
			hsbom := hsbom
			var err error
			if len(subjects.Packages) > 0 {
				creates[i], err = generateSBOMCreate(ctx, tx, subjects.Packages[index], nil, includes[index], hsbom)
				if err != nil {
					return nil, gqlerror.Errorf("generateSBOMCreate :: %s", err)
				}
			} else if len(subjects.Artifacts) > 0 {
				creates[i], err = generateSBOMCreate(ctx, tx, nil, subjects.Artifacts[index], includes[index], hsbom)
				if err != nil {
					return nil, gqlerror.Errorf("generateSBOMCreate :: %s", err)
				}
			}
			index++
		}

		err := tx.BillOfMaterials.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			Ignore().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert hasSBOM node")
		}
	}

	return &ids, nil
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

	hsID := uuid.NewHash(sha256.New(), uuid.NameSpaceDNS, []byte(hsIDString), 5)
	return &hsID, nil
}
