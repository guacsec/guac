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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hasmetadata"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) HasMetadata(ctx context.Context, filter *model.HasMetadataSpec) ([]*model.HasMetadata, error) {
	records, err := b.client.HasMetadata.Query().
		Where(hasMetadataPredicate(filter)).
		Limit(MaxPageSize).
		WithSource(withSourceNameTreeQuery()).
		WithArtifact().
		WithPackageVersion(withPackageVersionTree()).
		WithAllVersions(withPackageNameTree()).
		All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve HasMetadata :: %s", err)
	}

	return collect(records, toModelHasMetadata), nil
}

func (b *EntBackend) IngestHasMetadata(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, hasMetadata model.HasMetadataInputSpec) (string, error) {
	recordID, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertHasMetadata(ctx, ent.TxFromContext(ctx), subject, pkgMatchType, hasMetadata)
	})
	if txErr != nil {
		return "", fmt.Errorf("failed to execute IngestHasMetadata :: %s", txErr)
	}

	return *recordID, nil
}

func (b *EntBackend) IngestBulkHasMetadata(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, hasMetadataList []*model.HasMetadataInputSpec) ([]string, error) {
	funcName := "IngestBulkHasMetadata"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkHasMetadata(ctx, client, subjects, pkgMatchType, hasMetadataList)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return *ids, nil
}

func hasMetadataPredicate(filter *model.HasMetadataSpec) predicate.HasMetadata {
	predicates := []predicate.HasMetadata{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Since, hasmetadata.TimestampGTE),
		optionalPredicate(filter.Key, hasmetadata.KeyEQ),
		optionalPredicate(filter.Value, hasmetadata.ValueEQ),
		optionalPredicate(filter.Justification, hasmetadata.JustificationEQ),
		optionalPredicate(filter.Origin, hasmetadata.OriginEQ),
		optionalPredicate(filter.Collector, hasmetadata.CollectorEQ),
	}

	if filter.Subject != nil {
		switch {
		case filter.Subject.Artifact != nil:
			predicates = append(predicates, hasmetadata.HasArtifactWith(artifactQueryPredicates(filter.Subject.Artifact)))
		case filter.Subject.Package != nil:
			predicates = append(predicates, hasmetadata.Or(
				hasmetadata.HasAllVersionsWith(packageNameQuery(pkgNameQueryFromPkgSpec(filter.Subject.Package))),
				hasmetadata.HasPackageVersionWith(packageVersionQuery(filter.Subject.Package)),
			))
		case filter.Subject.Source != nil:
			predicates = append(predicates, hasmetadata.HasSourceWith(sourceQuery(filter.Subject.Source)))
		}
	}
	return hasmetadata.And(predicates...)
}

func upsertHasMetadata(ctx context.Context, tx *ent.Tx, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec model.HasMetadataInputSpec) (*string, error) {

	conflictColumns := []string{
		hasmetadata.FieldKey,
		hasmetadata.FieldValue,
		hasmetadata.FieldJustification,
		hasmetadata.FieldOrigin,
		hasmetadata.FieldCollector,
	}
	var conflictWhere *sql.Predicate

	switch {
	case subject.Artifact != nil:
		conflictColumns = append(conflictColumns, hasmetadata.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(hasmetadata.FieldArtifactID),
			sql.IsNull(hasmetadata.FieldPackageNameID),
			sql.IsNull(hasmetadata.FieldPackageVersionID),
			sql.IsNull(hasmetadata.FieldSourceID),
		)

	case subject.Package != nil:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			conflictColumns = append(conflictColumns, hasmetadata.FieldPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(hasmetadata.FieldArtifactID),
				sql.NotNull(hasmetadata.FieldPackageVersionID),
				sql.IsNull(hasmetadata.FieldPackageNameID),
				sql.IsNull(hasmetadata.FieldSourceID),
			)
		} else {
			conflictColumns = append(conflictColumns, hasmetadata.FieldPackageNameID)
			conflictWhere = sql.And(
				sql.IsNull(hasmetadata.FieldArtifactID),
				sql.IsNull(hasmetadata.FieldPackageVersionID),
				sql.NotNull(hasmetadata.FieldPackageNameID),
				sql.IsNull(hasmetadata.FieldSourceID),
			)
		}

	case subject.Source != nil:
		conflictColumns = append(conflictColumns, hasmetadata.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(hasmetadata.FieldArtifactID),
			sql.IsNull(hasmetadata.FieldPackageVersionID),
			sql.IsNull(hasmetadata.FieldPackageNameID),
			sql.NotNull(hasmetadata.FieldSourceID),
		)
	}

	insert, err := generateHasMetadataCreate(ctx, tx, subject.Package, subject.Source, subject.Artifact, pkgMatchType, &spec)
	if err != nil {
		return nil, gqlerror.Errorf("generateDependencyCreate :: %s", err)
	}

	if id, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
		sql.ConflictWhere(conflictWhere),
	).
		Ignore().
		ID(ctx); err != nil {
		return nil, errors.Wrap(err, "upsert HasMetadata node")

	} else {
		return ptrfrom.String(id.String()), nil
	}
}

func generateHasMetadataCreate(ctx context.Context, tx *ent.Tx, pkg *model.IDorPkgInput, src *model.IDorSourceInput, art *model.IDorArtifactInput, pkgMatchType *model.MatchFlags,
	hm *model.HasMetadataInputSpec) (*ent.HasMetadataCreate, error) {

	hasMetadataCreate := tx.HasMetadata.Create()

	hasMetadataCreate.
		SetKey(hm.Key).
		SetValue(hm.Value).
		SetTimestamp(hm.Timestamp.UTC()).
		SetJustification(hm.Justification).
		SetOrigin(hm.Origin).
		SetCollector(hm.Collector)

	switch {
	case art != nil:
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
		hasMetadataCreate.SetArtifactID(artID)
	case pkg != nil:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
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
			hasMetadataCreate.SetPackageVersionID(pkgVersionID)
		} else {
			var pkgNameID uuid.UUID
			if pkg.PackageNameID != nil {
				var err error
				pkgNameID, err = uuid.Parse(*pkg.PackageNameID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from PackageNameID failed with error: %w", err)
				}
			} else {
				pn, err := getPkgName(ctx, tx.Client(), *pkg.PackageInput)
				if err != nil {
					return nil, err
				}
				pkgNameID = pn.ID
			}
			hasMetadataCreate.SetAllVersionsID(pkgNameID)
		}
	case src != nil:
		var sourceID uuid.UUID
		if src.SourceNameID != nil {
			var err error
			sourceID, err = uuid.Parse(*src.SourceNameID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from SourceNameID failed with error: %w", err)
			}
		} else {
			srcID, err := getSourceNameID(ctx, tx.Client(), *src.SourceInput)
			if err != nil {
				return nil, err
			}
			sourceID = srcID
		}
		hasMetadataCreate.SetSourceID(sourceID)
	}
	return hasMetadataCreate, nil
}

func upsertBulkHasMetadata(ctx context.Context, tx *ent.Tx, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, hasMetadataList []*model.HasMetadataInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		hasmetadata.FieldKey,
		hasmetadata.FieldValue,
		hasmetadata.FieldJustification,
		hasmetadata.FieldOrigin,
		hasmetadata.FieldCollector,
	}
	var conflictWhere *sql.Predicate

	switch {
	case len(subjects.Artifacts) > 0:
		conflictColumns = append(conflictColumns, hasmetadata.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(hasmetadata.FieldArtifactID),
			sql.IsNull(hasmetadata.FieldPackageNameID),
			sql.IsNull(hasmetadata.FieldPackageVersionID),
			sql.IsNull(hasmetadata.FieldSourceID),
		)

	case len(subjects.Packages) > 0:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			conflictColumns = append(conflictColumns, hasmetadata.FieldPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(hasmetadata.FieldArtifactID),
				sql.NotNull(hasmetadata.FieldPackageVersionID),
				sql.IsNull(hasmetadata.FieldPackageNameID),
				sql.IsNull(hasmetadata.FieldSourceID),
			)
		} else {
			conflictColumns = append(conflictColumns, hasmetadata.FieldPackageNameID)
			conflictWhere = sql.And(
				sql.IsNull(hasmetadata.FieldArtifactID),
				sql.IsNull(hasmetadata.FieldPackageVersionID),
				sql.NotNull(hasmetadata.FieldPackageNameID),
				sql.IsNull(hasmetadata.FieldSourceID),
			)
		}

	case len(subjects.Sources) > 0:
		conflictColumns = append(conflictColumns, hasmetadata.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(hasmetadata.FieldArtifactID),
			sql.IsNull(hasmetadata.FieldPackageVersionID),
			sql.IsNull(hasmetadata.FieldPackageNameID),
			sql.NotNull(hasmetadata.FieldSourceID),
		)
	}

	batches := chunk(hasMetadataList, MaxBatchSize)

	index := 0
	for _, hms := range batches {
		creates := make([]*ent.HasMetadataCreate, len(hms))
		for i, hm := range hms {
			hm := hm
			var err error
			switch {
			case len(subjects.Artifacts) > 0:
				creates[i], err = generateHasMetadataCreate(ctx, tx, nil, nil, subjects.Artifacts[index], pkgMatchType, hm)
				if err != nil {
					return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
				}
			case len(subjects.Packages) > 0:
				creates[i], err = generateHasMetadataCreate(ctx, tx, subjects.Packages[index], nil, nil, pkgMatchType, hm)
				if err != nil {
					return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
				}
			case len(subjects.Sources) > 0:
				creates[i], err = generateHasMetadataCreate(ctx, tx, nil, subjects.Sources[index], nil, pkgMatchType, hm)
				if err != nil {
					return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
				}
			}
			index++
		}

		err := tx.HasMetadata.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert hasMetadata node")
		}
	}

	return &ids, nil
}

func toModelHasMetadata(v *ent.HasMetadata) *model.HasMetadata {
	var sub model.PackageSourceOrArtifact

	switch {
	case v.Edges.Source != nil:
		sub = toModelSource((v.Edges.Source))
	case v.Edges.PackageVersion != nil:
		sub = toModelPackage(backReferencePackageVersion(v.Edges.PackageVersion))
	case v.Edges.AllVersions != nil:
		pkg := toModelPackage(backReferencePackageName(v.Edges.AllVersions))
		// in this case, the expected response is package name with an empty package version array
		pkg.Namespaces[0].Names[0].Versions = []*model.PackageVersion{}
		sub = pkg
	case v.Edges.Artifact != nil:
		sub = toModelArtifact(v.Edges.Artifact)
	}

	return &model.HasMetadata{
		ID:            v.ID.String(),
		Subject:       sub,
		Key:           v.Key,
		Value:         v.Value,
		Timestamp:     v.Timestamp,
		Justification: v.Justification,
		Origin:        v.Origin,
		Collector:     v.Collector,
	}
}

// func hasMetadataInputPredicate(subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, filter model.HasMetadataInputSpec) predicate.HasMetadata {
// 	var subjectSpec *model.PackageSourceOrArtifactSpec
// 	if subject.Package != nil {
// 		if pkgMatchType != nil && pkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
// 			subject.Package.PackageInput.Version = nil
// 		}
// 		subjectSpec = &model.PackageSourceOrArtifactSpec{
// 			Package: helper.ConvertPkgInputSpecToPkgSpec(subject.Package.PackageInput),
// 		}
// 	} else if subject.Artifact != nil {
// 		subjectSpec = &model.PackageSourceOrArtifactSpec{
// 			Artifact: helper.ConvertArtInputSpecToArtSpec(subject.Artifact.ArtifactInput),
// 		}
// 	} else {
// 		subjectSpec = &model.PackageSourceOrArtifactSpec{
// 			Source: helper.ConvertSrcInputSpecToSrcSpec(subject.Source.SourceInput),
// 		}
// 	}
// 	return hasMetadataPredicate(&model.HasMetadataSpec{
// 		Subject:       subjectSpec,
// 		Key:           &filter.Key,
// 		Value:         &filter.Value,
// 		Justification: &filter.Justification,
// 		Origin:        &filter.Origin,
// 		Collector:     &filter.Collector,
// 	})
// }
