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

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pointofcontact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) PointOfContact(ctx context.Context, filter *model.PointOfContactSpec) ([]*model.PointOfContact, error) {
	records, err := b.client.PointOfContact.Query().
		Where(pointOfContactPredicate(filter)).
		Limit(MaxPageSize).
		WithSource(withSourceNameTreeQuery()).
		WithArtifact().
		WithPackageVersion(withPackageVersionTree()).
		WithAllVersions(withPackageNameTree()).
		All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve PointOfContact :: %s", err)
	}

	return collect(records, toModelPointOfContact), nil
}

func (b *EntBackend) IngestPointOfContact(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, pointOfContact model.PointOfContactInputSpec) (string, error) {
	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertPointOfContact(ctx, ent.TxFromContext(ctx), subject, pkgMatchType, pointOfContact)
	})
	if err != nil {
		return "", fmt.Errorf("failed to execute IngestPointOfContact :: %s", err)
	}

	return *recordID, nil
}

func (b *EntBackend) IngestPointOfContacts(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, pointOfContactList []*model.PointOfContactInputSpec) ([]string, error) {
	funcName := "IngestPointOfContacts"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkPointOfContact(ctx, client, subjects, pkgMatchType, pointOfContactList)
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

func pointOfContactPredicate(filter *model.PointOfContactSpec) predicate.PointOfContact {
	predicates := []predicate.PointOfContact{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Email, pointofcontact.EmailEqualFold),
		optionalPredicate(filter.Info, pointofcontact.InfoEqualFold),
		optionalPredicate(filter.Since, pointofcontact.SinceGTE),
		optionalPredicate(filter.Justification, pointofcontact.JustificationEQ),
		optionalPredicate(filter.Origin, pointofcontact.OriginEQ),
		optionalPredicate(filter.Collector, pointofcontact.CollectorEQ),
	}

	if filter.Subject != nil {
		switch {
		case filter.Subject.Artifact != nil:
			predicates = append(predicates, pointofcontact.HasArtifactWith(artifactQueryPredicates(filter.Subject.Artifact)))
		case filter.Subject.Package != nil:
			predicates = append(predicates, pointofcontact.Or(
				pointofcontact.HasAllVersionsWith(packageNameQuery(pkgNameQueryFromPkgSpec(filter.Subject.Package))),
				pointofcontact.HasPackageVersionWith(packageVersionQuery(filter.Subject.Package)),
			))
		case filter.Subject.Source != nil:
			predicates = append(predicates, pointofcontact.HasSourceWith(sourceQuery(filter.Subject.Source)))
		}
	}
	return pointofcontact.And(predicates...)
}

func upsertBulkPointOfContact(ctx context.Context, client *ent.Tx, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, pointOfContactList []*model.PointOfContactInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		pointofcontact.FieldEmail,
		pointofcontact.FieldInfo,
		pointofcontact.FieldSince,
		pointofcontact.FieldJustification,
		pointofcontact.FieldOrigin,
		pointofcontact.FieldCollector,
	}
	var conflictWhere *sql.Predicate

	switch {
	case len(subjects.Artifacts) > 0:
		conflictColumns = append(conflictColumns, pointofcontact.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(pointofcontact.FieldArtifactID),
			sql.IsNull(pointofcontact.FieldPackageNameID),
			sql.IsNull(pointofcontact.FieldPackageVersionID),
			sql.IsNull(pointofcontact.FieldSourceID),
		)
	case len(subjects.Packages) > 0:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			conflictColumns = append(conflictColumns, pointofcontact.FieldPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(pointofcontact.FieldArtifactID),
				sql.NotNull(pointofcontact.FieldPackageVersionID),
				sql.IsNull(pointofcontact.FieldPackageNameID),
				sql.IsNull(pointofcontact.FieldSourceID),
			)
		} else {
			conflictColumns = append(conflictColumns, pointofcontact.FieldPackageNameID)
			conflictWhere = sql.And(
				sql.IsNull(pointofcontact.FieldArtifactID),
				sql.IsNull(pointofcontact.FieldPackageVersionID),
				sql.NotNull(pointofcontact.FieldPackageNameID),
				sql.IsNull(pointofcontact.FieldSourceID),
			)
		}
	case len(subjects.Sources) > 0:
		conflictColumns = append(conflictColumns, pointofcontact.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(pointofcontact.FieldArtifactID),
			sql.IsNull(pointofcontact.FieldPackageVersionID),
			sql.IsNull(pointofcontact.FieldPackageNameID),
			sql.NotNull(pointofcontact.FieldSourceID),
		)
	}

	batches := chunk(pointOfContactList, 100)

	index := 0
	for _, pocs := range batches {
		creates := make([]*ent.PointOfContactCreate, len(pocs))
		for i, poc := range pocs {
			creates[i] = client.PointOfContact.Create().
				SetEmail(poc.Email).
				SetInfo(poc.Info).
				SetSince(poc.Since.UTC()).
				SetJustification(poc.Justification).
				SetOrigin(poc.Origin).
				SetCollector(poc.Collector)

			switch {
			case len(subjects.Artifacts) > 0:
				if subjects.Artifacts[index].ArtifactID == nil {
					return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
				}
				artID, err := uuid.Parse(*subjects.Artifacts[index].ArtifactID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
				}
				creates[i].SetArtifactID(artID)

			case len(subjects.Packages) > 0:
				if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
					if subjects.Packages[index].PackageVersionID == nil {
						return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
					}
					pkgVersionID, err := uuid.Parse(*subjects.Packages[index].PackageVersionID)
					if err != nil {
						return nil, fmt.Errorf("uuid conversion from PackageVersionID failed with error: %w", err)
					}
					creates[i].SetPackageVersionID(pkgVersionID)

				} else {
					if subjects.Packages[index].PackageNameID == nil {
						return nil, fmt.Errorf("packageName ID not specified in IDorPkgInput")
					}
					pkgNameID, err := uuid.Parse(*subjects.Packages[index].PackageNameID)
					if err != nil {
						return nil, fmt.Errorf("uuid conversion from PackageNameID failed with error: %w", err)
					}
					creates[i].SetAllVersionsID(pkgNameID)

				}
			case len(subjects.Sources) > 0:
				if subjects.Sources[index].SourceNameID == nil {
					return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
				}
				sourceID, err := uuid.Parse(*subjects.Sources[index].SourceNameID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from SourceNameID failed with error: %w", err)
				}
				creates[i].SetSourceID(sourceID)

			}
			index++
		}

		err := client.PointOfContact.CreateBulk(creates...).
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

func upsertPointOfContact(ctx context.Context, client *ent.Tx, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec model.PointOfContactInputSpec) (*string, error) {
	insert := client.PointOfContact.Create().
		SetEmail(spec.Email).
		SetInfo(spec.Info).
		SetSince(spec.Since.UTC()).
		SetJustification(spec.Justification).
		SetOrigin(spec.Origin).
		SetCollector(spec.Collector)

	conflictColumns := []string{
		pointofcontact.FieldEmail,
		pointofcontact.FieldInfo,
		pointofcontact.FieldSince,
		pointofcontact.FieldJustification,
		pointofcontact.FieldOrigin,
		pointofcontact.FieldCollector,
	}
	var conflictWhere *sql.Predicate

	switch {
	case subject.Artifact != nil:
		if subject.Artifact.ArtifactID == nil {
			return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
		}
		artID, err := uuid.Parse(*subject.Artifact.ArtifactID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
		}
		insert.SetArtifactID(artID)
		conflictColumns = append(conflictColumns, pointofcontact.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(pointofcontact.FieldArtifactID),
			sql.IsNull(pointofcontact.FieldPackageNameID),
			sql.IsNull(pointofcontact.FieldPackageVersionID),
			sql.IsNull(pointofcontact.FieldSourceID),
		)

	case subject.Package != nil:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			if subject.Package.PackageVersionID == nil {
				return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
			}
			pkgVersionID, err := uuid.Parse(*subject.Package.PackageVersionID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
			insert.SetPackageVersionID(pkgVersionID)
			conflictColumns = append(conflictColumns, pointofcontact.FieldPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(pointofcontact.FieldArtifactID),
				sql.NotNull(pointofcontact.FieldPackageVersionID),
				sql.IsNull(pointofcontact.FieldPackageNameID),
				sql.IsNull(pointofcontact.FieldSourceID),
			)
		} else {
			if subject.Package.PackageNameID == nil {
				return nil, fmt.Errorf("packageName ID not specified in IDorPkgInput")
			}
			pkgNameID, err := uuid.Parse(*subject.Package.PackageNameID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from PackageNameID failed with error: %w", err)
			}
			insert.SetAllVersionsID(pkgNameID)
			conflictColumns = append(conflictColumns, pointofcontact.FieldPackageNameID)
			conflictWhere = sql.And(
				sql.IsNull(pointofcontact.FieldArtifactID),
				sql.IsNull(pointofcontact.FieldPackageVersionID),
				sql.NotNull(pointofcontact.FieldPackageNameID),
				sql.IsNull(pointofcontact.FieldSourceID),
			)
		}

	case subject.Source != nil:
		if subject.Source.SourceNameID == nil {
			return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
		}
		sourceID, err := uuid.Parse(*subject.Source.SourceNameID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from SourceNameID failed with error: %w", err)
		}
		insert.SetSourceID(sourceID)
		conflictColumns = append(conflictColumns, pointofcontact.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(pointofcontact.FieldArtifactID),
			sql.IsNull(pointofcontact.FieldPackageVersionID),
			sql.IsNull(pointofcontact.FieldPackageNameID),
			sql.NotNull(pointofcontact.FieldSourceID),
		)
	}

	_, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
		sql.ConflictWhere(conflictWhere),
	).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert PointOfContact node")
		}
	}

	return ptrfrom.String(""), nil
}

func toModelPointOfContact(v *ent.PointOfContact) *model.PointOfContact {
	var sub model.PackageSourceOrArtifact

	switch {
	case v.Edges.Source != nil:
		sub = toModelSource(v.Edges.Source)
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

	return &model.PointOfContact{
		ID:            v.ID.String(),
		Subject:       sub,
		Email:         v.Email,
		Info:          v.Info,
		Since:         v.Since,
		Justification: v.Justification,
		Origin:        v.Origin,
		Collector:     v.Collector,
	}
}

func pointOfContactInputPredicate(subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, filter model.PointOfContactInputSpec) predicate.PointOfContact {
	var subjectSpec *model.PackageSourceOrArtifactSpec
	if subject.Package != nil {
		if pkgMatchType != nil && pkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
			subject.Package.PackageInput.Version = nil
		}
		subjectSpec = &model.PackageSourceOrArtifactSpec{
			Package: helper.ConvertPkgInputSpecToPkgSpec(subject.Package.PackageInput),
		}
	} else if subject.Artifact != nil {
		subjectSpec = &model.PackageSourceOrArtifactSpec{
			Artifact: helper.ConvertArtInputSpecToArtSpec(subject.Artifact.ArtifactInput),
		}
	} else {
		subjectSpec = &model.PackageSourceOrArtifactSpec{
			Source: helper.ConvertSrcInputSpecToSrcSpec(subject.Source.SourceInput),
		}
	}
	return pointOfContactPredicate(&model.PointOfContactSpec{
		Subject:       subjectSpec,
		Email:         &filter.Email,
		Info:          &filter.Info,
		Since:         &filter.Since,
		Justification: &filter.Justification,
		Origin:        &filter.Origin,
		Collector:     &filter.Collector,
	})
}
