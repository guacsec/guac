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

func upsertBulkPointOfContact(ctx context.Context, tx *ent.Tx, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, pointOfContactList []*model.PointOfContactInputSpec) (*[]string, error) {
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
			poc := poc
			var err error

			switch {
			case len(subjects.Artifacts) > 0:
				creates[i], err = generatePointOfContactCreate(tx, nil, nil, subjects.Artifacts[index], pkgMatchType, poc)
				if err != nil {
					return nil, gqlerror.Errorf("generatePointOfContactCreate :: %s", err)
				}
			case len(subjects.Packages) > 0:
				creates[i], err = generatePointOfContactCreate(tx, subjects.Packages[index], nil, nil, pkgMatchType, poc)
				if err != nil {
					return nil, gqlerror.Errorf("generatePointOfContactCreate :: %s", err)
				}
			case len(subjects.Sources) > 0:
				creates[i], err = generatePointOfContactCreate(tx, nil, subjects.Sources[index], nil, pkgMatchType, poc)
				if err != nil {
					return nil, gqlerror.Errorf("generatePointOfContactCreate :: %s", err)
				}
			}
			index++
		}

		err := tx.PointOfContact.CreateBulk(creates...).
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

func generatePointOfContactCreate(tx *ent.Tx, pkg *model.IDorPkgInput, src *model.IDorSourceInput, art *model.IDorArtifactInput, pkgMatchType *model.MatchFlags,
	poc *model.PointOfContactInputSpec) (*ent.PointOfContactCreate, error) {

	pocCreate := tx.PointOfContact.Create()

	pocCreate.
		SetEmail(poc.Email).
		SetInfo(poc.Info).
		SetSince(poc.Since.UTC()).
		SetJustification(poc.Justification).
		SetOrigin(poc.Origin).
		SetCollector(poc.Collector)

	switch {
	case art != nil:
		if art.ArtifactID == nil {
			return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
		}
		artID, err := uuid.Parse(*art.ArtifactID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
		}
		pocCreate.SetArtifactID(artID)
	case pkg != nil:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			if pkg.PackageVersionID == nil {
				return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
			}
			pkgVersionID, err := uuid.Parse(*pkg.PackageVersionID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
			pocCreate.SetPackageVersionID(pkgVersionID)
		} else {
			if pkg.PackageNameID == nil {
				return nil, fmt.Errorf("packageName ID not specified in IDorPkgInput")
			}
			pkgNameID, err := uuid.Parse(*pkg.PackageNameID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from PackageNameID failed with error: %w", err)
			}
			pocCreate.SetAllVersionsID(pkgNameID)
		}

	case src != nil:
		if src.SourceNameID == nil {
			return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
		}
		sourceID, err := uuid.Parse(*src.SourceNameID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from SourceNameID failed with error: %w", err)
		}
		pocCreate.SetSourceID(sourceID)
	}
	return pocCreate, nil
}

func upsertPointOfContact(ctx context.Context, tx *ent.Tx, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec model.PointOfContactInputSpec) (*string, error) {

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
		conflictColumns = append(conflictColumns, pointofcontact.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(pointofcontact.FieldArtifactID),
			sql.IsNull(pointofcontact.FieldPackageNameID),
			sql.IsNull(pointofcontact.FieldPackageVersionID),
			sql.IsNull(pointofcontact.FieldSourceID),
		)

	case subject.Package != nil:
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
	case subject.Source != nil:
		conflictColumns = append(conflictColumns, pointofcontact.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(pointofcontact.FieldArtifactID),
			sql.IsNull(pointofcontact.FieldPackageVersionID),
			sql.IsNull(pointofcontact.FieldPackageNameID),
			sql.NotNull(pointofcontact.FieldSourceID),
		)
	}

	insert, err := generatePointOfContactCreate(tx, subject.Package, subject.Source, subject.Artifact, pkgMatchType, &spec)
	if err != nil {
		return nil, gqlerror.Errorf("generatePointOfContactCreate :: %s", err)
	}
	if _, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
		sql.ConflictWhere(conflictWhere),
	).
		DoNothing().
		ID(ctx); err != nil {

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

// func pointOfContactInputPredicate(subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, filter model.PointOfContactInputSpec) predicate.PointOfContact {
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
// 	return pointOfContactPredicate(&model.PointOfContactSpec{
// 		Subject:       subjectSpec,
// 		Email:         &filter.Email,
// 		Info:          &filter.Info,
// 		Since:         &filter.Since,
// 		Justification: &filter.Justification,
// 		Origin:        &filter.Origin,
// 		Collector:     &filter.Collector,
// 	})
// }
