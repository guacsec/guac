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

func (b *EntBackend) IngestPointOfContact(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, pointOfContact model.PointOfContactInputSpec) (*model.PointOfContact, error) {
	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		return upsertPointOfContact(ctx, ent.TxFromContext(ctx), subject, pkgMatchType, pointOfContact)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to execute IngestPointOfContact :: %s", err)
	}

	return &model.PointOfContact{ID: nodeID(*recordID)}, nil
}

func (b *EntBackend) IngestPointOfContacts(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, pointOfContactList []*model.PointOfContactInputSpec) ([]string, error) {
	var results []string
	for i := range pointOfContactList {
		var subject model.PackageSourceOrArtifactInput
		if len(subjects.Packages) > 0 {
			subject = model.PackageSourceOrArtifactInput{Package: subjects.Packages[i]}
		} else if len(subjects.Artifacts) > 0 {
			subject = model.PackageSourceOrArtifactInput{Artifact: subjects.Artifacts[i]}
		} else {
			subject = model.PackageSourceOrArtifactInput{Source: subjects.Sources[i]}
		}
		hm, err := b.IngestPointOfContact(ctx, subject, pkgMatchType, *pointOfContactList[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestBulkPointOfContact failed with element #%v with err: %v", i, err)
		}
		results = append(results, hm.ID)
	}
	return results, nil
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

func upsertPointOfContact(ctx context.Context, client *ent.Tx, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec model.PointOfContactInputSpec) (*int, error) {
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
		art, err := client.Artifact.Query().Where(artifactQueryInputPredicates(*subject.Artifact)).Only(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve subject artifact :: %s", err)
		}
		insert.SetArtifact(art)
		conflictColumns = append(conflictColumns, pointofcontact.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(pointofcontact.FieldArtifactID),
			sql.IsNull(pointofcontact.FieldPackageNameID),
			sql.IsNull(pointofcontact.FieldPackageVersionID),
			sql.IsNull(pointofcontact.FieldSourceID),
		)

	case subject.Package != nil:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			pv, err := getPkgVersion(ctx, client.Client(), *subject.Package)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve subject package version :: %s", err)
			}
			insert.SetPackageVersion(pv)
			conflictColumns = append(conflictColumns, pointofcontact.FieldPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(pointofcontact.FieldArtifactID),
				sql.NotNull(pointofcontact.FieldPackageVersionID),
				sql.IsNull(pointofcontact.FieldPackageNameID),
				sql.IsNull(pointofcontact.FieldSourceID),
			)
		} else {
			pn, err := getPkgName(ctx, client.Client(), *subject.Package)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve subject package name :: %s", err)
			}
			insert.SetAllVersions(pn)
			conflictColumns = append(conflictColumns, pointofcontact.FieldPackageNameID)
			conflictWhere = sql.And(
				sql.IsNull(pointofcontact.FieldArtifactID),
				sql.IsNull(pointofcontact.FieldPackageVersionID),
				sql.NotNull(pointofcontact.FieldPackageNameID),
				sql.IsNull(pointofcontact.FieldSourceID),
			)
		}

	case subject.Source != nil:
		srcID, err := getSourceNameID(ctx, client.Client(), *subject.Source)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve subject source :: %s", err)
		}
		insert.SetSourceID(srcID)
		conflictColumns = append(conflictColumns, pointofcontact.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(pointofcontact.FieldArtifactID),
			sql.IsNull(pointofcontact.FieldPackageVersionID),
			sql.IsNull(pointofcontact.FieldPackageNameID),
			sql.NotNull(pointofcontact.FieldSourceID),
		)
	}

	id, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
		sql.ConflictWhere(conflictWhere),
	).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert PointOfContact node")
		}
		id, err = client.PointOfContact.Query().
			Where(pointOfContactInputPredicate(subject, pkgMatchType, spec)).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get PointOfContact")
		}
	}

	return &id, nil
}

func toModelPointOfContact(v *ent.PointOfContact) *model.PointOfContact {
	var sub model.PackageSourceOrArtifact

	switch {
	case v.Edges.Source != nil:
		sub = toModelSource(backReferenceSourceName(v.Edges.Source))
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
		ID:            nodeID(v.ID),
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
			subject.Package.Version = nil
		}
		subjectSpec = &model.PackageSourceOrArtifactSpec{
			Package: helper.ConvertPkgInputSpecToPkgSpec(subject.Package),
		}
	} else if subject.Artifact != nil {
		subjectSpec = &model.PackageSourceOrArtifactSpec{
			Artifact: helper.ConvertArtInputSpecToArtSpec(subject.Artifact),
		}
	} else {
		subjectSpec = &model.PackageSourceOrArtifactSpec{
			Source: helper.ConvertSrcInputSpecToSrcSpec(subject.Source),
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
