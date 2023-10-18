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
	"log"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certification"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

type certificationInputSpec interface {
	model.CertifyGoodInputSpec | model.CertifyBadInputSpec
}

func (b *EntBackend) CertifyBad(ctx context.Context, filter *model.CertifyBadSpec) ([]*model.CertifyBad, error) {
	records, err := queryCertifications(ctx, b.client, certification.TypeBAD, filter)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelCertifyBad), nil
}

func (b *EntBackend) CertifyGood(ctx context.Context, filter *model.CertifyGoodSpec) ([]*model.CertifyGood, error) {
	if filter == nil {
		return nil, nil
	}

	records, err := queryCertifications(ctx, b.client, certification.TypeGOOD, (*model.CertifyBadSpec)(filter))
	if err != nil {
		return nil, err
	}

	return collect(records, toModelCertifyGood), nil
}

func (b *EntBackend) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec model.CertifyBadInputSpec) (*model.CertifyBad, error) {

	certRecord, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.Certification, error) {
		return upsertCertification(ctx, ent.TxFromContext(ctx), subject, pkgMatchType, spec)
	})
	if err != nil {
		return nil, err
	}

	return toModelCertifyBad(certRecord), nil
}

func (b *EntBackend) IngestCertifyBads(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyBads []*model.CertifyBadInputSpec) ([]*model.CertifyBad, error) {
	var result []*model.CertifyBad
	for i := range certifyBads {
		var subject model.PackageSourceOrArtifactInput
		if len(subjects.Packages) > 0 {
			subject = model.PackageSourceOrArtifactInput{Package: subjects.Packages[i]}
		} else if len(subjects.Artifacts) > 0 {
			subject = model.PackageSourceOrArtifactInput{Artifact: subjects.Artifacts[i]}
		} else {
			subject = model.PackageSourceOrArtifactInput{Source: subjects.Sources[i]}
		}
		cb, err := b.IngestCertifyBad(ctx, subject, pkgMatchType, *certifyBads[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestCertifyBads failed with err: %v", err)
		}
		result = append(result, cb)
	}
	return result, nil
}

func (b *EntBackend) IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec model.CertifyGoodInputSpec) (*model.CertifyGood, error) {

	certRecord, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.Certification, error) {
		return upsertCertification(ctx, ent.TxFromContext(ctx), subject, pkgMatchType, spec)
	})
	if err != nil {
		return nil, err
	}

	return toModelCertifyGood(certRecord), nil
}

func (b *EntBackend) IngestCertifyGoods(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyGoods []*model.CertifyGoodInputSpec) ([]*model.CertifyGood, error) {
	var result []*model.CertifyGood
	for i := range certifyGoods {
		var subject model.PackageSourceOrArtifactInput
		if len(subjects.Packages) > 0 {
			subject = model.PackageSourceOrArtifactInput{Package: subjects.Packages[i]}
		} else if len(subjects.Artifacts) > 0 {
			subject = model.PackageSourceOrArtifactInput{Artifact: subjects.Artifacts[i]}
		} else {
			subject = model.PackageSourceOrArtifactInput{Source: subjects.Sources[i]}
		}
		cg, err := b.IngestCertifyGood(ctx, subject, pkgMatchType, *certifyGoods[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestCertifyGoods failed with err: %v", err)
		}
		result = append(result, cg)
	}
	return result, nil
}

func queryCertifications(ctx context.Context, client *ent.Client, typ certification.Type, filter *model.CertifyBadSpec) ([]*ent.Certification, error) {

	query := []predicate.Certification{
		certification.TypeEQ(typ),
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Collector, certification.CollectorEQ),
		optionalPredicate(filter.Origin, certification.OriginEQ),
		optionalPredicate(filter.Justification, certification.JustificationEQ),
		optionalPredicate(filter.KnownSince, certification.KnownSinceEQ),
	}

	if filter.Subject != nil {
		switch {
		case filter.Subject.Artifact != nil:
			query = append(query, certification.HasArtifactWith(artifactQueryPredicates(filter.Subject.Artifact)))
		case filter.Subject.Package != nil:
			query = append(query, certification.Or(
				certification.HasAllVersionsWith(packageNameQuery(pkgNameQueryFromPkgSpec(filter.Subject.Package))),
				certification.HasPackageVersionWith(packageVersionQuery(filter.Subject.Package)),
			))
		case filter.Subject.Source != nil:
			query = append(query, certification.HasSourceWith(sourceQuery(filter.Subject.Source)))
		}
	}

	return client.Certification.Query().
		Where(query...).
		Limit(MaxPageSize).
		WithSource(withSourceNameTreeQuery()).
		WithArtifact().
		WithPackageVersion(withPackageVersionTree()).
		WithAllVersions(withPackageNameTree()).
		All(ctx)
}

func upsertCertification[T certificationInputSpec](ctx context.Context, client *ent.Tx, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec T) (*ent.Certification, error) {
	insert := client.Certification.Create()

	switch v := any(spec).(type) {
	case model.CertifyBadInputSpec:
		insert.
			SetType(certification.TypeBAD).
			SetJustification(v.Justification).
			SetOrigin(v.Origin).
			SetCollector(v.Collector).
			SetKnownSince(v.KnownSince)
	case model.CertifyGoodInputSpec:
		insert.
			SetType(certification.TypeGOOD).
			SetJustification(v.Justification).
			SetOrigin(v.Origin).
			SetCollector(v.Collector).
			SetKnownSince(v.KnownSince.UTC())
	default:
		log.Printf("Unknown spec: %+T", v)
	}

	conflictColumns := []string{
		certification.FieldType,
		certification.FieldCollector,
		certification.FieldOrigin,
		certification.FieldJustification,
		certification.FieldKnownSince,
	}
	var conflictWhere *sql.Predicate

	switch {
	case subject.Artifact != nil:
		art, err := client.Artifact.Query().Where(artifactQueryInputPredicates(*subject.Artifact)).Only(ctx)
		if err != nil {
			return nil, err
		}
		insert.SetArtifact(art)
		conflictColumns = append(conflictColumns, certification.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(certification.FieldArtifactID),
			sql.IsNull(certification.FieldPackageNameID),
			sql.IsNull(certification.FieldPackageVersionID),
			sql.IsNull(certification.FieldSourceID),
		)

	case subject.Package != nil:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			pv, err := getPkgVersion(ctx, client.Client(), *subject.Package)
			if err != nil {
				return nil, err
			}
			insert.SetPackageVersion(pv)
			conflictColumns = append(conflictColumns, certification.FieldPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(certification.FieldArtifactID),
				sql.NotNull(certification.FieldPackageVersionID),
				sql.IsNull(certification.FieldPackageNameID),
				sql.IsNull(certification.FieldSourceID),
			)
		} else {
			pn, err := getPkgName(ctx, client.Client(), *subject.Package)
			if err != nil {
				return nil, err
			}
			insert.SetAllVersions(pn)
			conflictColumns = append(conflictColumns, certification.FieldPackageNameID)
			conflictWhere = sql.And(
				sql.IsNull(certification.FieldArtifactID),
				sql.IsNull(certification.FieldPackageVersionID),
				sql.NotNull(certification.FieldPackageNameID),
				sql.IsNull(certification.FieldSourceID),
			)
		}

	case subject.Source != nil:
		srcID, err := getSourceNameID(ctx, client.Client(), *subject.Source)
		if err != nil {
			return nil, err
		}
		insert.SetSourceID(srcID)
		conflictColumns = append(conflictColumns, certification.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(certification.FieldArtifactID),
			sql.IsNull(certification.FieldPackageVersionID),
			sql.IsNull(certification.FieldPackageNameID),
			sql.NotNull(certification.FieldSourceID),
		)
	}

	id, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
		sql.ConflictWhere(conflictWhere),
	).
		Ignore().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	return client.Certification.Query().
		Where(certification.ID(id)).
		WithSource(withSourceNameTreeQuery()).
		WithArtifact().
		WithPackageVersion(withPackageVersionTree()).
		WithAllVersions(withPackageNameTree()).
		Only(ctx)
}

func toModelCertifyBad(v *ent.Certification) *model.CertifyBad {
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

	return &model.CertifyBad{
		ID:            nodeID(v.ID),
		Justification: v.Justification,
		Origin:        v.Origin,
		Collector:     v.Collector,
		Subject:       sub,
		KnownSince:    v.KnownSince,
	}
}

func toModelCertifyGood(v *ent.Certification) *model.CertifyGood {
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

	return &model.CertifyGood{
		ID:            nodeID(v.ID),
		Justification: v.Justification,
		Origin:        v.Origin,
		Collector:     v.Collector,
		Subject:       sub,
		KnownSince:    v.KnownSince,
	}
}
