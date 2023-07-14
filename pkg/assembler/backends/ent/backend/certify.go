package backend

import (
	"context"
	"log"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certification"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (b *EntBackend) CertifyBad(ctx context.Context, filter *model.CertifyBadSpec) ([]*model.CertifyBad, error) {
	if filter != nil {
		if err := helper.ValidatePackageSourceOrArtifactQueryFilter(filter.Subject); err != nil {
			return nil, err
		}
	}

	query := []predicate.Certification{
		certification.TypeEQ(certification.TypeBAD),
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Collector, certification.CollectorEQ),
		optionalPredicate(filter.Origin, certification.OriginEQ),
		optionalPredicate(filter.Justification, certification.JustificationEQ),
	}

	if filter.Subject != nil {
		switch {
		case filter.Subject.Artifact != nil:
			query = append(query, certification.HasArtifactWith(artifactQueryPredicates(filter.Subject.Artifact)))
		case filter.Subject.Package != nil:
			query = append(query, certification.Or(
				certification.HasAllVersionsWith(packageNameQuery(pkgNameQueryFromPkgSpec(filter.Subject.Package))),
				certification.HasPackageVersionWith(pkgVersionPredicates(filter.Subject.Package)),
			))
		case filter.Subject.Source != nil:
			query = append(query, certification.HasSourceWith(sourceQuery(filter.Subject.Source)))
		}
	}

	records, err := b.client.Certification.Query().
		Where(query...).
		Limit(MaxPageSize).
		WithSource(withSourceNameTreeQuery()).
		WithArtifact().
		WithPackageVersion(withPackageVersionTree()).
		WithAllVersions(withPackageNameTree()).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelCertifyBad), nil
}

func (b *EntBackend) CertifyGood(ctx context.Context, certifyGoodSpec *model.CertifyGoodSpec) ([]*model.CertifyGood, error) {
	return nil, nil
}

func (b *EntBackend) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec model.CertifyBadInputSpec) (*model.CertifyBad, error) {
	funcName := "IngestCertifyBad"
	if err := helper.ValidatePackageSourceOrArtifactInput(&subject, "bad subject"); err != nil {
		return nil, Errorf("%v ::  %s", funcName, err)
	}

	certRecord, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.Certification, error) {
		return upsertCertification(ctx, ent.TxFromContext(ctx), subject, pkgMatchType, spec)
	})
	if err != nil {
		return nil, err
	}

	return toModelCertifyBad(certRecord), nil
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

type certificationSpec interface {
	model.CertifyGoodInputSpec | model.CertifyBadInputSpec
}

func upsertCertification[T certificationSpec](ctx context.Context, client *ent.Tx, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec T) (*ent.Certification, error) {
	insert := client.Certification.Create()

	switch v := any(spec).(type) {
	case model.CertifyBadInputSpec:
		insert.
			SetType(certification.TypeBAD).
			SetJustification(v.Justification).
			SetOrigin(v.Origin).
			SetCollector(v.Collector)
	case model.CertifyGoodInputSpec:
		insert.
			SetType(certification.TypeGOOD).
			SetJustification(v.Justification).
			SetOrigin(v.Origin).
			SetCollector(v.Collector)
	default:
		log.Printf("Unknown spec: %+T", v)
	}

	conflictColumns := []string{
		certification.FieldType,
		certification.FieldCollector,
		certification.FieldOrigin,
		certification.FieldJustification,
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
			pv, err := getPkgVersion(ctx, client.Client(), subject.Package)
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
			pn, err := getPkgName(ctx, client.Client(), subject.Package)
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
		src, err := client.SourceName.Query().Where(sourceInputQuery(*subject.Source)).Only(ctx)
		if err != nil {
			return nil, err
		}
		insert.SetSource(src)
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
		sub = toModelPackage(backReferencePackageName(v.Edges.AllVersions))
	case v.Edges.Artifact != nil:
		sub = toModelArtifact(v.Edges.Artifact)
	}

	return &model.CertifyBad{
		ID:            nodeID(v.ID),
		Justification: v.Justification,
		Origin:        v.Origin,
		Collector:     v.Collector,
		Subject:       sub,
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
		sub = toModelPackage(backReferencePackageName(v.Edges.AllVersions))
	case v.Edges.Artifact != nil:
		sub = toModelArtifact(v.Edges.Artifact)
	}

	return &model.CertifyGood{
		ID:            nodeID(v.ID),
		Justification: v.Justification,
		Origin:        v.Origin,
		Collector:     v.Collector,
		Subject:       sub,
	}
}
