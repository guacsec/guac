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
	"log"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
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

func (b *EntBackend) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec model.CertifyBadInputSpec) (string, error) {
	certRecord, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertCertification(ctx, ent.TxFromContext(ctx), subject, pkgMatchType, spec)
	})
	if err != nil {
		return "", err
	}

	//TODO optimize for only returning ID
	return *certRecord, nil
}

func (b *EntBackend) IngestCertifyBads(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyBads []*model.CertifyBadInputSpec) ([]string, error) {
	funcName := "IngestCertifyBads"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkCertification(ctx, client, subjects, pkgMatchType, certifyBads)
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

func (b *EntBackend) IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec model.CertifyGoodInputSpec) (string, error) {
	certRecord, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertCertification(ctx, ent.TxFromContext(ctx), subject, pkgMatchType, spec)
	})
	if err != nil {
		return "", err
	}

	//TODO optimize for only returning ID
	return *certRecord, nil
}

func (b *EntBackend) IngestCertifyGoods(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyGoods []*model.CertifyGoodInputSpec) ([]string, error) {
	funcName := "IngestCertifyGoods"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkCertification(ctx, client, subjects, pkgMatchType, certifyGoods)
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

func upsertCertification[T certificationInputSpec](ctx context.Context, client *ent.Tx, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec T) (*string, error) {
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
		if subject.Artifact.ArtifactID == nil {
			return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
		}
		artID, err := uuid.Parse(*subject.Artifact.ArtifactID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
		}
		insert.SetArtifactID(artID)
		conflictColumns = append(conflictColumns, certification.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(certification.FieldArtifactID),
			sql.IsNull(certification.FieldPackageNameID),
			sql.IsNull(certification.FieldPackageVersionID),
			sql.IsNull(certification.FieldSourceID),
		)

	case subject.Package != nil:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			if subject.Package.PackageVersionID == nil {
				return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
			}
			pkgVersionID, err := uuid.Parse(*subject.Package.PackageVersionID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
			}
			insert.SetPackageVersionID(pkgVersionID)
			conflictColumns = append(conflictColumns, certification.FieldPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(certification.FieldArtifactID),
				sql.NotNull(certification.FieldPackageVersionID),
				sql.IsNull(certification.FieldPackageNameID),
				sql.IsNull(certification.FieldSourceID),
			)
		} else {
			if subject.Package.PackageNameID == nil {
				return nil, fmt.Errorf("packageName ID not specified in IDorPkgInput")
			}
			pkgNameID, err := uuid.Parse(*subject.Package.PackageNameID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
			}
			insert.SetAllVersionsID(pkgNameID)
			conflictColumns = append(conflictColumns, certification.FieldPackageNameID)
			conflictWhere = sql.And(
				sql.IsNull(certification.FieldArtifactID),
				sql.IsNull(certification.FieldPackageVersionID),
				sql.NotNull(certification.FieldPackageNameID),
				sql.IsNull(certification.FieldSourceID),
			)
		}

	case subject.Source != nil:
		if subject.Source.SourceNameID == nil {
			return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
		}
		sourceID, err := uuid.Parse(*subject.Source.SourceNameID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
		}
		insert.SetSourceID(sourceID)
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

	return ptrfrom.String(id.String()), nil
}

func upsertBulkCertification[T certificationInputSpec](ctx context.Context, client *ent.Tx, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, spec []*T) (*[]string, error) {
	ids := make([]string, 0)

	var conflictWhere *sql.Predicate

	conflictColumns := []string{
		certification.FieldType,
		certification.FieldCollector,
		certification.FieldOrigin,
		certification.FieldJustification,
		certification.FieldKnownSince,
	}

	switch {
	case len(subjects.Artifacts) > 0:
		conflictColumns = append(conflictColumns, certification.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(certification.FieldArtifactID),
			sql.IsNull(certification.FieldPackageNameID),
			sql.IsNull(certification.FieldPackageVersionID),
			sql.IsNull(certification.FieldSourceID),
		)

	case len(subjects.Packages) > 0:
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			conflictColumns = append(conflictColumns, certification.FieldPackageVersionID)
			conflictWhere = sql.And(
				sql.IsNull(certification.FieldArtifactID),
				sql.NotNull(certification.FieldPackageVersionID),
				sql.IsNull(certification.FieldPackageNameID),
				sql.IsNull(certification.FieldSourceID),
			)
		} else {
			conflictColumns = append(conflictColumns, certification.FieldPackageNameID)
			conflictWhere = sql.And(
				sql.IsNull(certification.FieldArtifactID),
				sql.IsNull(certification.FieldPackageVersionID),
				sql.NotNull(certification.FieldPackageNameID),
				sql.IsNull(certification.FieldSourceID),
			)
		}

	case len(subjects.Sources) > 0:
		conflictColumns = append(conflictColumns, certification.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(certification.FieldArtifactID),
			sql.IsNull(certification.FieldPackageVersionID),
			sql.IsNull(certification.FieldPackageNameID),
			sql.NotNull(certification.FieldSourceID),
		)
	}

	switch certifies := any(spec).(type) {
	case []*model.CertifyBadInputSpec:
		batches := chunk(certifies, 100)

		index := 0
		for _, certifyBads := range batches {
			creates := make([]*ent.CertificationCreate, len(certifyBads))
			for i, cb := range certifyBads {
				creates[i] = client.Certification.Create().
					SetType(certification.TypeBAD).
					SetJustification(cb.Justification).
					SetOrigin(cb.Origin).
					SetCollector(cb.Collector).
					SetKnownSince(cb.KnownSince)

				switch {
				case len(subjects.Artifacts) > 0:
					if subjects.Artifacts[index].ArtifactID == nil {
						return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
					}
					artID, err := uuid.Parse(*subjects.Artifacts[index].ArtifactID)
					if err != nil {
						return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
					}
					creates[i].SetArtifactID(artID)

				case len(subjects.Packages) > 0:
					if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
						if subjects.Packages[index].PackageVersionID == nil {
							return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
						}
						pkgVersionID, err := uuid.Parse(*subjects.Packages[index].PackageVersionID)
						if err != nil {
							return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
						}
						creates[i].SetPackageVersionID(pkgVersionID)

					} else {
						if subjects.Packages[index].PackageNameID == nil {
							return nil, fmt.Errorf("packageName ID not specified in IDorPkgInput")
						}
						pkgNameID, err := uuid.Parse(*subjects.Packages[index].PackageNameID)
						if err != nil {
							return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
						}
						creates[i].SetAllVersionsID(pkgNameID)

					}

				case len(subjects.Sources) > 0:
					if subjects.Sources[index].SourceNameID == nil {
						return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
					}
					sourceID, err := uuid.Parse(*subjects.Sources[index].SourceNameID)
					if err != nil {
						return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
					}
					creates[i].SetSourceID(sourceID)

				}
				index++
			}

			err := client.Certification.CreateBulk(creates...).
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
	case []*model.CertifyGoodInputSpec:
		batches := chunk(certifies, 100)

		index := 0
		for _, certifyGoods := range batches {
			creates := make([]*ent.CertificationCreate, len(certifyGoods))
			for i, cb := range certifyGoods {
				creates[i] = client.Certification.Create().
					SetType(certification.TypeGOOD).
					SetJustification(cb.Justification).
					SetOrigin(cb.Origin).
					SetCollector(cb.Collector).
					SetKnownSince(cb.KnownSince)

				switch {
				case len(subjects.Artifacts) > 0:
					if subjects.Artifacts[index].ArtifactID == nil {
						return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
					}
					artID, err := uuid.Parse(*subjects.Artifacts[index].ArtifactID)
					if err != nil {
						return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
					}
					creates[i].SetArtifactID(artID)

				case len(subjects.Packages) > 0:
					if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
						if subjects.Packages[index].PackageVersionID == nil {
							return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
						}
						pkgVersionID, err := uuid.Parse(*subjects.Packages[index].PackageVersionID)
						if err != nil {
							return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
						}
						creates[i].SetPackageVersionID(pkgVersionID)

					} else {
						if subjects.Packages[index].PackageNameID == nil {
							return nil, fmt.Errorf("packageName ID not specified in IDorPkgInput")
						}
						pkgNameID, err := uuid.Parse(*subjects.Packages[index].PackageNameID)
						if err != nil {
							return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
						}
						creates[i].SetAllVersionsID(pkgNameID)

					}

				case len(subjects.Sources) > 0:
					if subjects.Sources[index].SourceNameID == nil {
						return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
					}
					sourceID, err := uuid.Parse(*subjects.Sources[index].SourceNameID)
					if err != nil {
						return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
					}
					creates[i].SetSourceID(sourceID)

				}
				index++
			}

			err := client.Certification.CreateBulk(creates...).
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
	default:
		return nil, fmt.Errorf("Unknown spec: %+T", certifies)
	}

	return &ids, nil
}

func toModelCertifyBad(v *ent.Certification) *model.CertifyBad {
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

	return &model.CertifyBad{
		ID:            v.ID.String(),
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

	return &model.CertifyGood{
		ID:            v.ID.String(),
		Justification: v.Justification,
		Origin:        v.Origin,
		Collector:     v.Collector,
		Subject:       sub,
		KnownSince:    v.KnownSince,
	}
}
