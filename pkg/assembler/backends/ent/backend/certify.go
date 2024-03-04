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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certification"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
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
	certRecord, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertCertification(ctx, ent.TxFromContext(ctx), subject, pkgMatchType, spec)
	})
	if txErr != nil {
		return "", txErr
	}

	//TODO optimize for only returning ID
	return *certRecord, nil
}

func (b *EntBackend) IngestCertifyBads(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyBads []*model.CertifyBadInputSpec) ([]string, error) {
	funcName := "IngestCertifyBads"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkCertification(ctx, client, subjects, pkgMatchType, certifyBads)
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

func (b *EntBackend) IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec model.CertifyGoodInputSpec) (string, error) {
	certRecord, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertCertification(ctx, ent.TxFromContext(ctx), subject, pkgMatchType, spec)
	})
	if txErr != nil {
		return "", txErr
	}

	//TODO optimize for only returning ID
	return *certRecord, nil
}

func (b *EntBackend) IngestCertifyGoods(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyGoods []*model.CertifyGoodInputSpec) ([]string, error) {
	funcName := "IngestCertifyGoods"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkCertification(ctx, client, subjects, pkgMatchType, certifyGoods)
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

func upsertCertification[T certificationInputSpec](ctx context.Context, tx *ent.Tx, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, spec T) (*string, error) {
	var conflictWhere *sql.Predicate

	conflictColumns := []string{
		certification.FieldType,
		certification.FieldCollector,
		certification.FieldOrigin,
		certification.FieldJustification,
		certification.FieldKnownSince,
	}

	switch {
	case subject.Artifact != nil:
		conflictColumns = append(conflictColumns, certification.FieldArtifactID)
		conflictWhere = sql.And(
			sql.NotNull(certification.FieldArtifactID),
			sql.IsNull(certification.FieldPackageNameID),
			sql.IsNull(certification.FieldPackageVersionID),
			sql.IsNull(certification.FieldSourceID),
		)

	case subject.Package != nil:
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

	case subject.Source != nil:
		conflictColumns = append(conflictColumns, certification.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(certification.FieldArtifactID),
			sql.IsNull(certification.FieldPackageVersionID),
			sql.IsNull(certification.FieldPackageNameID),
			sql.NotNull(certification.FieldSourceID),
		)
	}

	var insert *ent.CertificationCreate
	var err error
	switch v := any(spec).(type) {
	case model.CertifyBadInputSpec:
		insert, err = generateCertifyCreate(ctx, tx, subject.Package, subject.Source, subject.Artifact, pkgMatchType, &v, nil)
		if err != nil {
			return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
		}
	case model.CertifyGoodInputSpec:
		insert, err = generateCertifyCreate(ctx, tx, subject.Package, subject.Source, subject.Artifact, pkgMatchType, nil, &v)
		if err != nil {
			return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
		}
	default:
		return nil, fmt.Errorf("unknown spec: %+T", v)
	}

	if id, err := insert.OnConflict(
		sql.ConflictColumns(conflictColumns...),
		sql.ConflictWhere(conflictWhere),
	).
		Ignore().
		ID(ctx); err != nil {

		return nil, errors.Wrap(err, "upsert certify legal node")
	} else {
		return ptrfrom.String(id.String()), nil
	}
}

func generateCertifyCreate(ctx context.Context, tx *ent.Tx, pkg *model.IDorPkgInput, src *model.IDorSourceInput, art *model.IDorArtifactInput, pkgMatchType *model.MatchFlags,
	cb *model.CertifyBadInputSpec, cg *model.CertifyGoodInputSpec) (*ent.CertificationCreate, error) {

	certifyCreate := tx.Certification.Create()

	if cb != nil {
		certifyCreate.
			SetType(certification.TypeBAD).
			SetJustification(cb.Justification).
			SetOrigin(cb.Origin).
			SetCollector(cb.Collector).
			SetKnownSince(cb.KnownSince.UTC())
	} else if cg != nil {
		certifyCreate.
			SetType(certification.TypeGOOD).
			SetJustification(cg.Justification).
			SetOrigin(cg.Origin).
			SetCollector(cg.Collector).
			SetKnownSince(cg.KnownSince.UTC())
	} else {
		return nil, fmt.Errorf("must specify either certifyGood or certifyBad")
	}

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
		certifyCreate.SetArtifactID(artID)
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
			certifyCreate.SetPackageVersionID(pkgVersionID)
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
			certifyCreate.SetAllVersionsID(pkgNameID)
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
		certifyCreate.SetSourceID(sourceID)
	}
	return certifyCreate, nil
}

func upsertBulkCertification[T certificationInputSpec](ctx context.Context, tx *ent.Tx, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, spec []*T) (*[]string, error) {
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
		batches := chunk(certifies, MaxBatchSize)

		index := 0
		for _, certifyBads := range batches {
			creates := make([]*ent.CertificationCreate, len(certifyBads))
			for i, cb := range certifyBads {
				cb := cb
				var err error
				switch {
				case len(subjects.Artifacts) > 0:
					creates[i], err = generateCertifyCreate(ctx, tx, nil, nil, subjects.Artifacts[index], pkgMatchType, cb, nil)
					if err != nil {
						return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
					}
				case len(subjects.Packages) > 0:
					creates[i], err = generateCertifyCreate(ctx, tx, subjects.Packages[index], nil, nil, pkgMatchType, cb, nil)
					if err != nil {
						return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
					}
				case len(subjects.Sources) > 0:
					creates[i], err = generateCertifyCreate(ctx, tx, nil, subjects.Sources[index], nil, pkgMatchType, cb, nil)
					if err != nil {
						return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
					}
				}
				index++
			}

			err := tx.Certification.CreateBulk(creates...).
				OnConflict(
					sql.ConflictColumns(conflictColumns...),
					sql.ConflictWhere(conflictWhere),
				).
				DoNothing().
				Exec(ctx)
			if err != nil {
				return nil, errors.Wrap(err, "bulk upsert certifyBad node")
			}
		}
	case []*model.CertifyGoodInputSpec:
		batches := chunk(certifies, MaxBatchSize)

		index := 0
		for _, certifyGoods := range batches {
			creates := make([]*ent.CertificationCreate, len(certifyGoods))
			for i, cg := range certifyGoods {
				var err error
				switch {
				case len(subjects.Artifacts) > 0:
					creates[i], err = generateCertifyCreate(ctx, tx, nil, nil, subjects.Artifacts[index], pkgMatchType, nil, cg)
					if err != nil {
						return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
					}
				case len(subjects.Packages) > 0:
					creates[i], err = generateCertifyCreate(ctx, tx, subjects.Packages[index], nil, nil, pkgMatchType, nil, cg)
					if err != nil {
						return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
					}
				case len(subjects.Sources) > 0:
					creates[i], err = generateCertifyCreate(ctx, tx, nil, subjects.Sources[index], nil, pkgMatchType, nil, cg)
					if err != nil {
						return nil, gqlerror.Errorf("generateCertifyCreate :: %s", err)
					}
				}
				index++
			}

			err := tx.Certification.CreateBulk(creates...).
				OnConflict(
					sql.ConflictColumns(conflictColumns...),
					sql.ConflictWhere(conflictWhere),
				).
				DoNothing().
				Exec(ctx)
			if err != nil {
				return nil, errors.Wrap(err, "bulk upsert certifyGood node")
			}
		}
	default:
		return nil, fmt.Errorf("unknown spec: %+T", certifies)
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
