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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifylegal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/license"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) CertifyLegal(ctx context.Context, spec *model.CertifyLegalSpec) ([]*model.CertifyLegal, error) {

	records, err := b.client.CertifyLegal.Query().
		Where(certifyLegalQuery(*spec)).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
		}).
		WithSource(func(q *ent.SourceNameQuery) {}).
		WithDeclaredLicenses().
		WithDiscoveredLicenses().
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelCertifyLegal), nil
}

func (b *EntBackend) IngestCertifyLegals(ctx context.Context, subjects model.PackageOrSourceInputs, declaredLicensesList [][]*model.IDorLicenseInput, discoveredLicensesList [][]*model.IDorLicenseInput, certifyLegals []*model.CertifyLegalInputSpec) ([]string, error) {
	funcName := "IngestCertifyLegals"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		tx := ent.TxFromContext(ctx)
		slc, err := upsertBulkCertifyLegal(ctx, tx, subjects, declaredLicensesList, discoveredLicensesList, certifyLegals)
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

func (b *EntBackend) IngestCertifyLegal(ctx context.Context, subject model.PackageOrSourceInput, declaredLicenses []*model.IDorLicenseInput, discoveredLicenses []*model.IDorLicenseInput, spec *model.CertifyLegalInputSpec) (string, error) {

	recordID, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)

		certifyLegalConflictColumns := []string{
			certifylegal.FieldDeclaredLicense,
			certifylegal.FieldDiscoveredLicense,
			certifylegal.FieldAttribution,
			certifylegal.FieldJustification,
			certifylegal.FieldTimeScanned,
			certifylegal.FieldOrigin,
			certifylegal.FieldCollector,
			certifylegal.FieldDeclaredLicensesHash,
			certifylegal.FieldDiscoveredLicensesHash,
		}
		var conflictWhere *sql.Predicate

		if subject.Package != nil {
			certifyLegalConflictColumns = append(certifyLegalConflictColumns, certifylegal.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(certifylegal.FieldPackageID),
				sql.IsNull(certifylegal.FieldSourceID),
			)
		} else if subject.Source != nil {
			certifyLegalConflictColumns = append(certifyLegalConflictColumns, certifylegal.FieldSourceID)
			conflictWhere = sql.And(
				sql.IsNull(certifylegal.FieldPackageID),
				sql.NotNull(certifylegal.FieldSourceID),
			)
		} else {
			return nil, gqlerror.Errorf("%v :: %s", "IngestCertifyLegal", "subject must be either a package or source")
		}

		certifyLegalCreate, err := generateCertifyLegalCreate(ctx, tx, spec, subject.Package, subject.Source, declaredLicenses, discoveredLicenses)
		if err != nil {
			return nil, gqlerror.Errorf("generateCertifyLegalCreate :: %s", err)
		}

		if id, err := certifyLegalCreate.
			OnConflict(
				sql.ConflictColumns(certifyLegalConflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			Ignore().
			ID(ctx); err != nil {

			return nil, errors.Wrap(err, "upsert certify legal node")
		} else {
			return ptrfrom.String(id.String()), nil
		}
	})
	if txErr != nil {
		return "", gqlerror.Errorf("IngestCertifyLegal :: %s", txErr)
	}

	return *recordID, nil
}

func generateCertifyLegalCreate(ctx context.Context, tx *ent.Tx, cl *model.CertifyLegalInputSpec, pkg *model.IDorPkgInput, src *model.IDorSourceInput, declaredLicenses []*model.IDorLicenseInput, discoveredLicenses []*model.IDorLicenseInput) (*ent.CertifyLegalCreate, error) {
	certifyLegalCreate := tx.CertifyLegal.Create().
		SetDeclaredLicense(cl.DeclaredLicense).
		SetDiscoveredLicense(cl.DiscoveredLicense).
		SetAttribution(cl.Attribution).
		SetJustification(cl.Justification).
		SetTimeScanned(cl.TimeScanned.UTC()).
		SetOrigin(cl.Origin).
		SetCollector(cl.Collector)

	var sortedDeclaredLicenseHash string
	var sortedDiscoveredLicenseHash string

	if len(declaredLicenses) > 0 {
		var declaredLicenseIDs []string
		for _, decLic := range declaredLicenses {
			if decLic.LicenseID != nil {
				declaredLicenseIDs = append(declaredLicenseIDs, *decLic.LicenseID)
			} else {
				licenseID, err := getLicenseID(ctx, tx.Client(), *decLic.LicenseInput)
				if err != nil {
					return nil, errors.Wrap(err, "failed to get license ID")
				}
				declaredLicenseIDs = append(declaredLicenseIDs, licenseID.String())
			}
		}
		sortedDeclaredLicenseIDs := helper.SortAndRemoveDups(declaredLicenseIDs)

		for _, declaredLicID := range sortedDeclaredLicenseIDs {
			declaredLicUUID, err := uuid.Parse(declaredLicID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from licenseID failed with error: %w", err)
			}
			certifyLegalCreate.AddDeclaredLicenseIDs(declaredLicUUID)
		}
		sortedDeclaredLicenseHash = hashListOfSortedKeys(sortedDeclaredLicenseIDs)
		certifyLegalCreate.SetDeclaredLicensesHash(sortedDeclaredLicenseHash)
	} else {
		sortedDeclaredLicenseHash = hashListOfSortedKeys([]string{""})
		certifyLegalCreate.SetDeclaredLicensesHash(sortedDeclaredLicenseHash)
	}

	if len(discoveredLicenses) > 0 {
		var discoveredLicenseIDs []string
		for _, disLic := range discoveredLicenses {
			if disLic.LicenseID != nil {
				discoveredLicenseIDs = append(discoveredLicenseIDs, *disLic.LicenseID)
			} else {
				licenseID, err := getLicenseID(ctx, tx.Client(), *disLic.LicenseInput)
				if err != nil {
					return nil, errors.Wrap(err, "failed to get license ID")
				}
				discoveredLicenseIDs = append(discoveredLicenseIDs, licenseID.String())
			}
		}
		sortedDiscoveredLicenseIDs := helper.SortAndRemoveDups(discoveredLicenseIDs)

		for _, discoveredLicID := range sortedDiscoveredLicenseIDs {
			discoveredLicUUID, err := uuid.Parse(discoveredLicID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from licenseID failed with error: %w", err)
			}
			certifyLegalCreate.AddDiscoveredLicenseIDs(discoveredLicUUID)
		}
		sortedDiscoveredLicenseHash = hashListOfSortedKeys(sortedDiscoveredLicenseIDs)
		certifyLegalCreate.SetDiscoveredLicensesHash(sortedDiscoveredLicenseHash)
	} else {
		sortedDiscoveredLicenseHash = hashListOfSortedKeys([]string{""})
		certifyLegalCreate.SetDiscoveredLicensesHash(sortedDiscoveredLicenseHash)
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
		certifyLegalCreate.SetPackageID(pkgVersionID)
		certifyLegalID, err := guacCertifyLegalKey(ptrfrom.String(pkgVersionID.String()), nil, sortedDeclaredLicenseHash, sortedDiscoveredLicenseHash, cl)
		if err != nil {
			return nil, fmt.Errorf("failed to create certifyLegal uuid with error: %w", err)
		}
		certifyLegalCreate.SetID(*certifyLegalID)
	} else if src != nil {
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
		certifyLegalCreate.SetSourceID(sourceID)
		certifyLegalID, err := guacCertifyLegalKey(nil, ptrfrom.String(sourceID.String()), sortedDeclaredLicenseHash, sortedDiscoveredLicenseHash, cl)
		if err != nil {
			return nil, fmt.Errorf("failed to create certifyLegal uuid with error: %w", err)
		}
		certifyLegalCreate.SetID(*certifyLegalID)
	}

	return certifyLegalCreate, nil
}

func upsertBulkCertifyLegal(ctx context.Context, tx *ent.Tx, subjects model.PackageOrSourceInputs, declaredLicensesList [][]*model.IDorLicenseInput, discoveredLicensesList [][]*model.IDorLicenseInput, certifyLegals []*model.CertifyLegalInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	certifyLegalConflictColumns := []string{
		certifylegal.FieldDeclaredLicense,
		certifylegal.FieldDiscoveredLicense,
		certifylegal.FieldAttribution,
		certifylegal.FieldJustification,
		certifylegal.FieldTimeScanned,
		certifylegal.FieldOrigin,
		certifylegal.FieldCollector,
		certifylegal.FieldDeclaredLicensesHash,
		certifylegal.FieldDiscoveredLicensesHash,
	}

	var conflictWhere *sql.Predicate

	if len(subjects.Packages) > 0 {
		certifyLegalConflictColumns = append(certifyLegalConflictColumns, certifylegal.FieldPackageID)
		conflictWhere = sql.And(
			sql.NotNull(certifylegal.FieldPackageID),
			sql.IsNull(certifylegal.FieldSourceID),
		)
	} else if len(subjects.Sources) > 0 {
		certifyLegalConflictColumns = append(certifyLegalConflictColumns, certifylegal.FieldSourceID)
		conflictWhere = sql.And(
			sql.IsNull(certifylegal.FieldPackageID),
			sql.NotNull(certifylegal.FieldSourceID),
		)
	} else {
		return nil, gqlerror.Errorf("%v :: %s", "upsertBulkCertifyLegal", "subject must be either a package or source")
	}

	batches := chunk(certifyLegals, 100)

	index := 0
	for _, cls := range batches {
		creates := make([]*ent.CertifyLegalCreate, len(cls))
		for i, cl := range cls {
			cl := cl
			var err error
			if len(subjects.Packages) > 0 {
				creates[i], err = generateCertifyLegalCreate(ctx, tx, cl, subjects.Packages[index], nil, declaredLicensesList[index], discoveredLicensesList[index])
				if err != nil {
					return nil, gqlerror.Errorf("generateCertifyLegalCreate :: %s", err)
				}

			} else if len(subjects.Sources) > 0 {
				creates[i], err = generateCertifyLegalCreate(ctx, tx, cl, nil, subjects.Sources[index], declaredLicensesList[index], discoveredLicensesList[index])
				if err != nil {
					return nil, gqlerror.Errorf("generateCertifyLegalCreate :: %s", err)
				}
			} else {
				return nil, gqlerror.Errorf("%v :: %s", "upsertBulkCertifyLegal", "subject must be either a package or source")
			}
			index++
		}

		err := tx.CertifyLegal.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(certifyLegalConflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert certifyLegal node")
		}
	}

	return &ids, nil
}

func certifyLegalQuery(filter model.CertifyLegalSpec) predicate.CertifyLegal {
	predicates := []predicate.CertifyLegal{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.DeclaredLicense, certifylegal.DeclaredLicenseEqualFold),
		optionalPredicate(filter.DiscoveredLicense, certifylegal.DiscoveredLicenseEqualFold),
		optionalPredicate(filter.Attribution, certifylegal.Attribution),
		optionalPredicate(filter.Justification, certifylegal.JustificationEqualFold),
		optionalPredicate(filter.TimeScanned, certifylegal.TimeScannedEQ),
		optionalPredicate(filter.Origin, certifylegal.OriginEqualFold),
		optionalPredicate(filter.Collector, certifylegal.CollectorEqualFold),
	}

	if filter.Subject != nil {
		if filter.Subject.Package != nil {
			predicates = append(predicates,
				certifylegal.HasPackageWith(
					optionalPredicate(filter.Subject.Package.ID, IDEQ),
					optionalPredicate(filter.Subject.Package.Version, packageversion.VersionEqualFold),
					packageversion.QualifiersMatch(filter.Subject.Package.Qualifiers, ptrWithDefault(filter.Subject.Package.MatchOnlyEmptyQualifiers, false)),
					optionalPredicate(filter.Subject.Package.Subpath, packageversion.SubpathEqualFold),
					packageversion.HasNameWith(
						optionalPredicate(filter.Subject.Package.Name, packagename.NameEqualFold),
						optionalPredicate(filter.Subject.Package.Namespace, packagename.NamespaceEqualFold),
						optionalPredicate(filter.Subject.Package.Type, packagename.TypeEqualFold),
					),
				),
			)
		} else if filter.Subject.Source != nil {
			predicates = append(predicates,
				certifylegal.HasSourceWith(
					optionalPredicate(filter.Subject.Source.ID, IDEQ),
					optionalPredicate(filter.Subject.Source.Type, sourcename.TypeEqualFold),
					optionalPredicate(filter.Subject.Source.Namespace, sourcename.NamespaceEqualFold),
					optionalPredicate(filter.Subject.Source.Name, sourcename.NameEqualFold),
					optionalPredicate(filter.Subject.Source.Tag, sourcename.TagEqualFold),
					optionalPredicate(filter.Subject.Source.Commit, sourcename.CommitEqualFold),
				),
			)
		}
	}

	declaredLicensePredicate := make([]predicate.License, 0)
	for _, dl := range filter.DeclaredLicenses {
		declaredLicensePredicate = append(declaredLicensePredicate,
			optionalPredicate(dl.ID, IDEQ),
			optionalPredicate(dl.Name, license.NameEqualFold),
			optionalPredicate(dl.Inline, license.InlineEqualFold),
			optionalPredicate(dl.ListVersion, license.ListVersion),
		)
	}
	if len(declaredLicensePredicate) > 0 {
		predicates = append(predicates, certifylegal.HasDeclaredLicensesWith(declaredLicensePredicate...))
	}

	discoveredLicensePredicate := make([]predicate.License, 0)
	for _, dl := range filter.DiscoveredLicenses {
		discoveredLicensePredicate = append(discoveredLicensePredicate,
			optionalPredicate(dl.ID, IDEQ),
			optionalPredicate(dl.Name, license.NameEqualFold),
			optionalPredicate(dl.Inline, license.InlineEqualFold),
			optionalPredicate(dl.ListVersion, license.ListVersion),
		)
	}
	if len(discoveredLicensePredicate) > 0 {
		predicates = append(predicates, certifylegal.HasDiscoveredLicensesWith(discoveredLicensePredicate...))
	}

	return certifylegal.And(predicates...)
}

func canonicalCertifyLegalString(cl *model.CertifyLegalInputSpec) string {
	return fmt.Sprintf("%s::%s::%s::%s::%s::%s::%s", cl.DeclaredLicense, cl.DiscoveredLicense, cl.Attribution, cl.Justification, cl.TimeScanned.UTC(), cl.Origin, cl.Collector)
}

// guacCertifyLegalKey generates an uuid based on the hash of the inputspec and inputs. certifyLegal ID has to be set for bulk ingestion
// when ingesting multiple edges otherwise you get "violates foreign key constraint" as it creates
// a new ID for certifyLegal node (even when already ingested) that it maps to the edge and fails the look up. This only occurs when using UUID with
// "Default" func to generate a new UUID
func guacCertifyLegalKey(pkgVersionID *string, srcNameID *string, declaredLicenseHash, discoveredLicenseHash string, clInput *model.CertifyLegalInputSpec) (*uuid.UUID, error) {
	var subjectID string
	if pkgVersionID != nil {
		subjectID = *pkgVersionID
	} else if srcNameID != nil {
		subjectID = *srcNameID
	} else {
		return nil, gqlerror.Errorf("%v :: %s", "guacCertifyLegalKey", "subject must be either a package or source")
	}

	clIDString := fmt.Sprintf("%s::%s::%s::%s?", subjectID, declaredLicenseHash, discoveredLicenseHash, canonicalCertifyLegalString(clInput))

	clID := generateUUIDKey([]byte(clIDString))
	return &clID, nil
}

// func certifyLegalInputQuery(subject model.PackageOrSourceInput, declaredLicenses []*model.IDorLicenseInput, discoveredLicenses []*model.IDorLicenseInput, filter model.CertifyLegalInputSpec) predicate.CertifyLegal {
// 	var subjectSpec *model.PackageOrSourceSpec
// 	if subject.Package != nil {
// 		subjectSpec = &model.PackageOrSourceSpec{
// 			Package: helper.ConvertPkgInputSpecToPkgSpec(subject.Package.PackageInput),
// 		}
// 	} else {
// 		subjectSpec = &model.PackageOrSourceSpec{
// 			Source: helper.ConvertSrcInputSpecToSrcSpec(subject.Source.SourceInput),
// 		}
// 	}
// 	declaredLicenseSpecs := collect(declaredLicenses, helper.ConvertLicenseInputSpecToLicenseSpec)
// 	discoveredLicenseSpecs := collect(discoveredLicenses, helper.ConvertLicenseInputSpecToLicenseSpec)
// 	return certifyLegalQuery(model.CertifyLegalSpec{
// 		Subject:            subjectSpec,
// 		DeclaredLicense:    &filter.DeclaredLicense,
// 		DeclaredLicenses:   declaredLicenseSpecs,
// 		DiscoveredLicense:  &filter.DiscoveredLicense,
// 		DiscoveredLicenses: discoveredLicenseSpecs,
// 		Attribution:        &filter.Attribution,
// 		Justification:      &filter.Justification,
// 		TimeScanned:        &filter.TimeScanned,
// 		Origin:             &filter.Origin,
// 		Collector:          &filter.Collector,
// 	})
// }
