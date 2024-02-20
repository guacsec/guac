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
	"bytes"
	"context"
	"crypto/sha1"
	stdsql "database/sql"
	"fmt"
	"sort"

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
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkCertifyLegal(ctx, client, subjects, declaredLicensesList, discoveredLicensesList, certifyLegals)
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

func (b *EntBackend) IngestCertifyLegal(ctx context.Context, subject model.PackageOrSourceInput, declaredLicenses []*model.IDorLicenseInput, discoveredLicenses []*model.IDorLicenseInput, spec *model.CertifyLegalInputSpec) (string, error) {

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)
		client := tx.Client()

		certifyLegalCreate := client.CertifyLegal.Create().
			SetDeclaredLicense(spec.DeclaredLicense).
			SetDiscoveredLicense(spec.DiscoveredLicense).
			SetAttribution(spec.Attribution).
			SetJustification(spec.Justification).
			SetTimeScanned(spec.TimeScanned).
			SetOrigin(spec.Origin).
			SetCollector(spec.Collector)

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
			if subject.Package.PackageVersionID == nil {
				return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
			}
			pkgVersionID, err := uuid.Parse(*subject.Package.PackageVersionID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
			}
			certifyLegalCreate.SetPackageID(pkgVersionID)
			certifyLegalConflictColumns = append(certifyLegalConflictColumns, certifylegal.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(certifylegal.FieldPackageID),
				sql.IsNull(certifylegal.FieldSourceID),
			)
		} else if subject.Source != nil {
			if subject.Source.SourceNameID == nil {
				return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
			}
			sourceID, err := uuid.Parse(*subject.Source.SourceNameID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from SourceNameID failed with error: %w", err)
			}
			certifyLegalCreate.SetSourceID(sourceID)
			certifyLegalConflictColumns = append(certifyLegalConflictColumns, certifylegal.FieldSourceID)
			conflictWhere = sql.And(
				sql.IsNull(certifylegal.FieldPackageID),
				sql.NotNull(certifylegal.FieldSourceID),
			)
		}

		declaredLicenseIDs := make([]uuid.UUID, len(declaredLicenses))
		for i := range declaredLicenses {
			if declaredLicenses[i].LicenseID == nil {
				return nil, fmt.Errorf("LicenseID not specified in declaredLicenses")
			}
			licenseID, err := uuid.Parse(*declaredLicenses[i].LicenseID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from LicenseID failed with error: %w", err)
			}
			declaredLicenseIDs[i] = licenseID
		}
		certifyLegalCreate.SetDeclaredLicensesHash(hashLicenseIDs(declaredLicenseIDs))
		certifyLegalCreate.AddDeclaredLicenseIDs(declaredLicenseIDs...)

		discoveredLicenseIDs := make([]uuid.UUID, len(discoveredLicenses))
		for i := range discoveredLicenses {
			if discoveredLicenses[i].LicenseID == nil {
				return nil, fmt.Errorf("LicenseID not specified in discoveredLicenses")
			}
			licenseID, err := uuid.Parse(*discoveredLicenses[i].LicenseID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from LicenseID failed with error: %w", err)
			}
			discoveredLicenseIDs[i] = licenseID
		}
		certifyLegalCreate.SetDiscoveredLicensesHash(hashLicenseIDs(discoveredLicenseIDs))
		certifyLegalCreate.AddDiscoveredLicenseIDs(discoveredLicenseIDs...)

		_, err := certifyLegalCreate.
			OnConflict(
				sql.ConflictColumns(certifyLegalConflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			ID(ctx)
		if err != nil {
			if err != stdsql.ErrNoRows {
				return nil, errors.Wrap(err, "upsert certify legal node")
			}
		}

		return ptrfrom.String(""), nil
	})
	if err != nil {
		return "", gqlerror.Errorf("IngestCertifyLegal :: %s", err)
	}

	return *recordID, nil
}

func upsertBulkCertifyLegal(ctx context.Context, client *ent.Tx, subjects model.PackageOrSourceInputs, declaredLicensesList [][]*model.IDorLicenseInput, discoveredLicensesList [][]*model.IDorLicenseInput, certifyLegals []*model.CertifyLegalInputSpec) (*[]string, error) {
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
	}

	batches := chunk(certifyLegals, 100)

	index := 0
	for _, cbs := range batches {
		creates := make([]*ent.CertifyLegalCreate, len(cbs))
		for i, cb := range cbs {
			creates[i] = client.CertifyLegal.Create().
				SetDeclaredLicense(cb.DeclaredLicense).
				SetDiscoveredLicense(cb.DiscoveredLicense).
				SetAttribution(cb.Attribution).
				SetJustification(cb.Justification).
				SetTimeScanned(cb.TimeScanned).
				SetOrigin(cb.Origin).
				SetCollector(cb.Collector)

			if len(subjects.Packages) > 0 {
				if subjects.Packages[index].PackageVersionID == nil {
					return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
				}
				pkgVersionID, err := uuid.Parse(*subjects.Packages[index].PackageVersionID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
				}
				creates[i].SetPackageID(pkgVersionID)
			} else if len(subjects.Sources) > 0 {
				if subjects.Sources[index].SourceNameID == nil {
					return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
				}
				sourceID, err := uuid.Parse(*subjects.Sources[index].SourceNameID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
				}
				creates[i].SetSourceID(sourceID)
			}

			declaredLicenseIDs := make([]uuid.UUID, len(declaredLicensesList[index]))
			for i := range declaredLicensesList[index] {
				if declaredLicensesList[index][i].LicenseID == nil {
					return nil, fmt.Errorf("LicenseID not specified in declaredLicenses")
				}
				licenseID, err := uuid.Parse(*declaredLicensesList[index][i].LicenseID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from LicenseID failed with error: %w", err)
				}
				declaredLicenseIDs[i] = licenseID
			}
			creates[i].SetDeclaredLicensesHash(hashLicenseIDs(declaredLicenseIDs))
			creates[i].AddDeclaredLicenseIDs(declaredLicenseIDs...)

			discoveredLicenseIDs := make([]uuid.UUID, len(discoveredLicensesList[index]))
			for i := range discoveredLicensesList[index] {
				if discoveredLicensesList[index][i].LicenseID == nil {
					return nil, fmt.Errorf("LicenseID not specified in discoveredLicenses")
				}
				licenseID, err := uuid.Parse(*discoveredLicensesList[index][i].LicenseID)
				if err != nil {
					return nil, fmt.Errorf("uuid conversion from LicenseID failed with error: %w", err)
				}
				discoveredLicenseIDs[i] = licenseID
			}
			creates[i].SetDiscoveredLicensesHash(hashLicenseIDs(discoveredLicenseIDs))
			creates[i].AddDiscoveredLicenseIDs(discoveredLicenseIDs...)

			index++
		}

		err := client.CertifyLegal.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(certifyLegalConflictColumns...),
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

// hashLicenses is used to create a unique key for the M2M edge between CertifyLegal <-M2M-> License
func hashLicenseIDs(licenses []uuid.UUID) string {
	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	sort.Slice(licenses, func(i, j int) bool { return licenses[i].String() < licenses[j].String() })

	for _, v := range licenses {
		content.WriteString(fmt.Sprintf("%d", v.String()))
	}

	hash.Write(content.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
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

func certifyLegalInputQuery(subject model.PackageOrSourceInput, declaredLicenses []*model.IDorLicenseInput, discoveredLicenses []*model.IDorLicenseInput, filter model.CertifyLegalInputSpec) predicate.CertifyLegal {
	var subjectSpec *model.PackageOrSourceSpec
	if subject.Package != nil {
		subjectSpec = &model.PackageOrSourceSpec{
			Package: helper.ConvertPkgInputSpecToPkgSpec(subject.Package.PackageInput),
		}
	} else {
		subjectSpec = &model.PackageOrSourceSpec{
			Source: helper.ConvertSrcInputSpecToSrcSpec(subject.Source.SourceInput),
		}
	}
	declaredLicenseSpecs := collect(declaredLicenses, helper.ConvertLicenseInputSpecToLicenseSpec)
	discoveredLicenseSpecs := collect(discoveredLicenses, helper.ConvertLicenseInputSpecToLicenseSpec)
	return certifyLegalQuery(model.CertifyLegalSpec{
		Subject:            subjectSpec,
		DeclaredLicense:    &filter.DeclaredLicense,
		DeclaredLicenses:   declaredLicenseSpecs,
		DiscoveredLicense:  &filter.DiscoveredLicense,
		DiscoveredLicenses: discoveredLicenseSpecs,
		Attribution:        &filter.Attribution,
		Justification:      &filter.Justification,
		TimeScanned:        &filter.TimeScanned,
		Origin:             &filter.Origin,
		Collector:          &filter.Collector,
	})
}
