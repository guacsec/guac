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
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifylegal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/license"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagetype"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcetype"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) CertifyLegal(ctx context.Context, spec *model.CertifyLegalSpec) ([]*model.CertifyLegal, error) {

	records, err := b.client.CertifyLegal.Query().
		Where(certifyLegalQuery(*spec)).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {
				q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
					q.WithPackage()
				})
			})
		}).
		WithSource(func(q *ent.SourceNameQuery) {
			q.WithNamespace(func(q *ent.SourceNamespaceQuery) {
				q.WithSourceType()
			})
		}).
		WithDeclaredLicenses().
		WithDiscoveredLicenses().
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelCertifyLegal), nil
}

func (b *EntBackend) IngestCertifyLegals(ctx context.Context, subjects model.PackageOrSourceInputs, declaredLicensesList [][]*model.LicenseInputSpec, discoveredLicensesList [][]*model.LicenseInputSpec, certifyLegals []*model.CertifyLegalInputSpec) ([]*model.CertifyLegal, error) {
	var modelCertifyLegals []*model.CertifyLegal
	for i := range certifyLegals {
		var subject model.PackageOrSourceInput
		if len(subjects.Packages) > 0 {
			subject = model.PackageOrSourceInput{Package: subjects.Packages[i]}
		} else {
			subject = model.PackageOrSourceInput{Source: subjects.Sources[i]}
		}
		modelCertifyLegal, err := b.IngestCertifyLegal(ctx, subject, declaredLicensesList[i], discoveredLicensesList[i], certifyLegals[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestCertifyLegal failed with element #%v with err: %v", i, err)
		}
		modelCertifyLegals = append(modelCertifyLegals, modelCertifyLegal)
	}
	return modelCertifyLegals, nil
}

func (b *EntBackend) IngestCertifyLegal(ctx context.Context, subject model.PackageOrSourceInput, declaredLicenses []*model.LicenseInputSpec, discoveredLicenses []*model.LicenseInputSpec, spec *model.CertifyLegalInputSpec) (*model.CertifyLegal, error) {

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
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
			pkgVersion, err := getPkgVersion(ctx, client, *subject.Package)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get package version")
			}
			certifyLegalCreate.SetPackage(pkgVersion)
			certifyLegalConflictColumns = append(certifyLegalConflictColumns, certifylegal.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(certifylegal.FieldPackageID),
				sql.IsNull(certifylegal.FieldSourceID),
			)
		} else if subject.Source != nil {
			srcNameID, err := getSourceNameID(ctx, client, *subject.Source)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get source name ID")
			}
			certifyLegalCreate.SetSourceID(srcNameID)
			certifyLegalConflictColumns = append(certifyLegalConflictColumns, certifylegal.FieldSourceID)
			conflictWhere = sql.And(
				sql.IsNull(certifylegal.FieldPackageID),
				sql.NotNull(certifylegal.FieldSourceID),
			)
		}

		declaredLicenseIDs := make([]int, len(declaredLicenses))
		for i := range declaredLicenses {
			licenseID, err := getLicenseID(ctx, client, *declaredLicenses[i])
			if err != nil {
				return nil, errors.Wrap(err, "failed to get license ID")
			}
			declaredLicenseIDs[i] = licenseID
		}
		certifyLegalCreate.SetDeclaredLicensesHash(hashLicenseIDs(declaredLicenseIDs))
		certifyLegalCreate.AddDeclaredLicenseIDs(declaredLicenseIDs...)

		discoveredLicenseIDs := make([]int, len(discoveredLicenses))
		for i := range discoveredLicenses {
			licenseID, err := getLicenseID(ctx, client, *discoveredLicenses[i])
			if err != nil {
				return nil, err
			}
			discoveredLicenseIDs[i] = licenseID
		}
		certifyLegalCreate.SetDiscoveredLicensesHash(hashLicenseIDs(discoveredLicenseIDs))
		certifyLegalCreate.AddDiscoveredLicenseIDs(discoveredLicenseIDs...)

		id, err := certifyLegalCreate.
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
			id, err = client.CertifyLegal.Query().
				Where(certifyLegalInputQuery(subject, declaredLicenses, discoveredLicenses, *spec)).
				OnlyID(ctx)
			if err != nil {
				return nil, errors.Wrap(err, "get certify legal")
			}
		}

		return &id, nil
	})
	if err != nil {
		return nil, gqlerror.Errorf("IngestCertifyLegal :: %s", err)
	}

	return &model.CertifyLegal{ID: nodeID(*recordID)}, nil
}

// hashLicenses is used to create a unique key for the M2M edge between CertifyLegal <-M2M-> License
func hashLicenseIDs(licenses []int) string {
	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	sort.Slice(licenses, func(i, j int) bool { return licenses[i] < licenses[j] })

	for _, v := range licenses {
		content.WriteString(fmt.Sprintf("%d", v))
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
						packagename.HasNamespaceWith(
							optionalPredicate(filter.Subject.Package.Namespace, packagenamespace.NamespaceEqualFold),
							packagenamespace.HasPackageWith(
								optionalPredicate(filter.Subject.Package.Type, packagetype.TypeEqualFold),
							),
						),
					),
				),
			)
		} else if filter.Subject.Source != nil {
			predicates = append(predicates,
				certifylegal.HasSourceWith(
					optionalPredicate(filter.Subject.Source.ID, IDEQ),
					sourcename.HasNamespaceWith(
						optionalPredicate(filter.Subject.Source.Namespace, sourcenamespace.NamespaceEqualFold),
						sourcenamespace.HasSourceTypeWith(
							optionalPredicate(filter.Subject.Source.Type, sourcetype.TypeEqualFold),
						),
					),
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

func certifyLegalInputQuery(subject model.PackageOrSourceInput, declaredLicenses []*model.LicenseInputSpec, discoveredLicenses []*model.LicenseInputSpec, filter model.CertifyLegalInputSpec) predicate.CertifyLegal {
	var subjectSpec *model.PackageOrSourceSpec
	if subject.Package != nil {
		subjectSpec = &model.PackageOrSourceSpec{
			Package: helper.ConvertPkgInputSpecToPkgSpec(subject.Package),
		}
	} else {
		subjectSpec = &model.PackageOrSourceSpec{
			Source: helper.ConvertSrcInputSpecToSrcSpec(subject.Source),
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
