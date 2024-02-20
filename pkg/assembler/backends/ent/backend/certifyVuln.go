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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvuln"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IngestCertifyVuln(ctx context.Context, pkg model.IDorPkgInput, vulnerability model.IDorVulnerabilityInput, certifyVuln model.ScanMetadataInput) (string, error) {

	record, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		client := ent.TxFromContext(ctx)
		insert := client.CertifyVuln.Create()

		columns := []string{
			certifyvuln.FieldPackageID,
			certifyvuln.FieldVulnerabilityID,
			certifyvuln.FieldCollector,
			certifyvuln.FieldScannerURI,
			certifyvuln.FieldScannerVersion,
			certifyvuln.FieldOrigin,
			certifyvuln.FieldDbURI,
			certifyvuln.FieldDbVersion,
		}

		if vulnerability.VulnerabilityNodeID == nil {
			return nil, fmt.Errorf("VulnerabilityNodeID not specified in IDorVulnerabilityInput")
		}
		vulnID, err := uuid.Parse(*vulnerability.VulnerabilityNodeID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from VulnerabilityNodeID failed with error: %w", err)
		}
		insert.SetVulnerabilityID(vulnID)

		if pkg.PackageVersionID == nil {
			return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
		}
		pkgVersionID, err := uuid.Parse(*pkg.PackageVersionID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
		}

		insert.
			SetPackageID(pkgVersionID).
			SetCollector(certifyVuln.Collector).
			SetDbURI(certifyVuln.DbURI).
			SetDbVersion(certifyVuln.DbVersion).
			SetOrigin(certifyVuln.Origin).
			SetScannerURI(certifyVuln.ScannerURI).
			SetScannerVersion(certifyVuln.ScannerVersion).
			SetTimeScanned(certifyVuln.TimeScanned)

		if _, err := insert.
			OnConflict(
				sql.ConflictColumns(columns...),
			).
			Ignore().
			ID(ctx); err != nil {
			return nil, err
		}

		return ptrfrom.String(""), nil
	})
	if err != nil {
		return "", err
	}

	return *record, nil
}

func (b *EntBackend) IngestCertifyVulns(ctx context.Context, pkgs []*model.IDorPkgInput, vulnerabilities []*model.IDorVulnerabilityInput, certifyVulns []*model.ScanMetadataInput) ([]string, error) {
	funcName := "IngestCertifyVulns"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkCertifyVuln(ctx, client, pkgs, vulnerabilities, certifyVulns)
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

func upsertBulkCertifyVuln(ctx context.Context, client *ent.Tx, pkgs []*model.IDorPkgInput, vulnerabilities []*model.IDorVulnerabilityInput, certifyVulns []*model.ScanMetadataInput) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		certifyvuln.FieldPackageID,
		certifyvuln.FieldVulnerabilityID,
		certifyvuln.FieldCollector,
		certifyvuln.FieldScannerURI,
		certifyvuln.FieldScannerVersion,
		certifyvuln.FieldOrigin,
		certifyvuln.FieldDbURI,
		certifyvuln.FieldDbVersion,
	}

	batches := chunk(certifyVulns, 100)

	index := 0
	for _, vulns := range batches {
		creates := make([]*ent.CertifyVulnCreate, len(vulns))
		for i, vuln := range vulns {
			creates[i] = client.CertifyVuln.Create().
				SetCollector(vuln.Collector).
				SetDbURI(vuln.DbURI).
				SetDbVersion(vuln.DbVersion).
				SetOrigin(vuln.Origin).
				SetScannerURI(vuln.ScannerURI).
				SetScannerVersion(vuln.ScannerVersion).
				SetTimeScanned(vuln.TimeScanned)

			if pkgs[index].PackageVersionID == nil {
				return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
			}
			pkgVersionID, err := uuid.Parse(*pkgs[index].PackageVersionID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from string failed with error: %w", err)
			}
			creates[i].SetPackageID(pkgVersionID)

			if vulnerabilities[index].VulnerabilityNodeID == nil {
				return nil, fmt.Errorf("VulnerabilityNodeID not specified in IDorVulnerabilityInput")
			}
			vulnID, err := uuid.Parse(*vulnerabilities[index].VulnerabilityNodeID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from VulnerabilityNodeID failed with error: %w", err)
			}
			creates[i].SetVulnerabilityID(vulnID)

			index++
		}

		err := client.CertifyVuln.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, err
		}
	}

	return &ids, nil
}

func (b *EntBackend) CertifyVuln(ctx context.Context, spec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	predicates := []predicate.CertifyVuln{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.Collector, certifyvuln.CollectorEQ),
		optionalPredicate(spec.Origin, certifyvuln.OriginEQ),
		optionalPredicate(spec.DbURI, certifyvuln.DbURIEQ),
		optionalPredicate(spec.DbVersion, certifyvuln.DbVersionEQ),
		optionalPredicate(spec.ScannerURI, certifyvuln.ScannerURIEQ),
		optionalPredicate(spec.TimeScanned, certifyvuln.TimeScannedEQ),
		optionalPredicate(spec.Package, func(pkg model.PkgSpec) predicate.CertifyVuln {
			return certifyvuln.HasPackageWith(
				optionalPredicate(spec.ID, IDEQ),
				optionalPredicate(pkg.Version, packageversion.VersionEQ),
				optionalPredicate(pkg.Subpath, packageversion.SubpathEQ),
				packageversion.QualifiersMatch(pkg.Qualifiers, ptrWithDefault(pkg.MatchOnlyEmptyQualifiers, false)),

				packageversion.HasNameWith(
					optionalPredicate(pkg.Name, packagename.Name),
					optionalPredicate(pkg.Namespace, packagename.Namespace),
					optionalPredicate(pkg.Type, packagename.Type),
				),
			)
		}),
		optionalPredicate(spec.Vulnerability, func(vuln model.VulnerabilitySpec) predicate.CertifyVuln {
			return certifyvuln.HasVulnerabilityWith(
				optionalPredicate(vuln.VulnerabilityID, vulnerabilityid.VulnerabilityIDEqualFold),
				optionalPredicate(vuln.Type, vulnerabilityid.TypeEqualFold),
			)
		}),
	}

	if spec.Vulnerability != nil &&
		spec.Vulnerability.NoVuln != nil {
		if *spec.Vulnerability.NoVuln {
			predicates = append(predicates,
				certifyvuln.HasVulnerabilityWith(
					vulnerabilityid.TypeEqualFold(NoVuln),
				),
			)
		} else {
			predicates = append(predicates,
				certifyvuln.HasVulnerabilityWith(
					vulnerabilityid.TypeNEQ(NoVuln),
				),
			)
		}
	}

	records, err := b.client.CertifyVuln.Query().
		Where(predicates...).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
		}).
		WithVulnerability(func(query *ent.VulnerabilityIDQuery) {}).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelCertifyVulnerability), nil
}

func toModelCertifyVulnerability(record *ent.CertifyVuln) *model.CertifyVuln {
	return &model.CertifyVuln{
		ID:            record.ID.String(),
		Package:       toModelPackage(backReferencePackageVersion(record.Edges.Package)),
		Vulnerability: toModelVulnerabilityFromVulnerabilityID(record.Edges.Vulnerability),
		Metadata: &model.ScanMetadata{
			TimeScanned:    record.TimeScanned,
			DbURI:          record.DbURI,
			DbVersion:      record.DbVersion,
			ScannerURI:     record.ScannerURI,
			ScannerVersion: record.ScannerVersion,
			Origin:         record.Origin,
			Collector:      record.Collector,
		},
	}

}
