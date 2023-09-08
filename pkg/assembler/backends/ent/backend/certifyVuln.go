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

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvuln"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagetype"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilitytype"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IngestCertifyVuln(ctx context.Context, pkg model.PkgInputSpec, spec model.VulnerabilityInputSpec, certifyVuln model.ScanMetadataInput) (*model.CertifyVuln, error) {

	record, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		client := ent.TxFromContext(ctx)
		insert := client.CertifyVuln.Create()

		columns := []string{
			certifyvuln.FieldPackageID,
			certifyvuln.FieldCollector,
			certifyvuln.FieldScannerURI,
			certifyvuln.FieldScannerVersion,
			certifyvuln.FieldOrigin,
			certifyvuln.FieldDbURI,
			certifyvuln.FieldDbVersion,
		}

		vuln, err := getVulnerabilityFromInput(ctx, client.Client(), spec)
		if err != nil {
			return nil, err
		}
		insert.SetVulnerability(vuln)
		columns = append(columns, certifyvuln.FieldVulnerabilityID)

		pv, err := getPkgVersion(ctx, client.Client(), pkg)
		if err != nil {
			return nil, err
		}

		insert.
			SetPackage(pv).
			SetCollector(certifyVuln.Collector).
			SetDbURI(certifyVuln.DbURI).
			SetDbVersion(certifyVuln.DbVersion).
			SetOrigin(certifyVuln.Origin).
			SetScannerURI(certifyVuln.ScannerURI).
			SetScannerVersion(certifyVuln.ScannerVersion).
			SetTimeScanned(certifyVuln.TimeScanned)

		id, err := insert.
			OnConflict(
				sql.ConflictColumns(columns...),
			).
			Ignore().
			ID(ctx)
		if err != nil {
			return nil, err
		}

		return &id, nil
	})
	if err != nil {
		return nil, err
	}

	return &model.CertifyVuln{ID: nodeID(*record)}, nil
}

func (b *EntBackend) IngestCertifyVulns(ctx context.Context, pkgs []*model.PkgInputSpec, vulnerabilities []*model.VulnerabilityInputSpec, certifyVulns []*model.ScanMetadataInput) ([]*model.CertifyVuln, error) {
	var modelCertifyVulns []*model.CertifyVuln
	for i, certifyVuln := range certifyVulns {
		modelCertifyVuln, err := b.IngestCertifyVuln(ctx, *pkgs[i], *vulnerabilities[i], *certifyVuln)
		if err != nil {
			return nil, gqlerror.Errorf("IngestVulnerability failed with err: %v", err)
		}
		modelCertifyVulns = append(modelCertifyVulns, modelCertifyVuln)
	}
	return modelCertifyVulns, nil
}

func getVulnerability(ctx context.Context, client *ent.Client, query model.VulnerabilitySpec) (*ent.VulnerabilityID, error) {
	results, err := getVulnerabilities(ctx, client, query)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, &ent.NotFoundError{}
	}

	if len(results) > 1 {
		return nil, &ent.NotSingularError{}
	}

	return results[0].Edges.VulnerabilityIds[0], nil
}

func getVulnerabilityFromInput(ctx context.Context, client *ent.Client, spec model.VulnerabilityInputSpec) (*ent.VulnerabilityID, error) {
	var vuln *ent.VulnerabilityID
	vuln, err := getVulnerability(ctx, client, model.VulnerabilitySpec{
		Type:            &spec.Type,
		VulnerabilityID: &spec.VulnerabilityID,
	})
	if err != nil {
		return nil, err
	}
	return vuln, nil
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
					packagename.HasNamespaceWith(
						optionalPredicate(pkg.Namespace, packagenamespace.Namespace),
						packagenamespace.HasPackageWith(
							optionalPredicate(pkg.Type, packagetype.Type),
						),
					),
				),
			)
		}),
		optionalPredicate(spec.Vulnerability, func(vuln model.VulnerabilitySpec) predicate.CertifyVuln {
			return certifyvuln.HasVulnerabilityWith(
				optionalPredicate(vuln.VulnerabilityID, vulnerabilityid.VulnerabilityIDEqualFold),
				optionalPredicate(vuln.Type, func(vulnID string) predicate.VulnerabilityID {
					return vulnerabilityid.HasTypeWith(
						optionalPredicate(&vulnID, vulnerabilitytype.TypeEqualFold),
					)
				}),
			)
		}),
	}

	if spec.Vulnerability != nil &&
		spec.Vulnerability.NoVuln != nil {
		if *spec.Vulnerability.NoVuln {
			predicates = append(predicates,
				certifyvuln.HasVulnerabilityWith(
					vulnerabilityid.HasTypeWith(vulnerabilitytype.TypeEqualFold(NoVuln)),
				),
			)
		} else {
			predicates = append(predicates,
				certifyvuln.HasVulnerabilityWith(
					vulnerabilityid.HasTypeWith(vulnerabilitytype.TypeNEQ(NoVuln)),
				),
			)
		}
	}

	records, err := b.client.CertifyVuln.Query().
		Where(predicates...).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {
				q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
					q.WithPackage()
				})
			})
		}).
		WithVulnerability(func(query *ent.VulnerabilityIDQuery) {
			query.WithType()
		}).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelCertifyVulnerability), nil
}

func toModelCertifyVulnerability(record *ent.CertifyVuln) *model.CertifyVuln {
	return &model.CertifyVuln{
		ID:            nodeID(record.ID),
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
