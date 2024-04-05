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
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IngestCertifyVuln(ctx context.Context, pkg model.IDorPkgInput, vulnerability model.IDorVulnerabilityInput, certifyVuln model.ScanMetadataInput) (string, error) {

	record, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)

		conflictColumns := []string{
			certifyvuln.FieldPackageID,
			certifyvuln.FieldVulnerabilityID,
			certifyvuln.FieldCollector,
			certifyvuln.FieldScannerURI,
			certifyvuln.FieldScannerVersion,
			certifyvuln.FieldOrigin,
			certifyvuln.FieldDbURI,
			certifyvuln.FieldDbVersion,
			certifyvuln.FieldTimeScanned,
		}

		insert, err := generateCertifyVulnCreate(ctx, tx, &pkg, &vulnerability, &certifyVuln)
		if err != nil {
			return nil, gqlerror.Errorf("generateCertifyVulnCreate :: %s", err)
		}

		if id, err := insert.
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
			).
			Ignore().
			ID(ctx); err != nil {
			return nil, errors.Wrap(err, "upsert certify Vuln statement node")
		} else {
			return ptrfrom.String(id.String()), nil
		}
	})
	if txErr != nil {
		return "", txErr
	}

	return toGlobalID(certifyvuln.Table, *record), nil
}

func (b *EntBackend) IngestCertifyVulns(ctx context.Context, pkgs []*model.IDorPkgInput, vulnerabilities []*model.IDorVulnerabilityInput, certifyVulns []*model.ScanMetadataInput) ([]string, error) {
	funcName := "IngestCertifyVulns"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkCertifyVuln(ctx, client, pkgs, vulnerabilities, certifyVulns)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return toGlobalIDs(certifyvuln.Table, *ids), nil
}

func generateCertifyVulnCreate(ctx context.Context, tx *ent.Tx, pkg *model.IDorPkgInput, vuln *model.IDorVulnerabilityInput, certifyVuln *model.ScanMetadataInput) (*ent.CertifyVulnCreate, error) {

	certifyVulnCreate := tx.CertifyVuln.Create()

	// manage vulnerability
	if vuln == nil {
		return nil, fmt.Errorf("vulnerability must be specified for vex ingestion")
	}
	var vulnID uuid.UUID
	if vuln.VulnerabilityNodeID != nil {
		var err error
		vulnGlobalID := fromGlobalID(*vuln.VulnerabilityNodeID)
		vulnID, err = uuid.Parse(vulnGlobalID.id)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from VulnerabilityNodeID failed with error: %w", err)
		}
	} else {
		foundVulnID, err := tx.VulnerabilityID.Query().
			Where(
				vulnerabilityid.VulnerabilityIDEqualFold(vuln.VulnerabilityInput.VulnerabilityID),
				vulnerabilityid.TypeEqualFold(vuln.VulnerabilityInput.Type),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, Errorf("%v ::  %s", "generateVexCreate", err)
		}
		vulnID = foundVulnID
	}
	certifyVulnCreate.SetVulnerabilityID(vulnID)

	// manage package or artifact
	if pkg == nil {
		return nil, Errorf("%v :: %s", "generateCertifyVulnCreate", "subject must be package")
	}
	var pkgVersionID uuid.UUID
	if pkg.PackageVersionID != nil {
		var err error
		pkgVersionGlobalID := fromGlobalID(*pkg.PackageVersionID)
		pkgVersionID, err = uuid.Parse(pkgVersionGlobalID.id)
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
	certifyVulnCreate.SetPackageID(pkgVersionID)

	certifyVulnCreate.
		SetCollector(certifyVuln.Collector).
		SetDbURI(certifyVuln.DbURI).
		SetDbVersion(certifyVuln.DbVersion).
		SetOrigin(certifyVuln.Origin).
		SetScannerURI(certifyVuln.ScannerURI).
		SetScannerVersion(certifyVuln.ScannerVersion).
		SetTimeScanned(certifyVuln.TimeScanned)

	return certifyVulnCreate, nil
}

func upsertBulkCertifyVuln(ctx context.Context, tx *ent.Tx, pkgs []*model.IDorPkgInput, vulnerabilities []*model.IDorVulnerabilityInput, certifyVulns []*model.ScanMetadataInput) (*[]string, error) {
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
		certifyvuln.FieldTimeScanned,
	}

	batches := chunk(certifyVulns, MaxBatchSize)

	index := 0
	for _, vulns := range batches {
		creates := make([]*ent.CertifyVulnCreate, len(vulns))
		for i, vuln := range vulns {
			vuln := vuln
			var err error
			creates[i], err = generateCertifyVulnCreate(ctx, tx, pkgs[index], vulnerabilities[index], vuln)
			if err != nil {
				return nil, gqlerror.Errorf("generateCertifyVulnCreate :: %s", err)
			}
			index++
		}

		err := tx.CertifyVuln.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert certifyVuln node")
		}
	}

	return &ids, nil
}

func (b *EntBackend) CertifyVuln(ctx context.Context, spec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	if spec == nil {
		spec = &model.CertifyVulnSpec{}
	}
	certVulnQuery := b.client.CertifyVuln.Query().
		Where(certifyVulnPredicate(*spec))

	records, err := getCertVulnObject(certVulnQuery).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelCertifyVulnerability), nil
}

func certifyVulnPredicate(spec model.CertifyVulnSpec) predicate.CertifyVuln {
	predicates := []predicate.CertifyVuln{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.Collector, certifyvuln.CollectorEQ),
		optionalPredicate(spec.Origin, certifyvuln.OriginEQ),
		optionalPredicate(spec.DbURI, certifyvuln.DbURIEQ),
		optionalPredicate(spec.DbVersion, certifyvuln.DbVersionEQ),
		optionalPredicate(spec.ScannerURI, certifyvuln.ScannerURIEQ),
		optionalPredicate(spec.ScannerVersion, certifyvuln.ScannerVersionEQ),
		optionalPredicate(spec.TimeScanned, certifyvuln.TimeScannedEQ),
		optionalPredicate(spec.Package, func(pkg model.PkgSpec) predicate.CertifyVuln {
			return certifyvuln.HasPackageWith(
				optionalPredicate(pkg.ID, IDEQ),
				optionalPredicate(pkg.Version, packageversion.VersionEQ),
				optionalPredicate(pkg.Subpath, packageversion.SubpathEQ),
				packageversion.QualifiersMatch(pkg.Qualifiers, ptrWithDefault(pkg.MatchOnlyEmptyQualifiers, false)),
				packageversion.HasNameWith(
					optionalPredicate(pkg.Name, packagename.NameEQ),
					optionalPredicate(pkg.Namespace, packagename.NamespaceEQ),
					optionalPredicate(pkg.Type, packagename.TypeEQ),
				),
			)
		}),
		optionalPredicate(spec.Vulnerability, func(vuln model.VulnerabilitySpec) predicate.CertifyVuln {
			return certifyvuln.HasVulnerabilityWith(
				optionalPredicate(vuln.ID, IDEQ),
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
	return certifyvuln.And(predicates...)
}

// getCertVulnObject is used recreate the CertifyVuln object be eager loading the edges
func getCertVulnObject(q *ent.CertifyVulnQuery) *ent.CertifyVulnQuery {
	return q.
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
		}).
		WithVulnerability(func(query *ent.VulnerabilityIDQuery) {})
}

func toModelCertifyVulnerability(record *ent.CertifyVuln) *model.CertifyVuln {
	return &model.CertifyVuln{
		ID:            toGlobalID(certifyvuln.Table, record.ID.String()),
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

func (b *EntBackend) certifyVulnNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.CertifyVuln.Query().
		Where(certifyVulnPredicate(model.CertifyVulnSpec{ID: &nodeID}))

	if allowedEdges[model.EdgeCertifyVulnPackage] {
		query.
			WithPackage(withPackageVersionTree())
	}
	if allowedEdges[model.EdgeCertifyVulnVulnerability] {
		query.
			WithVulnerability()
	}

	query.
		Limit(MaxPageSize)

	certVulns, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for certifyVuln with node ID: %s with error: %w", nodeID, err)
	}

	for _, foundVuln := range certVulns {
		if foundVuln.Edges.Package != nil {
			out = append(out, toModelPackage(backReferencePackageVersion(foundVuln.Edges.Package)))
		}
		if foundVuln.Edges.Vulnerability != nil {
			out = append(out, toModelVulnerabilityFromVulnerabilityID(foundVuln.Edges.Vulnerability))
		}
	}

	return out, nil
}
