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
	"fmt"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvex"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/securityadvisory"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInput, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	funcName := "IngestVEXStatement"
	if err := helper.ValidatePackageOrArtifactInput(&subject, "IngestVEXStatement"); err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	if err := helper.ValidateVulnerabilityIngestionInput(vulnerability, "IngestVEXStatement", false); err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}

	err := validateVexInputBasedOnStatus(vexStatement.Status, vexStatement.VexJustification, vexStatement.Statement)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}

	record, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.CertifyVex, error) {
		client := ent.TxFromContext(ctx)
		insert := client.CertifyVex.Create()

		conflictColumns := []string{
			certifyvex.FieldKnownSince,
			certifyvex.FieldStatus,
			certifyvex.FieldStatement,
			certifyvex.FieldStatusNotes,
			certifyvex.FieldJustification,
			certifyvex.FieldOrigin,
			certifyvex.FieldCollector,
		}

		// manage vulnerability
		v, err := getAdvisoryFromVulnerabilityInput(ctx, client.Client(), vulnerability)
		if err != nil {
			return nil, err
		}
		insert.SetVulnerability(v)
		conflictColumns = append(conflictColumns, certifyvex.FieldVulnerabilityID)
		var conflictWhere = sql.And(sql.NotNull(certifyvex.FieldVulnerabilityID))

		// manage package or artifact
		if subject.Package != nil {
			p, err := getPkgVersion(ctx, client.Client(), *subject.Package)
			if err != nil {
				return nil, Errorf("%v ::  %s", funcName, err)
			}
			insert.SetPackage(p)
			conflictColumns = append(conflictColumns, certifyvex.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(certifyvex.FieldPackageID),
				sql.IsNull(certifyvex.FieldArtifactID),
			)
		} else if subject.Artifact != nil {
			art, err := client.Artifact.Query().
				Where(artifactQueryInputPredicates(*subject.Artifact)).
				Only(ctx)
			if err != nil {
				return nil, Errorf("%v ::  %s", funcName, err)
			}
			insert.SetArtifact(art)
			conflictColumns = append(conflictColumns, certifyvex.FieldArtifactID)
			conflictWhere = sql.And(
				sql.IsNull(certifyvex.FieldPackageID),
				sql.NotNull(certifyvex.FieldArtifactID),
			)
		} else {
			return nil, Errorf("%v :: %s", funcName, "subject must be either a package or artifact")
		}

		insert.
			SetKnownSince(vexStatement.KnownSince).
			SetStatus(vexStatement.Status.String()).
			SetStatement(vexStatement.Statement).
			SetStatusNotes(vexStatement.StatusNotes).
			SetJustification(vexStatement.VexJustification.String()).
			SetOrigin(vexStatement.Origin).
			SetCollector(vexStatement.Collector)

		id, err := insert.
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			Ignore().
			ID(ctx)
		if err != nil {
			return nil, err
		}

		return client.CertifyVex.Query().
			Where(certifyvex.IDEQ(id)).
			WithPackage(func(q *ent.PackageVersionQuery) {
				q.WithName(func(q *ent.PackageNameQuery) {
					q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
						q.WithPackage()
					})
				})
			}).
			WithVulnerability().
			Only(ctx)
	})

	if err != nil {
		return nil, err
	}

	return toModelCertifyVEXStatement(record), nil
}

func (b *EntBackend) CertifyVEXStatement(ctx context.Context, spec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	funcName := "CertifyVEXStatement"

	if spec != nil {
		if err := helper.ValidatePackageOrArtifactQueryFilter(spec.Subject); err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if err := helper.ValidateVulnerabilityQueryFilter(spec.Vulnerability, false); err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
	}

	query := b.client.CertifyVex.Query()
	predicates := []predicate.CertifyVex{
		optionalPredicate(spec.ID, IDEQ),
		optionalPredicate(spec.KnownSince, certifyvex.KnownSinceEQ),
		optionalPredicate(spec.Statement, certifyvex.StatementEQ),
		optionalPredicate(spec.StatusNotes, certifyvex.StatusNotesEQ),
		optionalPredicate(spec.Collector, certifyvex.CollectorEQ),
		optionalPredicate(spec.Origin, certifyvex.OriginEQ),
	}
	if spec.Status != nil {
		status := spec.Status.String()
		predicates = append(predicates, optionalPredicate(&status, certifyvex.StatusEQ))
	}
	if spec.VexJustification != nil {
		justification := spec.VexJustification.String()
		predicates = append(predicates, optionalPredicate(&justification, certifyvex.JustificationEQ))
	}

	if spec.Subject != nil {
		if spec.Subject.Package != nil {
			predicates = append(predicates, certifyvex.HasPackageWith(packageVersionQuery(spec.Subject.Package)))
		} else if spec.Subject.Artifact != nil {
			predicates = append(predicates, certifyvex.HasArtifactWith(artifactQueryPredicates(spec.Subject.Artifact)))
		}
	}

	if spec.Vulnerability != nil {
		if spec.Vulnerability.Cve != nil {
			predicates = append(predicates, certifyvex.HasVulnerabilityWith(securityadvisory.CveIDNotNil()))
			predicates = append(predicates, certifyvex.HasVulnerabilityWith(optionalPredicate(spec.Vulnerability.Cve.CveID, securityadvisory.CveIDEqualFold)))
			predicates = append(predicates, certifyvex.HasVulnerabilityWith(optionalPredicate(spec.Vulnerability.Cve.Year, securityadvisory.CveYearEQ)))
			predicates = append(predicates, certifyvex.HasVulnerabilityWith(optionalPredicate(spec.Vulnerability.Cve.ID, IDEQ)))
		} else if spec.Vulnerability.Ghsa != nil {
			predicates = append(predicates, certifyvex.HasVulnerabilityWith(securityadvisory.GhsaIDNotNil()))
			predicates = append(predicates, certifyvex.HasVulnerabilityWith(optionalPredicate(spec.Vulnerability.Ghsa.GhsaID, securityadvisory.GhsaIDEqualFold)))
			predicates = append(predicates, certifyvex.HasVulnerabilityWith(optionalPredicate(spec.Vulnerability.Ghsa.ID, IDEQ)))
		} else if spec.Vulnerability.Osv != nil {
			predicates = append(predicates, certifyvex.HasVulnerabilityWith(securityadvisory.OsvIDNotNil()))
			predicates = append(predicates, certifyvex.HasVulnerabilityWith(optionalPredicate(spec.Vulnerability.Osv.OsvID, securityadvisory.OsvIDEqualFold)))
			predicates = append(predicates, certifyvex.HasVulnerabilityWith(optionalPredicate(spec.Vulnerability.Osv.ID, IDEQ)))
		}
	}

	records, err := query.
		Where(predicates...).
		WithVulnerability().
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {
				q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
					q.WithPackage()
				})
			})
		}).
		WithArtifact().
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %v", funcName, err)
	}

	return collect(records, toModelCertifyVEXStatement), nil
}

func validateVexInputBasedOnStatus(status model.VexStatus, justification model.VexJustification, statement string) error {
	if status == model.VexStatusNotAffected && justification == model.VexJustificationNotProvided && statement == "" {
		return fmt.Errorf("for [status] “not_affected”, if [justification] is not provided then [statement] MUST be provided")
	} else if status == model.VexStatusAffected && justification == model.VexJustificationNotProvided && statement == "" {
		return fmt.Errorf("for [status] “affected”, MUST include one [statement]")
	}
	return nil
}

func toModelCertifyVEXStatement(record *ent.CertifyVex) *model.CertifyVEXStatement {
	var vuln model.Vulnerability

	switch {
	case record.Edges.Vulnerability.CveID != nil:
		vuln = toModelCVE(record.Edges.Vulnerability)
	case record.Edges.Vulnerability.GhsaID != nil:
		vuln = toModelGHSA(record.Edges.Vulnerability)
	case record.Edges.Vulnerability.OsvID != nil:
		vuln = toModelOSV(record.Edges.Vulnerability)
	}

	return &model.CertifyVEXStatement{
		ID:               nodeID(record.ID),
		Subject:          toPackageOrArtifact(record.Edges.Package, record.Edges.Artifact),
		Vulnerability:    vuln,
		KnownSince:       record.KnownSince,
		Status:           model.VexStatus(record.Status),
		Statement:        record.Statement,
		StatusNotes:      record.StatusNotes,
		VexJustification: model.VexJustification(record.Justification),
		Origin:           record.Origin,
		Collector:        record.Collector,
	}

}
