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
	stdsql "database/sql"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvex"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilitytype"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInputSpec, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	funcName := "IngestVEXStatement"

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
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
		vulnID, err := client.VulnerabilityID.Query().
			Where(
				vulnerabilityid.VulnerabilityIDEqualFold(vulnerability.VulnerabilityID),
				vulnerabilityid.HasTypeWith(vulnerabilitytype.TypeEqualFold(vulnerability.Type)),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, Errorf("%v ::  %s", funcName, err)
		}
		insert.SetVulnerabilityID(vulnID)
		conflictColumns = append(conflictColumns, certifyvex.FieldVulnerabilityID)
		var conflictWhere *sql.Predicate

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
			artID, err := client.Artifact.Query().
				Where(artifactQueryInputPredicates(*subject.Artifact)).
				OnlyID(ctx)
			if err != nil {
				return nil, Errorf("%v ::  %s", funcName, err)
			}
			insert.SetArtifactID(artID)
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
			DoNothing().
			ID(ctx)
		if err != nil {
			if err != stdsql.ErrNoRows {
				return nil, errors.Wrap(err, "upsert certify vex statement node")
			}
			id, err = client.CertifyVex.Query().
				Where(vexStatementInputPredicate(subject, vulnerability, vexStatement)).
				WithPackage(func(q *ent.PackageVersionQuery) {
					q.WithName(func(q *ent.PackageNameQuery) {
						q.WithNamespace(func(q *ent.PackageNamespaceQuery) {
							q.WithPackage()
						})
					})
				}).
				WithVulnerability(func(q *ent.VulnerabilityIDQuery) {
					q.WithType()
				}).
				OnlyID(ctx)
			if err != nil {
				return nil, errors.Wrap(err, "get certify vex statement")
			}
		}
		return &id, nil
	})

	if err != nil {
		return nil, err
	}

	return &model.CertifyVEXStatement{ID: nodeID(*recordID)}, nil
}

func (b *EntBackend) IngestVEXStatements(ctx context.Context, subjects model.PackageOrArtifactInputs, vulnerabilities []*model.VulnerabilityInputSpec, vexStatements []*model.VexStatementInputSpec) ([]string, error) {
	var ids []string
	for i := range vexStatements {
		var subject model.PackageOrArtifactInput
		if len(subjects.Packages) > 0 {
			subject = model.PackageOrArtifactInput{Package: subjects.Packages[i]}
		} else {
			subject = model.PackageOrArtifactInput{Artifact: subjects.Artifacts[i]}
		}
		statement, err := b.IngestVEXStatement(ctx, subject, *vulnerabilities[i], *vexStatements[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestVEXStatements failed with element #%v with err: %v", i, err)
		}
		ids = append(ids, statement.ID)
	}
	return ids, nil
}

func (b *EntBackend) CertifyVEXStatement(ctx context.Context, spec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	funcName := "CertifyVEXStatement"

	query := b.client.CertifyVex.Query()
	records, err := query.
		Where(certifyVexPredicate(*spec)).
		WithVulnerability(func(q *ent.VulnerabilityIDQuery) {
			q.WithType()
		}).
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

func toModelCertifyVEXStatement(record *ent.CertifyVex) *model.CertifyVEXStatement {
	return &model.CertifyVEXStatement{
		ID:               nodeID(record.ID),
		Subject:          toPackageOrArtifact(record.Edges.Package, record.Edges.Artifact),
		Vulnerability:    toModelVulnerabilityFromVulnerabilityID(record.Edges.Vulnerability),
		KnownSince:       record.KnownSince,
		Status:           model.VexStatus(record.Status),
		Statement:        record.Statement,
		StatusNotes:      record.StatusNotes,
		VexJustification: model.VexJustification(record.Justification),
		Origin:           record.Origin,
		Collector:        record.Collector,
	}

}

func certifyVexPredicate(filter model.CertifyVEXStatementSpec) predicate.CertifyVex {
	predicates := []predicate.CertifyVex{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.KnownSince, certifyvex.KnownSinceEQ),
		optionalPredicate(filter.Statement, certifyvex.StatementEQ),
		optionalPredicate(filter.StatusNotes, certifyvex.StatusNotesEQ),
		optionalPredicate(filter.Collector, certifyvex.CollectorEQ),
		optionalPredicate(filter.Origin, certifyvex.OriginEQ),
	}
	if filter.Status != nil {
		status := filter.Status.String()
		predicates = append(predicates, optionalPredicate(&status, certifyvex.StatusEQ))
	}
	if filter.VexJustification != nil {
		justification := filter.VexJustification.String()
		predicates = append(predicates, optionalPredicate(&justification, certifyvex.JustificationEQ))
	}

	if filter.Subject != nil {
		if filter.Subject.Package != nil {
			predicates = append(predicates, certifyvex.HasPackageWith(packageVersionQuery(filter.Subject.Package)))
		} else if filter.Subject.Artifact != nil {
			predicates = append(predicates, certifyvex.HasArtifactWith(artifactQueryPredicates(filter.Subject.Artifact)))
		}
	}

	if filter.Vulnerability != nil {
		if filter.Vulnerability.NoVuln != nil && *filter.Vulnerability.NoVuln {
			predicates = append(predicates, certifyvex.Not(certifyvex.HasVulnerability()))
		} else {
			predicates = append(predicates,
				certifyvex.HasVulnerabilityWith(
					optionalPredicate(filter.Vulnerability.ID, IDEQ),
					optionalPredicate(filter.Vulnerability.VulnerabilityID, vulnerabilityid.VulnerabilityIDEqualFold),
					vulnerabilityid.HasTypeWith(
						optionalPredicate(filter.Vulnerability.Type, vulnerabilitytype.TypeEqualFold),
					),
				),
			)
		}
	}
	return certifyvex.And(predicates...)
}

func vexStatementInputPredicate(subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInputSpec, vexStatement model.VexStatementInputSpec) predicate.CertifyVex {
	var sub *model.PackageOrArtifactSpec
	if subject.Package != nil {
		sub = &model.PackageOrArtifactSpec{
			Package: helper.ConvertPkgInputSpecToPkgSpec(subject.Package),
		}
	} else {
		sub = &model.PackageOrArtifactSpec{
			Artifact: helper.ConvertArtInputSpecToArtSpec(subject.Artifact),
		}
	}
	return certifyVexPredicate(model.CertifyVEXStatementSpec{
		Subject: sub,
		Vulnerability: &model.VulnerabilitySpec{
			Type:            &vulnerability.Type,
			VulnerabilityID: &vulnerability.VulnerabilityID,
		},
		Status:           &vexStatement.Status,
		VexJustification: &vexStatement.VexJustification,
		Statement:        &vexStatement.Statement,
		StatusNotes:      &vexStatement.StatusNotes,
		KnownSince:       &vexStatement.KnownSince,
		Origin:           &vexStatement.Origin,
		Collector:        &vexStatement.Collector,
	})
}
