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
	"fmt"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvex"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.IDorVulnerabilityInput, vexStatement model.VexStatementInputSpec) (string, error) {
	funcName := "IngestVEXStatement"

	recordID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)
		conflictColumns := []string{
			certifyvex.FieldKnownSince,
			certifyvex.FieldStatus,
			certifyvex.FieldStatement,
			certifyvex.FieldStatusNotes,
			certifyvex.FieldJustification,
			certifyvex.FieldOrigin,
			certifyvex.FieldCollector,
			certifyvex.FieldVulnerabilityID,
		}

		var conflictWhere *sql.Predicate

		if subject.Package != nil {
			conflictColumns = append(conflictColumns, certifyvex.FieldPackageID)
			conflictWhere = sql.And(
				sql.NotNull(certifyvex.FieldPackageID),
				sql.IsNull(certifyvex.FieldArtifactID),
			)
		} else if subject.Artifact != nil {
			conflictColumns = append(conflictColumns, certifyvex.FieldArtifactID)
			conflictWhere = sql.And(
				sql.IsNull(certifyvex.FieldPackageID),
				sql.NotNull(certifyvex.FieldArtifactID),
			)
		} else {
			return nil, Errorf("%v :: %s", funcName, "subject must be either a package or artifact")
		}

		insert, err := generateVexCreate(tx, subject.Package, subject.Artifact, &vulnerability, &vexStatement)
		if err != nil {
			return nil, gqlerror.Errorf("generateVexCreate :: %s", err)
		}

		if _, err := insert.
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			DoNothing().
			ID(ctx); err != nil {

			if err != stdsql.ErrNoRows {
				return nil, errors.Wrap(err, "upsert certify vex statement node")
			}
		}
		return ptrfrom.String(""), nil
	})

	if err != nil {
		return "", err
	}

	return *recordID, nil
}

func (b *EntBackend) IngestVEXStatements(ctx context.Context, subjects model.PackageOrArtifactInputs, vulnerabilities []*model.IDorVulnerabilityInput, vexStatements []*model.VexStatementInputSpec) ([]string, error) {
	funcName := "IngestVEXStatements"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkVEX(ctx, client, subjects, vulnerabilities, vexStatements)
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

func generateVexCreate(tx *ent.Tx, pkg *model.IDorPkgInput, art *model.IDorArtifactInput, vuln *model.IDorVulnerabilityInput, vexStatement *model.VexStatementInputSpec) (*ent.CertifyVexCreate, error) {

	CertifyVexCreate := tx.CertifyVex.Create()

	// manage vulnerability
	if vuln == nil {
		return nil, fmt.Errorf("vulnerability must be specified for vex ingestion")
	}
	if vuln.VulnerabilityNodeID == nil {
		return nil, fmt.Errorf("VulnerabilityNodeID not specified in IDorVulnerabilityInput")
	}
	vulnID, err := uuid.Parse(*vuln.VulnerabilityNodeID)
	if err != nil {
		return nil, fmt.Errorf("uuid conversion from VulnerabilityNodeID failed with error: %w", err)
	}
	CertifyVexCreate.SetVulnerabilityID(vulnID)

	// manage package or artifact
	if pkg != nil {
		if pkg.PackageVersionID == nil {
			return nil, fmt.Errorf("packageVersion ID not specified in IDorPkgInput")
		}
		pkgVersionID, err := uuid.Parse(*pkg.PackageVersionID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from packageVersionID failed with error: %w", err)
		}
		CertifyVexCreate.SetPackageID(pkgVersionID)

	} else if art != nil {
		if art.ArtifactID == nil {
			return nil, fmt.Errorf("artifact ID not specified in IDorArtifactInput")
		}
		artID, err := uuid.Parse(*art.ArtifactID)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from ArtifactID failed with error: %w", err)
		}
		CertifyVexCreate.SetArtifactID(artID)

	} else {
		return nil, Errorf("%v :: %s", "generateVexCreate", "subject must be either a package or artifact")
	}

	CertifyVexCreate.
		SetKnownSince(vexStatement.KnownSince.UTC()).
		SetStatus(vexStatement.Status.String()).
		SetStatement(vexStatement.Statement).
		SetStatusNotes(vexStatement.StatusNotes).
		SetJustification(vexStatement.VexJustification.String()).
		SetOrigin(vexStatement.Origin).
		SetCollector(vexStatement.Collector)

	return CertifyVexCreate, nil
}

func upsertBulkVEX(ctx context.Context, tx *ent.Tx, subjects model.PackageOrArtifactInputs, vulnerabilities []*model.IDorVulnerabilityInput, vexStatements []*model.VexStatementInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		certifyvex.FieldKnownSince,
		certifyvex.FieldStatus,
		certifyvex.FieldStatement,
		certifyvex.FieldStatusNotes,
		certifyvex.FieldJustification,
		certifyvex.FieldOrigin,
		certifyvex.FieldCollector,
		certifyvex.FieldVulnerabilityID,
	}

	var conflictWhere *sql.Predicate

	if len(subjects.Packages) > 0 {
		conflictColumns = append(conflictColumns, certifyvex.FieldPackageID)
		conflictWhere = sql.And(
			sql.NotNull(certifyvex.FieldPackageID),
			sql.IsNull(certifyvex.FieldArtifactID),
		)
	} else if len(subjects.Artifacts) > 0 {
		conflictColumns = append(conflictColumns, certifyvex.FieldArtifactID)
		conflictWhere = sql.And(
			sql.IsNull(certifyvex.FieldPackageID),
			sql.NotNull(certifyvex.FieldArtifactID),
		)
	}

	batches := chunk(vexStatements, 100)

	index := 0
	for _, vexs := range batches {
		creates := make([]*ent.CertifyVexCreate, len(vexs))
		for i, vex := range vexs {
			var err error
			if len(subjects.Packages) > 0 {
				creates[i], err = generateVexCreate(tx, subjects.Packages[index], nil, vulnerabilities[index], vex)
				if err != nil {
					return nil, gqlerror.Errorf("generateVexCreate :: %s", err)
				}
			} else if len(subjects.Artifacts) > 0 {
				creates[i], err = generateVexCreate(tx, nil, subjects.Artifacts[index], vulnerabilities[index], vex)
				if err != nil {
					return nil, gqlerror.Errorf("generateVexCreate :: %s", err)
				}
			}
			index++
		}

		err := tx.CertifyVex.CreateBulk(creates...).
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

	return &ids, nil
}

func (b *EntBackend) CertifyVEXStatement(ctx context.Context, spec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	funcName := "CertifyVEXStatement"

	query := b.client.CertifyVex.Query()
	records, err := query.
		Where(certifyVexPredicate(*spec)).
		WithVulnerability(func(q *ent.VulnerabilityIDQuery) {

		}).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
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
		ID:               record.ID.String(),
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
					optionalPredicate(filter.Vulnerability.Type, vulnerabilityid.TypeEqualFold),
				),
			)
		}
	}
	return certifyvex.And(predicates...)
}

// func vexStatementInputPredicate(subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInputSpec, vexStatement model.VexStatementInputSpec) predicate.CertifyVex {
// 	var sub *model.PackageOrArtifactSpec
// 	if subject.Package != nil {
// 		sub = &model.PackageOrArtifactSpec{
// 			Package: helper.ConvertPkgInputSpecToPkgSpec(subject.Package.PackageInput),
// 		}
// 	} else {
// 		sub = &model.PackageOrArtifactSpec{
// 			Artifact: helper.ConvertArtInputSpecToArtSpec(subject.Artifact.ArtifactInput),
// 		}
// 	}
// 	return certifyVexPredicate(model.CertifyVEXStatementSpec{
// 		Subject: sub,
// 		Vulnerability: &model.VulnerabilitySpec{
// 			Type:            &vulnerability.Type,
// 			VulnerabilityID: &vulnerability.VulnerabilityID,
// 		},
// 		Status:           &vexStatement.Status,
// 		VexJustification: &vexStatement.VexJustification,
// 		Statement:        &vexStatement.Statement,
// 		StatusNotes:      &vexStatement.StatusNotes,
// 		KnownSince:       &vexStatement.KnownSince,
// 		Origin:           &vexStatement.Origin,
// 		Collector:        &vexStatement.Collector,
// 	})
// }
