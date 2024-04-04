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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvex"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.IDorVulnerabilityInput, vexStatement model.VexStatementInputSpec) (string, error) {
	funcName := "IngestVEXStatement"

	recordID, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
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

		insert, err := generateVexCreate(ctx, tx, subject.Package, subject.Artifact, &vulnerability, &vexStatement)
		if err != nil {
			return nil, gqlerror.Errorf("generateVexCreate :: %s", err)
		}

		if id, err := insert.
			OnConflict(
				sql.ConflictColumns(conflictColumns...),
				sql.ConflictWhere(conflictWhere),
			).
			Ignore().
			ID(ctx); err != nil {

			return nil, errors.Wrap(err, "upsert certify vex statement node")

		} else {
			return ptrfrom.String(id.String()), nil
		}
	})

	if txErr != nil {
		return "", txErr
	}

	return toGlobalID(certifyvex.Table, *recordID), nil
}

func (b *EntBackend) IngestVEXStatements(ctx context.Context, subjects model.PackageOrArtifactInputs, vulnerabilities []*model.IDorVulnerabilityInput, vexStatements []*model.VexStatementInputSpec) ([]string, error) {
	funcName := "IngestVEXStatements"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkVEX(ctx, client, subjects, vulnerabilities, vexStatements)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return toGlobalIDs(certifyvex.Table, *ids), nil
}

func generateVexCreate(ctx context.Context, tx *ent.Tx, pkg *model.IDorPkgInput, art *model.IDorArtifactInput, vuln *model.IDorVulnerabilityInput, vexStatement *model.VexStatementInputSpec) (*ent.CertifyVexCreate, error) {

	certifyVexCreate := tx.CertifyVex.Create()

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
	certifyVexCreate.SetVulnerabilityID(vulnID)

	// manage package or artifact
	if pkg != nil {
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
		certifyVexCreate.SetPackageID(pkgVersionID)

	} else if art != nil {
		var artID uuid.UUID
		if art.ArtifactID != nil {
			var err error
			artGlobalID := fromGlobalID(*art.ArtifactID)
			artID, err = uuid.Parse(artGlobalID.id)
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
		certifyVexCreate.SetArtifactID(artID)
	} else {
		return nil, Errorf("%v :: %s", "generateVexCreate", "subject must be either a package or artifact")
	}

	certifyVexCreate.
		SetKnownSince(vexStatement.KnownSince.UTC()).
		SetStatus(vexStatement.Status.String()).
		SetStatement(vexStatement.Statement).
		SetStatusNotes(vexStatement.StatusNotes).
		SetJustification(vexStatement.VexJustification.String()).
		SetOrigin(vexStatement.Origin).
		SetCollector(vexStatement.Collector)

	return certifyVexCreate, nil
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

	batches := chunk(vexStatements, MaxBatchSize)

	index := 0
	for _, vexs := range batches {
		creates := make([]*ent.CertifyVexCreate, len(vexs))
		for i, vex := range vexs {
			vex := vex
			var err error
			if len(subjects.Packages) > 0 {
				creates[i], err = generateVexCreate(ctx, tx, subjects.Packages[index], nil, vulnerabilities[index], vex)
				if err != nil {
					return nil, gqlerror.Errorf("generateVexCreate :: %s", err)
				}
			} else if len(subjects.Artifacts) > 0 {
				creates[i], err = generateVexCreate(ctx, tx, nil, subjects.Artifacts[index], vulnerabilities[index], vex)
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
			return nil, errors.Wrap(err, "bulk upsert certifyVex node")
		}
	}

	return &ids, nil
}

func (b *EntBackend) CertifyVEXStatement(ctx context.Context, spec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	if spec == nil {
		spec = &model.CertifyVEXStatementSpec{}
	}
	funcName := "CertifyVEXStatement"

	vexQuery := b.client.CertifyVex.Query().
		Where(certifyVexPredicate(*spec))

	records, err := getVEXObject(vexQuery).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, gqlerror.Errorf("%v :: %v", funcName, err)
	}

	return collect(records, toModelCertifyVEXStatement), nil
}

// getVEXObject is used recreate the VEX object be eager loading the edges
func getVEXObject(q *ent.CertifyVexQuery) *ent.CertifyVexQuery {
	return q.
		WithVulnerability(func(q *ent.VulnerabilityIDQuery) {
		}).
		WithPackage(func(q *ent.PackageVersionQuery) {
			q.WithName(func(q *ent.PackageNameQuery) {})
		}).
		WithArtifact()
}

func toModelCertifyVEXStatement(record *ent.CertifyVex) *model.CertifyVEXStatement {
	return &model.CertifyVEXStatement{
		ID:               toGlobalID(certifyvex.Table, record.ID.String()),
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

func (b *EntBackend) certifyVexNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node
	if allowedEdges[model.EdgeCertifyVexStatementPackage] {
		query := b.client.CertifyVex.Query().
			Where(certifyVexPredicate(model.CertifyVEXStatementSpec{ID: &nodeID})).
			WithPackage(withPackageVersionTree()).
			Limit(MaxPageSize)

		certVexs, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get package for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundVex := range certVexs {
			if foundVex.Edges.Package != nil {
				out = append(out, toModelPackage(backReferencePackageVersion(foundVex.Edges.Package)))
			}
		}
	}
	if allowedEdges[model.EdgeCertifyVexStatementArtifact] {
		query := b.client.CertifyVex.Query().
			Where(certifyVexPredicate(model.CertifyVEXStatementSpec{ID: &nodeID})).
			WithArtifact().
			Limit(MaxPageSize)

		certVexs, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get artifact for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundVex := range certVexs {
			if foundVex.Edges.Artifact != nil {
				out = append(out, toModelArtifact(foundVex.Edges.Artifact))
			}
		}
	}
	if allowedEdges[model.EdgeCertifyVexStatementVulnerability] {
		query := b.client.CertifyVex.Query().
			Where(certifyVexPredicate(model.CertifyVEXStatementSpec{ID: &nodeID})).
			WithVulnerability().
			Limit(MaxPageSize)

		certVexs, err := query.All(ctx)
		if err != nil {
			return []model.Node{}, fmt.Errorf("failed to get vulnerability for node ID: %s with error: %w", nodeID, err)
		}

		for _, foundVex := range certVexs {
			if foundVex.Edges.Vulnerability != nil {
				out = append(out, toModelVulnerabilityFromVulnerabilityID(foundVex.Edges.Vulnerability))
			}
		}
	}
	return out, nil
}
