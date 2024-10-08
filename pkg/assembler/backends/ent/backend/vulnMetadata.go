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

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilitymetadata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func vulnMetaGlobalID(id string) string {
	return toGlobalID(vulnerabilitymetadata.Table, id)
}

func bulkVulnMetaGlobalID(ids []string) []string {
	return toGlobalIDs(vulnerabilitymetadata.Table, ids)
}

func (b *EntBackend) VulnerabilityMetadataList(ctx context.Context, spec model.VulnerabilityMetadataSpec, after *string, first *int) (*model.VulnerabilityMetadataConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		if globalID.nodeType != vulnerabilitymetadata.Table {
			return nil, fmt.Errorf("after cursor is not type vulnMetadata but type: %s", globalID.nodeType)
		}
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse global ID with error: %w", err)
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	vulnMetadataPred, err := vulnerabilityMetadataPredicate(&spec)
	if err != nil {
		return nil, fmt.Errorf("failed to generate vulnerabilityMetadataPredicate :: %w", err)
	}

	vmQuery := b.client.VulnerabilityMetadata.Query().
		Where(vulnMetadataPred)

	vmConn, err := getVulnMetadataObject(vmQuery).
		Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed vulnMetadata query with error: %w", err)
	}

	// if not found return nil
	if vmConn == nil {
		return nil, nil
	}

	var edges []*model.VulnerabilityMetadataEdge
	for _, edge := range vmConn.Edges {
		edges = append(edges, &model.VulnerabilityMetadataEdge{
			Cursor: vulnMetaGlobalID(edge.Cursor.ID.String()),
			Node:   toModelVulnerabilityMetadata(edge.Node),
		})
	}

	if vmConn.PageInfo.StartCursor != nil {
		return &model.VulnerabilityMetadataConnection{
			TotalCount: vmConn.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: vmConn.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(vulnMetaGlobalID(vmConn.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(vulnMetaGlobalID(vmConn.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}

func (b *EntBackend) VulnerabilityMetadata(ctx context.Context, filter *model.VulnerabilityMetadataSpec) ([]*model.VulnerabilityMetadata, error) {
	if filter == nil {
		filter = &model.VulnerabilityMetadataSpec{}
	}
	vulnMetadataPred, err := vulnerabilityMetadataPredicate(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to generate vulnerabilityMetadataPredicate :: %w", err)
	}

	vmConn := b.client.VulnerabilityMetadata.Query().
		Where(vulnMetadataPred)

	records, err := getVulnMetadataObject(vmConn).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed vulnMetadata query with error: %w", err)
	}

	return collect(records, toModelVulnerabilityMetadata), nil
}

// getVulnEqualObject is used recreate the vulnEqual object be eager loading the edges
func getVulnMetadataObject(q *ent.VulnerabilityMetadataQuery) *ent.VulnerabilityMetadataQuery {
	return q.
		WithVulnerabilityID(func(q *ent.VulnerabilityIDQuery) {})
}

func (b *EntBackend) IngestVulnerabilityMetadata(ctx context.Context, vulnerability model.IDorVulnerabilityInput, vulnerabilityMetadata model.VulnerabilityMetadataInputSpec) (string, error) {
	recordID, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertVulnerabilityMetadata(ctx, ent.TxFromContext(ctx), vulnerability, vulnerabilityMetadata)
	})
	if txErr != nil {
		return "", fmt.Errorf("failed to execute IngestVulnerabilityMetadata :: %s", txErr)
	}

	return vulnMetaGlobalID(*recordID), nil
}

func (b *EntBackend) IngestBulkVulnerabilityMetadata(ctx context.Context, vulnerabilities []*model.IDorVulnerabilityInput, vulnerabilityMetadataList []*model.VulnerabilityMetadataInputSpec) ([]string, error) {
	funcName := "IngestBulkVulnerabilityMetadata"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkVulnerabilityMetadata(ctx, client, vulnerabilities, vulnerabilityMetadataList)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return bulkVulnMetaGlobalID(*ids), nil
}

func vulnerabilityMetadataPredicate(filter *model.VulnerabilityMetadataSpec) (predicate.VulnerabilityMetadata, error) {
	predicates := []predicate.VulnerabilityMetadata{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Timestamp, vulnerabilitymetadata.TimestampGTE),
		optionalPredicate(filter.Origin, vulnerabilitymetadata.OriginEQ),
		optionalPredicate(filter.Collector, vulnerabilitymetadata.CollectorEQ),
		optionalPredicate(filter.DocumentRef, vulnerabilitymetadata.DocumentRefEQ),
	}

	if filter.ScoreType != nil {
		predicates = append(predicates,
			optionalPredicate(ptrfrom.Any(vulnerabilitymetadata.ScoreType(*filter.ScoreType)), vulnerabilitymetadata.ScoreTypeEQ),
		)
	}

	var comparator predicate.VulnerabilityMetadata
	if filter.Comparator != nil {
		if filter.ScoreValue == nil {
			return nil, fmt.Errorf("comparator set without a vulnerability score being specified")
		}
		switch *filter.Comparator {
		case model.ComparatorGreater:
			comparator = optionalPredicate(filter.ScoreValue, vulnerabilitymetadata.ScoreValueGT)
		case model.ComparatorEqual:
			comparator = optionalPredicate(filter.ScoreValue, vulnerabilitymetadata.ScoreValueEQ)
		case model.ComparatorLess:
			comparator = optionalPredicate(filter.ScoreValue, vulnerabilitymetadata.ScoreValueLT)
		case model.ComparatorGreaterEqual:
			comparator = optionalPredicate(filter.ScoreValue, vulnerabilitymetadata.ScoreValueGTE)
		case model.ComparatorLessEqual:
			comparator = optionalPredicate(filter.ScoreValue, vulnerabilitymetadata.ScoreValueLTE)
		}
	} else {
		comparator = optionalPredicate(filter.ScoreValue, vulnerabilitymetadata.ScoreValueEQ)
	}
	predicates = append(predicates, comparator)

	if filter.Vulnerability != nil {
		if filter.Vulnerability.ID != nil {
			predicates = append(predicates, optionalPredicate(filter.Vulnerability.ID, vulnerabilityIDMetaEQ))
		} else {
			predicates = append(predicates,
				vulnerabilitymetadata.HasVulnerabilityIDWith(
					vulnerabilityQueryPredicates(*filter.Vulnerability)...,
				),
			)
		}
	}
	return vulnerabilitymetadata.And(predicates...), nil
}

func vulnMetaConflictColumns() []string {
	return []string{
		vulnerabilitymetadata.FieldVulnerabilityIDID,
		vulnerabilitymetadata.FieldScoreType,
		vulnerabilitymetadata.FieldScoreValue,
		vulnerabilitymetadata.FieldTimestamp,
		vulnerabilitymetadata.FieldOrigin,
		vulnerabilitymetadata.FieldCollector,
		vulnerabilitymetadata.FieldDocumentRef,
	}
}

func upsertBulkVulnerabilityMetadata(ctx context.Context, tx *ent.Tx, vulnerabilities []*model.IDorVulnerabilityInput, vulnerabilityMetadataList []*model.VulnerabilityMetadataInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	batches := chunk(vulnerabilityMetadataList, MaxBatchSize)

	index := 0
	for _, vml := range batches {
		creates := make([]*ent.VulnerabilityMetadataCreate, len(vml))
		for i, vm := range vml {
			vm := vm
			var err error

			creates[i], err = generateVulnMetadataCreate(ctx, tx, vulnerabilities[index], vm)
			if err != nil {
				return nil, gqlerror.Errorf("generateVulnEqualCreate :: %s", err)
			}
			index++
		}

		err := tx.VulnerabilityMetadata.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(vulnMetaConflictColumns()...),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert VulnerabilityMetadata node")
		}
	}

	return &ids, nil
}

func generateVulnMetadataCreate(ctx context.Context, tx *ent.Tx, vuln *model.IDorVulnerabilityInput, metadata *model.VulnerabilityMetadataInputSpec) (*ent.VulnerabilityMetadataCreate, error) {

	if vuln == nil {
		return nil, fmt.Errorf("vulnerability must be specified for vulnMetadata")
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

	vulnMetadataCreate := tx.VulnerabilityMetadata.Create()

	vulnMetadataCreate.
		SetVulnerabilityIDID(vulnID).
		SetScoreType(vulnerabilitymetadata.ScoreType(metadata.ScoreType)).
		SetScoreValue(metadata.ScoreValue).
		SetTimestamp(metadata.Timestamp.UTC()).
		SetOrigin(metadata.Origin).
		SetCollector(metadata.Collector).
		SetDocumentRef(metadata.DocumentRef)

	return vulnMetadataCreate, nil
}

func upsertVulnerabilityMetadata(ctx context.Context, tx *ent.Tx, vulnerability model.IDorVulnerabilityInput, spec model.VulnerabilityMetadataInputSpec) (*string, error) {

	insert, err := generateVulnMetadataCreate(ctx, tx, &vulnerability, &spec)
	if err != nil {
		return nil, gqlerror.Errorf("generateVulnMetadataCreate :: %s", err)

	}
	if id, err := insert.OnConflict(
		sql.ConflictColumns(vulnMetaConflictColumns()...),
	).
		Ignore().
		ID(ctx); err != nil {
		return nil, errors.Wrap(err, "upsert VulnerabilityMetadata node")
	} else {
		return ptrfrom.String(id.String()), nil
	}
}

func toModelVulnerabilityMetadata(v *ent.VulnerabilityMetadata) *model.VulnerabilityMetadata {
	return &model.VulnerabilityMetadata{
		ID:            vulnMetaGlobalID(v.ID.String()),
		Vulnerability: toModelVulnerabilityFromVulnerabilityID(v.Edges.VulnerabilityID),
		ScoreType:     model.VulnerabilityScoreType(v.ScoreType),
		ScoreValue:    v.ScoreValue,
		Timestamp:     v.Timestamp,
		Origin:        v.Origin,
		Collector:     v.Collector,
		DocumentRef:   v.DocumentRef,
	}
}

func (b *EntBackend) vulnMetadataNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	vulnMetadataPred, err := vulnerabilityMetadataPredicate(&model.VulnerabilityMetadataSpec{ID: &nodeID})
	if err != nil {
		return nil, fmt.Errorf("failed to generate vulnerabilityMetadataPredicate :: %w", err)
	}

	query := b.client.VulnerabilityMetadata.Query().
		Where(vulnMetadataPred)

	if allowedEdges[model.EdgeVulnMetadataVulnerability] {
		query.
			WithVulnerabilityID()
	}

	vulnMetas, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for vulnerability Metadata with node ID: %s with error: %w", nodeID, err)
	}

	for _, vm := range vulnMetas {
		if vm.Edges.VulnerabilityID != nil {
			out = append(out, toModelVulnerabilityFromVulnerabilityID(vm.Edges.VulnerabilityID))
		}
	}

	return out, nil
}
