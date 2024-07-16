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
	"fmt"
	"sort"

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func vulnEqualGlobalID(id string) string {
	return toGlobalID(vulnequal.Table, id)
}

func bulkVulnEqualGlobalID(ids []string) []string {
	return toGlobalIDs(vulnequal.Table, ids)
}

func (b *EntBackend) VulnEqualList(ctx context.Context, spec model.VulnEqualSpec, after *string, first *int) (*model.VulnEqualConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		if globalID.nodeType != vulnequal.Table {
			return nil, fmt.Errorf("after cursor is not type vulnEqual but type: %s", globalID.nodeType)
		}
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse global ID with error: %w", err)
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	veQuery := b.client.VulnEqual.Query().
		Where(vulnEqualQuery(&spec))

	veConn, err := getVulnEqualObject(veQuery).
		Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed vulnEqual query with error: %w", err)
	}

	// if not found return nil
	if veConn == nil {
		return nil, nil
	}

	var edges []*model.VulnEqualEdge
	for _, edge := range veConn.Edges {
		edges = append(edges, &model.VulnEqualEdge{
			Cursor: vulnEqualGlobalID(edge.Cursor.ID.String()),
			Node:   toModelVulnEqual(edge.Node),
		})
	}

	if veConn.PageInfo.StartCursor != nil {
		return &model.VulnEqualConnection{
			TotalCount: veConn.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: veConn.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(vulnEqualGlobalID(veConn.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(vulnEqualGlobalID(veConn.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}

func (b *EntBackend) VulnEqual(ctx context.Context, filter *model.VulnEqualSpec) ([]*model.VulnEqual, error) {
	if filter == nil {
		filter = &model.VulnEqualSpec{}
	}
	if len(filter.Vulnerabilities) > 2 {
		return nil, fmt.Errorf("too many vulnerability specified in vuln equal filter")
	}

	veQuery := b.client.VulnEqual.Query().
		Where(vulnEqualQuery(filter))

	query, err := getVulnEqualObject(veQuery).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed vulnEqual query with error: %w", err)
	}

	return collect(query, toModelVulnEqual), nil
}

// getVulnEqualObject is used recreate the vulnEqual object be eager loading the edges
func getVulnEqualObject(q *ent.VulnEqualQuery) *ent.VulnEqualQuery {
	return q.
		WithVulnerabilityA(func(query *ent.VulnerabilityIDQuery) {}).
		WithVulnerabilityB(func(query *ent.VulnerabilityIDQuery) {})
}

func vulnEqualQuery(filter *model.VulnEqualSpec) predicate.VulnEqual {
	if filter == nil {
		return NoOpSelector()
	}
	where := []predicate.VulnEqual{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.Justification, vulnequal.JustificationEQ),
		optionalPredicate(filter.Origin, vulnequal.OriginEQ),
		optionalPredicate(filter.Collector, vulnequal.CollectorEQ),
		optionalPredicate(filter.DocumentRef, vulnequal.DocumentRefEQ),
	}

	if len(filter.Vulnerabilities) == 1 {
		where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(vulnerabilityQueryPredicates(*filter.Vulnerabilities[0])...),
			vulnequal.HasVulnerabilityBWith(vulnerabilityQueryPredicates(*filter.Vulnerabilities[0])...)))

		if filter.Vulnerabilities[0].NoVuln != nil {
			if *filter.Vulnerabilities[0].NoVuln {
				where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(vulnerabilityid.TypeEqualFold(NoVuln)), vulnequal.HasVulnerabilityBWith(vulnerabilityid.TypeEqualFold(NoVuln))))
			} else {
				where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(vulnerabilityid.TypeNEQ(NoVuln)), vulnequal.HasVulnerabilityBWith(vulnerabilityid.TypeNEQ(NoVuln))))
			}
		}
	} else if len(filter.Vulnerabilities) == 2 {
		where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(vulnerabilityQueryPredicates(*filter.Vulnerabilities[0])...),
			vulnequal.HasVulnerabilityBWith(vulnerabilityQueryPredicates(*filter.Vulnerabilities[0])...)))

		where = append(where, vulnequal.Or(vulnequal.HasVulnerabilityAWith(vulnerabilityQueryPredicates(*filter.Vulnerabilities[1])...),
			vulnequal.HasVulnerabilityBWith(vulnerabilityQueryPredicates(*filter.Vulnerabilities[1])...)))

	}

	return vulnequal.And(where...)
}

func (b *EntBackend) IngestVulnEquals(ctx context.Context, vulnerabilities []*model.IDorVulnerabilityInput, otherVulnerabilities []*model.IDorVulnerabilityInput, vulnEquals []*model.VulnEqualInputSpec) ([]string, error) {
	funcName := "IngestVulnEquals"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkVulnEquals(ctx, client, vulnerabilities, otherVulnerabilities, vulnEquals)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return bulkVulnEqualGlobalID(*ids), nil
}

func (b *EntBackend) IngestVulnEqual(ctx context.Context, vulnerability model.IDorVulnerabilityInput, otherVulnerability model.IDorVulnerabilityInput, vulnEqual model.VulnEqualInputSpec) (string, error) {
	id, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		tx := ent.TxFromContext(ctx)
		return upsertVulnEquals(ctx, tx, vulnerability, otherVulnerability, vulnEqual)
	})

	if txErr != nil {
		return "", txErr
	}

	return vulnEqualGlobalID(*id), nil
}

func vulnEqualConflictColumns() []string {
	return []string{
		vulnequal.FieldVulnerabilitiesHash,
		vulnequal.FieldVulnID,
		vulnequal.FieldEqualVulnID,
		vulnequal.FieldOrigin,
		vulnequal.FieldCollector,
		vulnequal.FieldJustification,
		vulnequal.FieldDocumentRef,
	}
}

func upsertBulkVulnEquals(ctx context.Context, tx *ent.Tx, vulnerabilities []*model.IDorVulnerabilityInput, otherVulnerabilities []*model.IDorVulnerabilityInput, vulnEquals []*model.VulnEqualInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	batches := chunk(vulnEquals, MaxBatchSize)

	index := 0
	for _, ves := range batches {
		creates := make([]*ent.VulnEqualCreate, len(ves))
		for i, ve := range ves {
			ve := ve
			var err error

			creates[i], err = generateVulnEqualCreate(ctx, tx, vulnerabilities[index], otherVulnerabilities[index], ve)
			if err != nil {
				return nil, gqlerror.Errorf("generateVulnEqualCreate :: %s", err)
			}
			index++
		}

		err := tx.VulnEqual.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(vulnEqualConflictColumns()...),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert vulnEqual node")
		}
	}
	return &ids, nil
}

func generateVulnEqualCreate(ctx context.Context, tx *ent.Tx, vulnerability *model.IDorVulnerabilityInput, otherVulnerability *model.IDorVulnerabilityInput, ve *model.VulnEqualInputSpec) (*ent.VulnEqualCreate, error) {

	if vulnerability == nil {
		return nil, fmt.Errorf("vulnerability must be specified for vulnEqual")
	}
	if otherVulnerability == nil {
		return nil, fmt.Errorf("otherVulnerability must be specified for vulnEqual")
	}

	vulnEqualCreate := tx.VulnEqual.Create().
		SetCollector(ve.Collector).
		SetJustification(ve.Justification).
		SetOrigin(ve.Origin).
		SetDocumentRef(ve.DocumentRef)

	if vulnerability.VulnerabilityNodeID == nil {
		foundVulnID, err := tx.VulnerabilityID.Query().
			Where(
				vulnerabilityid.VulnerabilityIDEqualFold(vulnerability.VulnerabilityInput.VulnerabilityID),
				vulnerabilityid.TypeEqualFold(vulnerability.VulnerabilityInput.Type),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, Errorf("%v ::  %s", "generateVexCreate", err)
		}
		vulnerability.VulnerabilityNodeID = ptrfrom.String(vulnIDGlobalID(foundVulnID.String()))
	}

	if otherVulnerability.VulnerabilityNodeID == nil {
		foundVulnID, err := tx.VulnerabilityID.Query().
			Where(
				vulnerabilityid.VulnerabilityIDEqualFold(otherVulnerability.VulnerabilityInput.VulnerabilityID),
				vulnerabilityid.TypeEqualFold(otherVulnerability.VulnerabilityInput.Type),
			).
			OnlyID(ctx)
		if err != nil {
			return nil, Errorf("%v ::  %s", "generateVexCreate", err)
		}
		otherVulnerability.VulnerabilityNodeID = ptrfrom.String(vulnIDGlobalID(foundVulnID.String()))
	}

	sortedVulns := []model.IDorVulnerabilityInput{*vulnerability, *otherVulnerability}

	sort.SliceStable(sortedVulns, func(i, j int) bool { return *sortedVulns[i].VulnerabilityNodeID < *sortedVulns[j].VulnerabilityNodeID })

	var sortedVulnUUIDs []uuid.UUID
	for _, vuln := range sortedVulns {
		if vuln.VulnerabilityNodeID == nil {
			return nil, fmt.Errorf("VulnerabilityNodeID not specified in IDorVulnerabilityInput")
		}
		vulnGlobalID := fromGlobalID(*vuln.VulnerabilityNodeID)
		vulnID, err := uuid.Parse(vulnGlobalID.id)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from VulnerabilityNodeID failed with error: %w", err)
		}
		sortedVulnUUIDs = append(sortedVulnUUIDs, vulnID)
	}

	vulnEqualCreate.SetVulnerabilityAID(sortedVulnUUIDs[0])
	vulnEqualCreate.SetVulnerabilityBID(sortedVulnUUIDs[1])

	sortedVulnerabilitiesHash := hashVulnerabilities(sortedVulns)

	vulnEqualCreate.SetVulnerabilitiesHash(sortedVulnerabilitiesHash)

	vulnEqualID, err := guacVulnEqualKey(sortedVulnerabilitiesHash, ve)
	if err != nil {
		return nil, fmt.Errorf("failed to create vulnEqual uuid with error: %w", err)
	}
	vulnEqualCreate.SetID(*vulnEqualID)

	return vulnEqualCreate, nil
}

func upsertVulnEquals(ctx context.Context, tx *ent.Tx, vulnerability model.IDorVulnerabilityInput, otherVulnerability model.IDorVulnerabilityInput, vulnEqualInput model.VulnEqualInputSpec) (*string, error) {

	vulnEqualCreate, err := generateVulnEqualCreate(ctx, tx, &vulnerability, &otherVulnerability, &vulnEqualInput)
	if err != nil {
		return nil, gqlerror.Errorf("generatePkgEqualCreate :: %s", err)
	}

	if id, err := vulnEqualCreate.
		OnConflict(
			sql.ConflictColumns(vulnEqualConflictColumns()...),
		).
		Ignore().
		ID(ctx); err != nil {

		return nil, errors.Wrap(err, "upsert vulnEqual node")
	} else {
		return ptrfrom.String(id.String()), nil
	}
}

// hashPackages is used to create a unique key for the M2M edge between PkgEquals <-M2M-> PackageVersions
func hashVulnerabilities(slc []model.IDorVulnerabilityInput) string {
	vulns := slc
	hash := sha1.New()
	content := bytes.NewBuffer(nil)

	for _, v := range vulns {
		content.WriteString(*v.VulnerabilityNodeID)
	}

	hash.Write(content.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func toModelVulnEqual(record *ent.VulnEqual) *model.VulnEqual {

	vulnerabilities := []*ent.VulnerabilityID{record.Edges.VulnerabilityA, record.Edges.VulnerabilityB}

	return &model.VulnEqual{
		ID:              vulnEqualGlobalID(record.ID.String()),
		Vulnerabilities: collect(vulnerabilities, toModelVulnerabilityFromVulnerabilityID),
		Justification:   record.Justification,
		Origin:          record.Origin,
		Collector:       record.Collector,
		DocumentRef:     record.DocumentRef,
	}
}

func toModelVulnerabilityFromVulnerabilityID(vulnID *ent.VulnerabilityID) *model.Vulnerability {
	return &model.Vulnerability{
		ID:               vulnTypeGlobalID(vulnID.ID.String()),
		Type:             vulnID.Type,
		VulnerabilityIDs: []*model.VulnerabilityID{toModelVulnerabilityID(vulnID)},
	}
}

func canonicalVulnEqualString(ve *model.VulnEqualInputSpec) string {
	return fmt.Sprintf("%s::%s::%s:%s", ve.Justification, ve.Origin, ve.Collector, ve.DocumentRef)
}

// guacVulnEqualKey generates an uuid based on the hash of the inputspec and inputs. vulnEqual ID has to be set for bulk ingestion
// when ingesting multiple edges otherwise you get "violates foreign key constraint" as it creates
// a new ID for vulnEqual node (even when already ingested) that it maps to the edge and fails the look up. This only occurs when using UUID with
// "Default" func to generate a new UUID
func guacVulnEqualKey(sortedVulnHash string, veInput *model.VulnEqualInputSpec) (*uuid.UUID, error) {
	veIDString := fmt.Sprintf("%s::%s?", sortedVulnHash, canonicalVulnEqualString(veInput))

	veID := generateUUIDKey([]byte(veIDString))
	return &veID, nil
}

func (b *EntBackend) vulnEqualNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.VulnEqual.Query().
		Where(vulnEqualQuery(&model.VulnEqualSpec{ID: &nodeID}))

	if allowedEdges[model.EdgeVulnEqualVulnerability] {
		query.
			WithVulnerabilityA().
			WithVulnerabilityB()
	}

	vulnEquals, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for vulnEquals with node ID: %s with error: %w", nodeID, err)
	}

	for _, ve := range vulnEquals {
		if ve.Edges.VulnerabilityA != nil {
			out = append(out, toModelVulnerabilityFromVulnerabilityID(ve.Edges.VulnerabilityA))
		}
		if ve.Edges.VulnerabilityB != nil {
			out = append(out, toModelVulnerabilityFromVulnerabilityID(ve.Edges.VulnerabilityB))
		}
	}

	return out, nil
}
