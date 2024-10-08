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
	"strconv"

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyscorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func scorecardGlobalID(id string) string {
	return toGlobalID(certifyscorecard.Table, id)
}

func bulkScorecardGlobalID(ids []string) []string {
	return toGlobalIDs(certifyscorecard.Table, ids)
}

func (b *EntBackend) ScorecardsList(ctx context.Context, spec model.CertifyScorecardSpec, after *string, first *int) (*model.CertifyScorecardConnection, error) {
	var afterCursor *entgql.Cursor[uuid.UUID]

	if after != nil {
		globalID := fromGlobalID(*after)
		if globalID.nodeType != certifyscorecard.Table {
			return nil, fmt.Errorf("after cursor is not type Scorecard but type: %s", globalID.nodeType)
		}
		afterUUID, err := uuid.Parse(globalID.id)
		if err != nil {
			return nil, fmt.Errorf("failed to parse global ID with error: %w", err)
		}
		afterCursor = &ent.Cursor{ID: afterUUID}
	} else {
		afterCursor = nil
	}

	scorecardQuery := b.client.CertifyScorecard.Query().
		Where(certifyScorecardQuery(&spec))

	scorecardConn, err := getScorecardObject(scorecardQuery).
		Paginate(ctx, afterCursor, first, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed scorecard query with error: %w", err)
	}

	// if not found return nil
	if scorecardConn == nil {
		return nil, nil
	}

	var edges []*model.CertifyScorecardEdge
	for _, edge := range scorecardConn.Edges {
		edges = append(edges, &model.CertifyScorecardEdge{
			Cursor: scorecardGlobalID(edge.Cursor.ID.String()),
			Node:   toModelCertifyScorecard(edge.Node),
		})
	}

	if scorecardConn.PageInfo.StartCursor != nil {
		return &model.CertifyScorecardConnection{
			TotalCount: scorecardConn.TotalCount,
			PageInfo: &model.PageInfo{
				HasNextPage: scorecardConn.PageInfo.HasNextPage,
				StartCursor: ptrfrom.String(scorecardGlobalID(scorecardConn.PageInfo.StartCursor.ID.String())),
				EndCursor:   ptrfrom.String(scorecardGlobalID(scorecardConn.PageInfo.EndCursor.ID.String())),
			},
			Edges: edges,
		}, nil
	} else {
		// if not found return nil
		return nil, nil
	}
}

func (b *EntBackend) Scorecards(ctx context.Context, filter *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {
	if filter == nil {
		filter = &model.CertifyScorecardSpec{}
	}

	scorecardQuery := b.client.CertifyScorecard.Query().
		Where(certifyScorecardQuery(filter))

	records, err := getScorecardObject(scorecardQuery).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed scorecard query with error: %w", err)
	}

	return collect(records, toModelCertifyScorecard), nil
}

// getPkgEqualObject is used recreate the pkgEqual object be eager loading the edges
func getScorecardObject(q *ent.CertifyScorecardQuery) *ent.CertifyScorecardQuery {
	return q.
		WithSource(func(q *ent.SourceNameQuery) {})
}

func certifyScorecardQuery(filter *model.CertifyScorecardSpec) predicate.CertifyScorecard {
	if filter == nil {
		return NoOpSelector()
	}

	predicates := []predicate.CertifyScorecard{
		optionalPredicate(filter.ID, IDEQ),
		optionalPredicate(filter.AggregateScore, certifyscorecard.AggregateScoreEQ),
		optionalPredicate(filter.TimeScanned, certifyscorecard.TimeScannedEQ),
		optionalPredicate(filter.ScorecardVersion, certifyscorecard.ScorecardVersionEQ),
		optionalPredicate(filter.ScorecardCommit, certifyscorecard.ScorecardCommitEqualFold),
		optionalPredicate(filter.Origin, certifyscorecard.OriginEQ),
		optionalPredicate(filter.Collector, certifyscorecard.CollectorEQ),
		optionalPredicate(filter.DocumentRef, certifyscorecard.DocumentRef),
	}

	if len(filter.Checks) > 0 {
		checks := make([]*model.ScorecardCheck, len(filter.Checks))
		for i, check := range filter.Checks {
			checks[i] = &model.ScorecardCheck{
				Check: check.Check,
				Score: check.Score,
			}
		}

		sort.Slice(checks, func(i, j int) bool { return checks[i].Check < checks[j].Check })

		predicates = append(predicates, optionalPredicate(ptrfrom.String(hashSortedScorecardChecks(checks)), certifyscorecard.ChecksHashEQ))
	}

	if filter.Source != nil {
		if filter.Source.ID != nil {
			predicates = append(predicates, optionalPredicate(filter.Source.ID, sourceIDEQ))
		} else {
			predicates = append(predicates,
				certifyscorecard.HasSourceWith(sourceQuery(filter.Source)),
			)
		}
	}

	return certifyscorecard.And(predicates...)
}

// Mutations for evidence trees (read-write queries, assume software trees ingested)
// IngestScorecard takes a scorecard and a source and creates a certifyScorecard
func (b *EntBackend) IngestScorecard(ctx context.Context, source model.IDorSourceInput, scorecard model.ScorecardInputSpec) (string, error) {
	cscID, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertScorecard(ctx, ent.TxFromContext(ctx), source, scorecard)
	})
	if txErr != nil {
		return "", txErr
	}
	return scorecardGlobalID(*cscID), nil
}

func (b *EntBackend) IngestScorecards(ctx context.Context, sources []*model.IDorSourceInput, scorecards []*model.ScorecardInputSpec) ([]string, error) {
	funcName := "IngestScorecards"
	ids, txErr := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkScorecard(ctx, client, sources, scorecards)
		if err != nil {
			return nil, err
		}
		return slc, nil
	})
	if txErr != nil {
		return nil, gqlerror.Errorf("%v :: %s", funcName, txErr)
	}

	return bulkScorecardGlobalID(*ids), nil
}

func generateScorecardCreate(ctx context.Context, tx *ent.Tx, src *model.IDorSourceInput, scorecard *model.ScorecardInputSpec) (*ent.CertifyScorecardCreate, error) {

	checks := make([]*model.ScorecardCheck, len(scorecard.Checks))
	for i, check := range scorecard.Checks {
		checks[i] = &model.ScorecardCheck{
			Check: check.Check,
			Score: check.Score,
		}
	}

	sort.Slice(checks, func(i, j int) bool { return checks[i].Check < checks[j].Check })

	var sourceID uuid.UUID
	if src.SourceNameID != nil {
		var err error
		srcNameGlobalID := fromGlobalID(*src.SourceNameID)
		sourceID, err = uuid.Parse(srcNameGlobalID.id)
		if err != nil {
			return nil, fmt.Errorf("uuid conversion from SourceNameID failed with error: %w", err)
		}
	} else {
		srcID, err := getSourceNameID(ctx, tx.Client(), *src.SourceInput)
		if err != nil {
			return nil, err
		}
		sourceID = srcID
	}

	scorecardCreate := tx.CertifyScorecard.Create()

	scorecardCreate.
		SetSourceID(sourceID).
		SetChecks(checks).
		SetChecksHash(hashSortedScorecardChecks(checks)).
		SetAggregateScore(scorecard.AggregateScore).
		SetTimeScanned(scorecard.TimeScanned.UTC()).
		SetScorecardVersion(scorecard.ScorecardVersion).
		SetScorecardCommit(scorecard.ScorecardCommit).
		SetOrigin(scorecard.Origin).
		SetCollector(scorecard.Collector).
		SetDocumentRef(scorecard.DocumentRef)

	return scorecardCreate, nil
}

func scorecardConflictColumns() []string {
	return []string{
		certifyscorecard.FieldSourceID,
		certifyscorecard.FieldOrigin,
		certifyscorecard.FieldCollector,
		certifyscorecard.FieldScorecardCommit,
		certifyscorecard.FieldScorecardVersion,
		certifyscorecard.FieldTimeScanned,
		certifyscorecard.FieldAggregateScore,
		certifyscorecard.FieldChecksHash,
		certifyscorecard.FieldDocumentRef,
	}
}

func upsertBulkScorecard(ctx context.Context, tx *ent.Tx, sources []*model.IDorSourceInput, scorecards []*model.ScorecardInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	batches := chunk(scorecards, MaxBatchSize)

	index := 0
	for _, css := range batches {
		creates := make([]*ent.CertifyScorecardCreate, len(css))
		for i, cs := range css {
			cs := cs
			var err error
			creates[i], err = generateScorecardCreate(ctx, tx, sources[index], cs)
			if err != nil {
				return nil, gqlerror.Errorf("generateScorecardCreate :: %s", err)
			}
			index++
		}

		err := tx.CertifyScorecard.CreateBulk(creates...).
			OnConflict(
				sql.ConflictColumns(scorecardConflictColumns()...),
			).
			DoNothing().
			Exec(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "bulk upsert scorecard node")
		}
	}

	return &ids, nil
}

func upsertScorecard(ctx context.Context, tx *ent.Tx, source model.IDorSourceInput, scorecardInput model.ScorecardInputSpec) (*string, error) {

	scorecardCreate, err := generateScorecardCreate(ctx, tx, &source, &scorecardInput)
	if err != nil {
		return nil, gqlerror.Errorf("generateScorecardCreate :: %s", err)
	}
	if id, err := scorecardCreate.
		OnConflict(
			sql.ConflictColumns(scorecardConflictColumns()...),
		).
		Ignore().
		ID(ctx); err != nil {
		return nil, errors.Wrap(err, "upsert Scorecard")

	} else {
		return ptrfrom.String(id.String()), nil
	}
}

func hashSortedScorecardChecks(checks []*model.ScorecardCheck) string {
	hash := sha1.New()

	checksBuffer := bytes.NewBuffer(nil)

	for _, c := range checks {
		checksBuffer.WriteString(c.Check)
		checksBuffer.WriteString(strconv.Itoa(c.Score))
	}

	hash.Write(checksBuffer.Bytes())
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func toModelCertifyScorecard(record *ent.CertifyScorecard) *model.CertifyScorecard {
	return &model.CertifyScorecard{
		ID:        scorecardGlobalID(record.ID.String()),
		Source:    toModelSource(record.Edges.Source),
		Scorecard: toModelScorecard(record),
	}
}

func toModelScorecard(record *ent.CertifyScorecard) *model.Scorecard {
	return &model.Scorecard{
		Checks:           record.Checks,
		AggregateScore:   record.AggregateScore,
		TimeScanned:      record.TimeScanned,
		ScorecardVersion: record.ScorecardVersion,
		ScorecardCommit:  record.ScorecardCommit,
		Origin:           record.Origin,
		Collector:        record.Collector,
		DocumentRef:      record.DocumentRef,
	}
}

func (b *EntBackend) certifyScorecardNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]model.Node, error) {
	var out []model.Node

	query := b.client.CertifyScorecard.Query().
		Where(certifyScorecardQuery(&model.CertifyScorecardSpec{ID: &nodeID}))

	if allowedEdges[model.EdgeCertifyScorecardSource] {
		query.
			WithSource()
	}

	scorecards, err := query.All(ctx)
	if err != nil {
		return []model.Node{}, fmt.Errorf("failed to query for scorecard with node ID: %s with error: %w", nodeID, err)
	}

	for _, s := range scorecards {
		if s.Edges.Source != nil {
			out = append(out, toModelSource(s.Edges.Source))
		}
	}

	return out, nil
}
