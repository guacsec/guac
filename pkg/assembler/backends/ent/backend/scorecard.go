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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyscorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) Scorecards(ctx context.Context, filter *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {
	if filter == nil {
		return nil, nil
	}

	records, err := b.client.CertifyScorecard.Query().
		Where(certifyScorecardQuery(filter)).
		WithSource(func(q *ent.SourceNameQuery) {}).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelCertifyScorecard), nil
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
	}

	if filter.Source != nil {
		predicates = append(predicates,
			certifyscorecard.HasSourceWith(sourceQuery(filter.Source)),
		)
	}

	return certifyscorecard.And(predicates...)
}

// Mutations for evidence trees (read-write queries, assume software trees ingested)
// IngestScorecard takes a scorecard and a source and creates a certifyScorecard
func (b *EntBackend) IngestScorecard(ctx context.Context, source model.IDorSourceInput, scorecard model.ScorecardInputSpec) (string, error) {
	cscID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*string, error) {
		return upsertScorecard(ctx, ent.TxFromContext(ctx), source, scorecard)
	})
	if err != nil {
		return "", err
	}
	return *cscID, nil
}

func (b *EntBackend) IngestScorecards(ctx context.Context, sources []*model.IDorSourceInput, scorecards []*model.ScorecardInputSpec) ([]string, error) {
	funcName := "IngestScorecards"
	ids, err := WithinTX(ctx, b.client, func(ctx context.Context) (*[]string, error) {
		client := ent.TxFromContext(ctx)
		slc, err := upsertBulkScorecard(ctx, client, sources, scorecards)
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

func upsertBulkScorecard(ctx context.Context, client *ent.Tx, sources []*model.IDorSourceInput, scorecards []*model.ScorecardInputSpec) (*[]string, error) {
	ids := make([]string, 0)

	conflictColumns := []string{
		certifyscorecard.FieldSourceID, certifyscorecard.FieldOrigin,
		certifyscorecard.FieldCollector, certifyscorecard.FieldScorecardCommit,
		certifyscorecard.FieldScorecardVersion, certifyscorecard.FieldTimeScanned, certifyscorecard.FieldAggregateScore}

	batches := chunk(scorecards, 100)

	index := 0
	for _, css := range batches {
		creates := make([]*ent.CertifyScorecardCreate, len(css))
		for i, cs := range css {

			checks := make([]*model.ScorecardCheck, len(cs.Checks))
			for i, check := range cs.Checks {
				checks[i] = &model.ScorecardCheck{
					Check: check.Check,
					Score: check.Score,
				}
			}

			creates[i] = client.CertifyScorecard.Create().
				SetChecks(checks).
				SetAggregateScore(cs.AggregateScore).
				SetTimeScanned(cs.TimeScanned.UTC()).
				SetScorecardVersion(cs.ScorecardVersion).
				SetScorecardCommit(cs.ScorecardCommit).
				SetOrigin(cs.Origin).
				SetCollector(cs.Collector)

			if sources[index].SourceNameID == nil {
				return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
			}
			sourceID, err := uuid.Parse(*sources[index].SourceNameID)
			if err != nil {
				return nil, fmt.Errorf("uuid conversion from SourceNameID failed with error: %w", err)
			}
			creates[i].SetSourceID(sourceID)

			index++
		}

		err := client.CertifyScorecard.CreateBulk(creates...).
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

func upsertScorecard(ctx context.Context, client *ent.Tx, source model.IDorSourceInput, scorecardInput model.ScorecardInputSpec) (*string, error) {
	checks := make([]*model.ScorecardCheck, len(scorecardInput.Checks))
	for i, check := range scorecardInput.Checks {
		checks[i] = &model.ScorecardCheck{
			Check: check.Check,
			Score: check.Score,
		}
	}

	if source.SourceNameID == nil {
		return nil, fmt.Errorf("source ID not specified in IDorSourceInput")
	}
	sourceID, err := uuid.Parse(*source.SourceNameID)
	if err != nil {
		return nil, fmt.Errorf("uuid conversion from SourceNameID failed with error: %w", err)
	}
	if _, err := client.CertifyScorecard.Create().
		SetSourceID(sourceID).
		SetChecks(checks).
		SetAggregateScore(scorecardInput.AggregateScore).
		SetTimeScanned(scorecardInput.TimeScanned.UTC()).
		SetScorecardVersion(scorecardInput.ScorecardVersion).
		SetScorecardCommit(scorecardInput.ScorecardCommit).
		SetOrigin(scorecardInput.Origin).
		SetCollector(scorecardInput.Collector).
		OnConflict(
			sql.ConflictColumns(certifyscorecard.FieldSourceID, certifyscorecard.FieldOrigin,
				certifyscorecard.FieldCollector, certifyscorecard.FieldScorecardCommit,
				certifyscorecard.FieldScorecardVersion, certifyscorecard.FieldTimeScanned, certifyscorecard.FieldAggregateScore),
		).
		DoNothing().
		ID(ctx); err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert Scorecard")
		}
	}
	return ptrfrom.String(""), nil
}

func toModelCertifyScorecard(record *ent.CertifyScorecard) *model.CertifyScorecard {
	return &model.CertifyScorecard{
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
	}
}
