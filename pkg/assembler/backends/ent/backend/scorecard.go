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
	"strconv"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyscorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/scorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcetype"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/pkg/errors"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func (b *EntBackend) Scorecards(ctx context.Context, filter *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {
	if filter == nil {
		return nil, nil
	}

	query := b.client.CertifyScorecard.Query()
	query.Where(
		certifyscorecard.HasScorecardWith(func(s *sql.Selector) {
			// optionalPredicate(filter.Checks, scorecard.ChecksContains)(s)
			optionalPredicate(filter.AggregateScore, scorecard.AggregateScoreEQ)(s)
			optionalPredicate(filter.TimeScanned, scorecard.TimeScannedEQ)(s)
			optionalPredicate(filter.ScorecardVersion, scorecard.ScorecardVersionEQ)(s)
			optionalPredicate(filter.ScorecardCommit, scorecard.ScorecardCommitEqualFold)(s)
			optionalPredicate(filter.Origin, scorecard.OriginEQ)(s)
			optionalPredicate(filter.Collector, scorecard.CollectorEQ)(s)
		}),
	)

	if filter.Source != nil {
		query.Where(
			certifyscorecard.HasSourceWith(
				optionalPredicate(filter.Source.ID, IDEQ),
				optionalPredicate(filter.Source.Name, sourcename.NameEQ),
				optionalPredicate(filter.Source.Commit, sourcename.CommitEqualFold),
				optionalPredicate(filter.Source.Tag, sourcename.TagContainsFold),
			),
		)
		if filter.Source.Namespace != nil {
			query.Where(
				certifyscorecard.HasSourceWith(
					sourcename.HasNamespaceWith(sourcenamespace.NamespaceEQ(*filter.Source.Namespace)),
				),
			)
		}
		if filter.Source.Type != nil {
			query.Where(
				certifyscorecard.HasSourceWith(
					sourcename.HasNamespaceWith(sourcenamespace.HasSourceTypeWith(sourcetype.TypeEQ(*filter.Source.Type))),
				),
			)
		}
	}

	records, err := query.
		WithScorecard().
		WithSource(withSourceNameTreeQuery()).
		Limit(MaxPageSize).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return collect(records, toModelCertifyScorecard), nil
}

// Mutations for evidence trees (read-write queries, assume software trees ingested)
// IngestScorecard takes a scorecard and a source and creates a certifyScorecard
func (b *EntBackend) IngestScorecard(ctx context.Context, source model.IDorSourceInput, scorecard model.ScorecardInputSpec) (string, error) {
	cscID, err := WithinTX(ctx, b.client, func(ctx context.Context) (*int, error) {
		return upsertScorecard(ctx, ent.TxFromContext(ctx), *source.SourceInput, scorecard)
	})
	if err != nil {
		return "", err
	}
	return strconv.Itoa(*cscID), nil
}

func (b *EntBackend) IngestScorecards(ctx context.Context, sources []*model.IDorSourceInput, scorecards []*model.ScorecardInputSpec) ([]string, error) {
	var modelScorecardIDs []string
	for i, sc := range scorecards {
		modelScorecardID, err := b.IngestScorecard(ctx, *sources[i], *sc)
		if err != nil {
			return nil, gqlerror.Errorf("IngestScorecards failed with err: %v", err)
		}
		modelScorecardIDs = append(modelScorecardIDs, modelScorecardID)
	}
	return modelScorecardIDs, nil
}

func upsertScorecard(ctx context.Context, client *ent.Tx, source model.SourceInputSpec, scorecardInput model.ScorecardInputSpec) (*int, error) {
	checks := make([]*model.ScorecardCheck, len(scorecardInput.Checks))
	for i, check := range scorecardInput.Checks {
		checks[i] = &model.ScorecardCheck{
			Check: check.Check,
			Score: check.Score,
		}
	}

	sc, err := client.Scorecard.
		Create().
		SetChecks(checks).
		SetAggregateScore(scorecardInput.AggregateScore).
		SetTimeScanned(scorecardInput.TimeScanned).
		SetScorecardVersion(scorecardInput.ScorecardVersion).
		SetScorecardCommit(scorecardInput.ScorecardCommit).
		SetOrigin(scorecardInput.Origin).
		SetCollector(scorecardInput.Collector).
		OnConflict(
			sql.ConflictColumns(scorecard.FieldOrigin, scorecard.FieldCollector, scorecard.FieldScorecardCommit, scorecard.FieldScorecardVersion, scorecard.FieldAggregateScore),
		).
		DoNothing().
		ID(ctx)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert Scorecard")
		}
		sc, err = client.Scorecard.Query().
			Where(scorecard.TimeScannedEQ(scorecardInput.TimeScanned),
				scorecard.ScorecardVersionEQ(scorecardInput.ScorecardVersion),
				scorecard.ScorecardCommitEQ(scorecardInput.ScorecardCommit)).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get Scorecard ID")
		}
	}

	// NOTE: This might be better as a query, but using insert here since the spec is an inputspec
	var srcID int
	ids, err := upsertSource(ctx, client, source)
	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert Source")
		}
		srcID, err = client.SourceName.Query().
			Where(sourcename.Name(source.Name)).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get Source ID")
		}
	} else {
		srcID, err = strconv.Atoi(ids.SourceNameID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Source ID")
		}
	}
	id, err := client.CertifyScorecard.Create().
		SetScorecardID(sc).
		SetSourceID(srcID).
		OnConflict(
			sql.ConflictColumns(certifyscorecard.FieldScorecardID, certifyscorecard.FieldSourceID),
		).
		DoNothing().
		ID(ctx)

	if err != nil {
		if err != stdsql.ErrNoRows {
			return nil, errors.Wrap(err, "upsert Scorecard")
		}
		id, err = client.Scorecard.Query().
			Where(scorecard.IDEQ(srcID)).
			OnlyID(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "get Scorecard ID")
		}
	}
	return &id, nil
}

func toModelCertifyScorecard(record *ent.CertifyScorecard) *model.CertifyScorecard {
	return &model.CertifyScorecard{
		Source:    toModelSource(backReferenceSourceName(record.Edges.Source)),
		Scorecard: toModelScorecard(record.Edges.Scorecard),
	}
}

func toModelScorecard(record *ent.Scorecard) *model.Scorecard {
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
