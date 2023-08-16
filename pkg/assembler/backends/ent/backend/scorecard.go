package backend

import (
	"context"
	"log"

	"entgo.io/ent/dialect/sql"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyscorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/scorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcenamespace"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcetype"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
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
			sourcename.HasNamespaceWith(sourcenamespace.NamespaceEQ(*filter.Source.Namespace))
		}
		if filter.Source.Type != nil {
			sourcename.HasNamespaceWith(sourcenamespace.HasSourceTypeWith(sourcetype.TypeEQ(*filter.Source.Type)))
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
func (b *EntBackend) CertifyScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (*model.CertifyScorecard, error) {
	csc, err := WithinTX(ctx, b.client, func(ctx context.Context) (*ent.CertifyScorecard, error) {
		return upsertScorecard(ctx, ent.TxFromContext(ctx), source, scorecard)
	})

	if err != nil {
		return nil, err
	}

	csc, err = b.client.CertifyScorecard.Query().
		Where(certifyscorecard.IDEQ(csc.ID)).
		WithScorecard().
		WithSource(withSourceNameTreeQuery()).
		Only(ctx)
	if err != nil {
		return nil, err
	}

	return toModelCertifyScorecard(csc), nil
}

func upsertScorecard(ctx context.Context, tx *ent.Tx, source model.SourceInputSpec, scorecardInput model.ScorecardInputSpec) (*ent.CertifyScorecard, error) {
	checks := make([]*model.ScorecardCheck, len(scorecardInput.Checks))
	for i, check := range scorecardInput.Checks {
		checks[i] = &model.ScorecardCheck{
			Check: check.Check,
			Score: check.Score,
		}
	}

	sc, err := tx.Scorecard.
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
		Ignore().
		ID(ctx)
	if err != nil {
		return nil, err
	}

	// NOTE: This might be better as a query, but using insert here since the spec is an inputspec
	src, err := upsertSource(ctx, tx, source)
	if err != nil {
		return nil, err
	}

	log.Println("Source ID", src.ID)

	id, err := tx.CertifyScorecard.Create().
		SetScorecardID(sc).
		SetSource(src).
		OnConflict(
			sql.ConflictColumns(certifyscorecard.FieldScorecardID, certifyscorecard.FieldSourceID),
		).
		Ignore().
		ID(ctx)

	if err != nil {
		return nil, err
	}

	return tx.CertifyScorecard.Get(ctx, id)
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
