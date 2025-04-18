package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.70

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// IngestScorecard is the resolver for the ingestScorecard field.
func (r *mutationResolver) IngestScorecard(ctx context.Context, source model.IDorSourceInput, scorecard model.ScorecardInputSpec) (string, error) {
	return r.Backend.IngestScorecard(ctx, source, scorecard)
}

// IngestScorecards is the resolver for the ingestScorecards field.
func (r *mutationResolver) IngestScorecards(ctx context.Context, sources []*model.IDorSourceInput, scorecards []*model.ScorecardInputSpec) ([]string, error) {
	funcName := "IngestScorecards"
	ingestedScorecardsIDS := []string{}
	if len(sources) != len(scorecards) {
		return ingestedScorecardsIDS, fmt.Errorf("%v :: uneven source and scorecards for ingestion", funcName)
	}
	return r.Backend.IngestScorecards(ctx, sources, scorecards)
}

// Scorecards is the resolver for the scorecards field.
func (r *queryResolver) Scorecards(ctx context.Context, scorecardSpec model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {
	return r.Backend.Scorecards(ctx, &scorecardSpec)
}

// ScorecardsList is the resolver for the scorecardsList field.
func (r *queryResolver) ScorecardsList(ctx context.Context, scorecardSpec model.CertifyScorecardSpec, after *string, first *int) (*model.CertifyScorecardConnection, error) {
	return r.Backend.ScorecardsList(ctx, scorecardSpec, after, first)
}
