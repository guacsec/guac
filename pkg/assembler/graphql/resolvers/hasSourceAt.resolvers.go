package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.31

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// IngestHasSourceAt is the resolver for the ingestHasSourceAt field.
func (r *mutationResolver) IngestHasSourceAt(ctx context.Context, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error) {
	return r.Backend.IngestHasSourceAt(ctx, pkg, pkgMatchType, source, hasSourceAt)
}

// HasSourceAt is the resolver for the HasSourceAt field.
func (r *queryResolver) HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	return r.Backend.HasSourceAt(ctx, hasSourceAtSpec)
}
