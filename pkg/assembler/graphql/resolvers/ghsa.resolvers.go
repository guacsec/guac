package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.35

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// IngestGhsa is the resolver for the ingestGHSA field.
func (r *mutationResolver) IngestGhsa(ctx context.Context, ghsa *model.GHSAInputSpec) (*model.Ghsa, error) {
	return r.Backend.IngestGhsa(ctx, ghsa)
}

// IngestGHSAs is the resolver for the ingestGHSAs field.
func (r *mutationResolver) IngestGHSAs(ctx context.Context, ghsas []*model.GHSAInputSpec) ([]*model.Ghsa, error) {
	return r.Backend.IngestGHSAs(ctx, ghsas)
}

// Ghsa is the resolver for the ghsa field.
func (r *queryResolver) Ghsa(ctx context.Context, ghsaSpec model.GHSASpec) ([]*model.Ghsa, error) {
	return r.Backend.Ghsa(ctx, &ghsaSpec)
}
