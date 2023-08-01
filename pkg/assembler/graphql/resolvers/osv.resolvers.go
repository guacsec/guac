package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.36

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// IngestOsv is the resolver for the ingestOSV field.
func (r *mutationResolver) IngestOsv(ctx context.Context, osv *model.OSVInputSpec) (*model.Osv, error) {
	return r.Backend.IngestOsv(ctx, osv)
}

// IngestOSVs is the resolver for the ingestOSVs field.
func (r *mutationResolver) IngestOSVs(ctx context.Context, osvs []*model.OSVInputSpec) ([]*model.Osv, error) {
	return r.Backend.IngestOSVs(ctx, osvs)
}

// Osv is the resolver for the osv field.
func (r *queryResolver) Osv(ctx context.Context, osvSpec *model.OSVSpec) ([]*model.Osv, error) {
	return r.Backend.Osv(ctx, osvSpec)
}
