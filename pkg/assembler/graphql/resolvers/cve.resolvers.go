package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.35

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// IngestCve is the resolver for the ingestCVE field.
func (r *mutationResolver) IngestCve(ctx context.Context, cve *model.CVEInputSpec) (*model.Cve, error) {
	return r.Backend.IngestCve(ctx, cve)
}

// IngestCVEs is the resolver for the ingestCVEs field.
func (r *mutationResolver) IngestCVEs(ctx context.Context, cves []*model.CVEInputSpec) ([]*model.Cve, error) {
	return r.Backend.IngestCVEs(ctx, cves)
}

// Cve is the resolver for the cve field.
func (r *queryResolver) Cve(ctx context.Context, cveSpec model.CVESpec) ([]*model.Cve, error) {
	return r.Backend.Cve(ctx, &cveSpec)
}
