package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.25

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// IsDependency is the resolver for the IsDependency field.
func (r *queryResolver) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	return r.Backend.IsDependency(ctx, isDependencySpec)
}
