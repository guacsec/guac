package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.70

import (
	"context"
)

// Delete is the resolver for the delete field.
func (r *mutationResolver) Delete(ctx context.Context, node string) (bool, error) {
	return r.Backend.Delete(ctx, node)
}
