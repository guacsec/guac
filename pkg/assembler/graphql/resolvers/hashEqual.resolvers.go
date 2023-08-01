package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.35

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// IngestHashEqual is the resolver for the ingestHashEqual field.
func (r *mutationResolver) IngestHashEqual(ctx context.Context, artifact model.ArtifactInputSpec, otherArtifact model.ArtifactInputSpec, hashEqual model.HashEqualInputSpec) (*model.HashEqual, error) {
	return r.Backend.IngestHashEqual(ctx, artifact, otherArtifact, hashEqual)
}

// IngestHashEquals is the resolver for the ingestHashEquals field.
func (r *mutationResolver) IngestHashEquals(ctx context.Context, artifacts []*model.ArtifactInputSpec, otherArtifacts []*model.ArtifactInputSpec, hashEquals []*model.HashEqualInputSpec) ([]*model.HashEqual, error) {
	return r.Backend.IngestHashEquals(ctx, artifacts, otherArtifacts, hashEquals)
}

// HashEqual is the resolver for the HashEqual field.
func (r *queryResolver) HashEqual(ctx context.Context, hashEqualSpec model.HashEqualSpec) ([]*model.HashEqual, error) {
	return r.Backend.HashEqual(ctx, &hashEqualSpec)
}
