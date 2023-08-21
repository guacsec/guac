package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.36

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// IngestHasSbom is the resolver for the ingestHasSBOM field.
func (r *mutationResolver) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec) (string, error) {
	ingestedHasSbom, err := r.Backend.IngestHasSbom(ctx, subject, hasSbom)
	if err != nil {
		return "", err
	}
	return ingestedHasSbom.ID, err
}

// IngestHasSBOMs is the resolver for the ingestHasSBOMs field.
func (r *mutationResolver) IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec) ([]string, error) {
	ingestedHasSBOMs, err := r.Backend.IngestHasSBOMs(ctx, subjects, hasSBOMs)
	ingestedHasSBOMSIDS := []string{}
	if err == nil {
		for _, hasSBOM := range ingestedHasSBOMs {
			ingestedHasSBOMSIDS = append(ingestedHasSBOMSIDS, hasSBOM.ID)
		}
	}
	return ingestedHasSBOMSIDS, err
}

// HasSbom is the resolver for the HasSBOM field.
func (r *queryResolver) HasSbom(ctx context.Context, hasSBOMSpec model.HasSBOMSpec) ([]*model.HasSbom, error) {
	return r.Backend.HasSBOM(ctx, &hasSBOMSpec)
}
