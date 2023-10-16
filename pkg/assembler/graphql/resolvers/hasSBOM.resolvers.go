package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.39

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// IngestHasSbom is the resolver for the ingestHasSBOM field.
func (r *mutationResolver) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec) (string, error) {
	funcName := "IngestHasSbom"
	if err := helper.ValidatePackageOrArtifactInput(&subject, funcName); err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	if hasSbom.KnownSince.IsZero() {
		return "", gqlerror.Errorf("hasSbom.KnownSince is a zero time")
	}

	ingestedHasSbom, err := r.Backend.IngestHasSbom(ctx, subject, hasSbom)
	if err != nil {
		return "", err
	}
	return ingestedHasSbom.ID, err
}

// IngestHasSBOMs is the resolver for the ingestHasSBOMs field.
func (r *mutationResolver) IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec) ([]string, error) {
	funcName := "IngestHasSBOMs"
	valuesDefined := 0
	ingestedHasSBOMSIDS := []string{}
	if len(subjects.Packages) > 0 {
		if len(subjects.Packages) != len(hasSBOMs) {
			return ingestedHasSBOMSIDS, gqlerror.Errorf("%v :: uneven packages and hasSBOMs for ingestion", funcName)
		}
		valuesDefined = valuesDefined + 1
	}
	if len(subjects.Artifacts) > 0 {
		if len(subjects.Artifacts) != len(hasSBOMs) {
			return ingestedHasSBOMSIDS, gqlerror.Errorf("%v :: uneven artifact and hasSBOMs for ingestion", funcName)
		}
		valuesDefined = valuesDefined + 1
	}
	if valuesDefined != 1 {
		return ingestedHasSBOMSIDS, gqlerror.Errorf("%v :: must specify at most packages or artifacts for ingestion", funcName)
	}

	for _, hasSbom := range hasSBOMs {
		if hasSbom.KnownSince.IsZero() {
			return ingestedHasSBOMSIDS, gqlerror.Errorf("hasSBOMS contains a zero time")
		}
	}

	ingestedHasSBOMs, err := r.Backend.IngestHasSBOMs(ctx, subjects, hasSBOMs)
	if err == nil {
		for _, hasSBOM := range ingestedHasSBOMs {
			ingestedHasSBOMSIDS = append(ingestedHasSBOMSIDS, hasSBOM.ID)
		}
	}
	return ingestedHasSBOMSIDS, err
}

// HasSbom is the resolver for the HasSBOM field.
func (r *queryResolver) HasSbom(ctx context.Context, hasSBOMSpec model.HasSBOMSpec) ([]*model.HasSbom, error) {
	if err := helper.ValidatePackageOrArtifactQueryFilter(hasSBOMSpec.Subject); err != nil {
		return nil, gqlerror.Errorf("%v :: %s", "HasSBOM", err)
	}
	return r.Backend.HasSBOM(ctx, &hasSBOMSpec)
}
