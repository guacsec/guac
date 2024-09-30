package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.54

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// FindSoftware is the resolver for the findSoftware field.
func (r *queryResolver) FindSoftware(ctx context.Context, searchText string) ([]model.PackageSourceOrArtifact, error) {
	return r.Backend.FindSoftware(ctx, searchText)
}

// FindSoftwareList is the resolver for the findSoftwareList field.
func (r *queryResolver) FindSoftwareList(ctx context.Context, searchText string, after *string, first *int) (*model.FindSoftwareConnection, error) {
	return r.Backend.FindSoftwareList(ctx, searchText, after, first)
}

// QueryPackagesListForType is the resolver for the queryPackagesListForType field.
func (r *queryResolver) QueryPackagesListForType(ctx context.Context, pkgSpec model.PkgSpec, queryType model.QueryType, lastInterval *int, after *string, first *int) (*model.PackageConnection, error) {
	if queryType == model.QueryTypeLicense {
		return r.Backend.QueryLicensePackagesList(ctx, pkgSpec, lastInterval, after, first)
	} else {
		return r.Backend.QueryVulnPackagesList(ctx, pkgSpec, lastInterval, after, first)
	}
}
