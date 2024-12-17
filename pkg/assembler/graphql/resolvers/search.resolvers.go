package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.60

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

// QueryPackagesListForScan is the resolver for the queryPackagesListForScan field.
func (r *queryResolver) QueryPackagesListForScan(ctx context.Context, pkgIDs []string, after *string, first *int) (*model.PackageConnection, error) {
	return r.Backend.QueryPackagesListForScan(ctx, pkgIDs, after, first)
}

// FindPackagesThatNeedScanning is the resolver for the findPackagesThatNeedScanning field.
func (r *queryResolver) FindPackagesThatNeedScanning(ctx context.Context, queryType model.QueryType, lastScan *int) ([]string, error) {
	return r.Backend.FindPackagesThatNeedScanning(ctx, queryType, lastScan)
}
