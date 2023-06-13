package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.32

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// IngestVEXStatement is the resolver for the ingestVEXStatement field.
func (r *mutationResolver) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInput, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	return r.Backend.IngestVEXStatement(ctx, subject, vulnerability, vexStatement)
}

// CertifyVEXStatement is the resolver for the CertifyVEXStatement field.
func (r *queryResolver) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	return r.Backend.CertifyVEXStatement(ctx, certifyVEXStatementSpec)
}
