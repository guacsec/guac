package backend

import (
	"context"
	"log"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Retrieval read-only queries for evidence trees
func (b *EntBackend) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	log.Println("CertifyVEXStatement not implemented")
	return nil, nil
}

func (b *EntBackend) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInput, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	log.Println("IngestVEXStatement not implemented")
	return nil, nil
}

// Topological queries: queries where node connectivity matters more than node type
func (b *EntBackend) Nodes(ctx context.Context, nodes []string) ([]model.Node, error) {
	log.Println("Nodes not implemented")
	return nil, nil
}
func (b *EntBackend) Path(ctx context.Context, subject string, target string, maxPathLength int, usingOnly []model.Edge) ([]model.Node, error) {
	log.Println("Path not implemented")
	return nil, nil
}
