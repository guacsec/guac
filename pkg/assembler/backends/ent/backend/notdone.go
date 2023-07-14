package backend

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Retrieval read-only queries for software trees

// Retrieval read-only queries for evidence trees
func (b *EntBackend) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	return nil, nil
}

func (b *EntBackend) Scorecards(ctx context.Context, certifyScorecardSpec *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {
	return nil, nil
}

// Mutations for evidence trees (read-write queries, assume software trees ingested)
func (b *EntBackend) CertifyScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (*model.CertifyScorecard, error) {
	return nil, nil
}

func (b *EntBackend) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInput, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	return nil, nil
}

// Topological queries: queries where node connectivity matters more than node type
func (b *EntBackend) Neighbors(ctx context.Context, node string, usingOnly []model.Edge) ([]model.Node, error) {
	return nil, nil
}
func (b *EntBackend) Node(ctx context.Context, node string) (model.Node, error) { return nil, nil }
func (b *EntBackend) Nodes(ctx context.Context, nodes []string) ([]model.Node, error) {
	return nil, nil
}
func (b *EntBackend) Path(ctx context.Context, subject string, target string, maxPathLength int, usingOnly []model.Edge) ([]model.Node, error) {
	return nil, nil
}
