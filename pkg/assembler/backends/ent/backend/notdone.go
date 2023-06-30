package backend

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Retrieval read-only queries for software trees
func (b *EntBackend) Cve(ctx context.Context, cveSpec *model.CVESpec) ([]*model.Cve, error) {
	return nil, nil
}
func (b *EntBackend) Ghsa(ctx context.Context, ghsaSpec *model.GHSASpec) ([]*model.Ghsa, error) {
	return nil, nil
}
func (b *EntBackend) Osv(ctx context.Context, osvSpec *model.OSVSpec) ([]*model.Osv, error) {
	return nil, nil
}
func (b *EntBackend) Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
	return nil, nil
}

// Retrieval read-only queries for evidence trees
func (b *EntBackend) CertifyBad(ctx context.Context, certifyBadSpec *model.CertifyBadSpec) ([]*model.CertifyBad, error) {
	return nil, nil
}
func (b *EntBackend) CertifyGood(ctx context.Context, certifyGoodSpec *model.CertifyGoodSpec) ([]*model.CertifyGood, error) {
	return nil, nil
}
func (b *EntBackend) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {
	return nil, nil
}
func (b *EntBackend) CertifyVuln(ctx context.Context, certifyVulnSpec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	return nil, nil
}
func (b *EntBackend) HasSBOM(ctx context.Context, hasSBOMSpec *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	return nil, nil
}
func (b *EntBackend) HasSlsa(ctx context.Context, hasSLSASpec *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	return nil, nil
}
func (b *EntBackend) HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	return nil, nil
}
func (b *EntBackend) HashEqual(ctx context.Context, hashEqualSpec *model.HashEqualSpec) ([]*model.HashEqual, error) {
	return nil, nil
}

func (b *EntBackend) IsVulnerability(ctx context.Context, isVulnerabilitySpec *model.IsVulnerabilitySpec) ([]*model.IsVulnerability, error) {
	return nil, nil
}
func (b *EntBackend) PkgEqual(ctx context.Context, pkgEqualSpec *model.PkgEqualSpec) ([]*model.PkgEqual, error) {
	return nil, nil
}
func (b *EntBackend) Scorecards(ctx context.Context, certifyScorecardSpec *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {
	return nil, nil
}

// Mutations for software trees (read-write queries)
func (b *EntBackend) IngestCve(ctx context.Context, cve *model.CVEInputSpec) (*model.Cve, error) {
	return nil, nil
}
func (b *EntBackend) IngestGhsa(ctx context.Context, ghsa *model.GHSAInputSpec) (*model.Ghsa, error) {
	return nil, nil
}
func (b *EntBackend) IngestMaterials(ctx context.Context, materials []*model.ArtifactInputSpec) ([]*model.Artifact, error) {
	return nil, nil
}
func (b *EntBackend) IngestOsv(ctx context.Context, osv *model.OSVInputSpec) (*model.Osv, error) {
	return nil, nil
}

// Mutations for evidence trees (read-write queries, assume software trees ingested)
func (b *EntBackend) CertifyScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (*model.CertifyScorecard, error) {
	return nil, nil
}
func (b *EntBackend) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (*model.CertifyBad, error) {
	return nil, nil
}
func (b *EntBackend) IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyGood model.CertifyGoodInputSpec) (*model.CertifyGood, error) {
	return nil, nil
}

func (b *EntBackend) IngestHasSourceAt(ctx context.Context, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error) {
	return nil, nil
}
func (b *EntBackend) IngestHashEqual(ctx context.Context, artifact model.ArtifactInputSpec, equalArtifact model.ArtifactInputSpec, hashEqual model.HashEqualInputSpec) (*model.HashEqual, error) {
	return nil, nil
}
func (b *EntBackend) IngestIsVulnerability(ctx context.Context, osv model.OSVInputSpec, vulnerability model.CveOrGhsaInput, isVulnerability model.IsVulnerabilityInputSpec) (*model.IsVulnerability, error) {
	return nil, nil
}

//	func (b *EntBackend) IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error) {
//		return nil, nil
//	}
func (b *EntBackend) IngestPkgEqual(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec) (*model.PkgEqual, error) {
	return nil, nil
}
func (b *EntBackend) IngestSLSA(ctx context.Context, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {
	return nil, nil
}
func (b *EntBackend) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInput, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	return nil, nil
}
func (b *EntBackend) IngestVulnerability(ctx context.Context, pkg model.PkgInputSpec, vulnerability model.VulnerabilityInput, certifyVuln model.VulnerabilityMetaDataInput) (*model.CertifyVuln, error) {
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
