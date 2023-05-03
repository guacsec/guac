//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package backends

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Backend interface allows having multiple database backends for the same
// GraphQL interface. All backends must implement all queries specified by the
// GraphQL interface and this is enforced by this interface.
type Backend interface {
	// Retrieval read-only queries for software trees
	Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error)
	Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error)
	Cve(ctx context.Context, cveSpec *model.CVESpec) ([]*model.Cve, error)
	Ghsa(ctx context.Context, ghsaSpec *model.GHSASpec) ([]*model.Ghsa, error)
	Osv(ctx context.Context, osvSpec *model.OSVSpec) ([]*model.Osv, error)
	Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error)
	Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error)

	// Retrieval read-only queries for evidence trees
	CertifyBad(ctx context.Context, certifyBadSpec *model.CertifyBadSpec) ([]*model.CertifyBad, error)
	CertifyGood(ctx context.Context, certifyGoodSpec *model.CertifyGoodSpec) ([]*model.CertifyGood, error)
	CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error)
	CertifyVuln(ctx context.Context, certifyVulnSpec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error)
	HasSBOM(ctx context.Context, hasSBOMSpec *model.HasSBOMSpec) ([]*model.HasSbom, error)
	HasSlsa(ctx context.Context, hasSLSASpec *model.HasSLSASpec) ([]*model.HasSlsa, error)
	HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error)
	HashEqual(ctx context.Context, hashEqualSpec *model.HashEqualSpec) ([]*model.HashEqual, error)
	IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error)
	IsOccurrence(ctx context.Context, isOccurrenceSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error)
	IsVulnerability(ctx context.Context, isVulnerabilitySpec *model.IsVulnerabilitySpec) ([]*model.IsVulnerability, error)
	PkgEqual(ctx context.Context, pkgEqualSpec *model.PkgEqualSpec) ([]*model.PkgEqual, error)
	Scorecards(ctx context.Context, certifyScorecardSpec *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error)

	// Mutations for software trees (read-write queries)
	IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (*model.Artifact, error)
	IngestBuilder(ctx context.Context, builder *model.BuilderInputSpec) (*model.Builder, error)
	IngestCve(ctx context.Context, cve *model.CVEInputSpec) (*model.Cve, error)
	IngestGhsa(ctx context.Context, ghsa *model.GHSAInputSpec) (*model.Ghsa, error)
	IngestMaterials(ctx context.Context, materials []*model.ArtifactInputSpec) ([]*model.Artifact, error)
	IngestOsv(ctx context.Context, osv *model.OSVInputSpec) (*model.Osv, error)
	IngestPackage(ctx context.Context, pkg model.PkgInputSpec) (*model.Package, error)
	IngestSource(ctx context.Context, source model.SourceInputSpec) (*model.Source, error)

	// Mutations for evidence trees (read-write queries, assume software trees ingested)
	CertifyScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (*model.CertifyScorecard, error)
	IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (*model.CertifyBad, error)
	IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyGood model.CertifyGoodInputSpec) (*model.CertifyGood, error)
	IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, dependency model.IsDependencyInputSpec) (*model.IsDependency, error)
	IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec) (*model.HasSbom, error)
	IngestHasSourceAt(ctx context.Context, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error)
	IngestHashEqual(ctx context.Context, artifact model.ArtifactInputSpec, equalArtifact model.ArtifactInputSpec, hashEqual model.HashEqualInputSpec) (*model.HashEqual, error)
	IngestIsVulnerability(ctx context.Context, osv model.OSVInputSpec, vulnerability model.CveOrGhsaInput, isVulnerability model.IsVulnerabilityInputSpec) (*model.IsVulnerability, error)
	IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error)
	IngestPkgEqual(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec) (*model.PkgEqual, error)
	IngestSLSA(ctx context.Context, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error)
	IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInput, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error)
	IngestVulnerability(ctx context.Context, pkg model.PkgInputSpec, vulnerability model.VulnerabilityInput, certifyVuln model.VulnerabilityMetaDataInput) (*model.CertifyVuln, error)

	// Topological queries: queries where node connectivity matters more than node type
	Neighbors(ctx context.Context, node string, usingOnly []model.Edge) ([]model.Node, error)
	Node(ctx context.Context, node string) (model.Node, error)
	Nodes(ctx context.Context, nodes []string) ([]model.Node, error)
	Path(ctx context.Context, subject string, target string, maxPathLength int, usingOnly []model.Edge) ([]model.Node, error)
}

// BackendArgs interface allows each backend to specify the arguments needed to
// initialize (e.g., credentials).
type BackendArgs interface{}
