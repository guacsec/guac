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
	Vulnerabilities(ctx context.Context, vulnSpec *model.VulnerabilitySpec) ([]*model.Vulnerability, error)
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
	VulnEqual(ctx context.Context, vulnEqualSpec *model.VulnEqualSpec) ([]*model.VulnEqual, error)
	PkgEqual(ctx context.Context, pkgEqualSpec *model.PkgEqualSpec) ([]*model.PkgEqual, error)
	Scorecards(ctx context.Context, certifyScorecardSpec *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error)
	HasMetadata(ctx context.Context, hasMetadataSpec *model.HasMetadataSpec) ([]*model.HasMetadata, error)
	PointOfContact(ctx context.Context, pointOfContactSpec *model.PointOfContactSpec) ([]*model.PointOfContact, error)

	// Mutations for software trees (read-write queries)
	IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (*model.Artifact, error)
	IngestArtifacts(ctx context.Context, artifacts []*model.ArtifactInputSpec) ([]*model.Artifact, error)
	IngestBuilder(ctx context.Context, builder *model.BuilderInputSpec) (*model.Builder, error)
	IngestBuilders(ctx context.Context, builders []*model.BuilderInputSpec) ([]*model.Builder, error)
	IngestVulnerability(ctx context.Context, vuln model.VulnerabilityInputSpec) (*model.Vulnerability, error)
	IngestVulnerabilities(ctx context.Context, vulns []*model.VulnerabilityInputSpec) ([]*model.Vulnerability, error)
	IngestPackage(ctx context.Context, pkg model.PkgInputSpec) (*model.Package, error)
	IngestPackages(ctx context.Context, pkgs []*model.PkgInputSpec) ([]*model.Package, error)
	IngestSource(ctx context.Context, source model.SourceInputSpec) (*model.Source, error)
	IngestSources(ctx context.Context, sources []*model.SourceInputSpec) ([]*model.Source, error)

	// Mutations for evidence trees (read-write queries, assume software trees ingested)
	IngestScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (*model.CertifyScorecard, error)
	IngestScorecards(ctx context.Context, sources []*model.SourceInputSpec, scorecards []*model.ScorecardInputSpec) ([]*model.CertifyScorecard, error)
	IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (*model.CertifyBad, error)
	IngestCertifyBads(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyBads []*model.CertifyBadInputSpec) ([]*model.CertifyBad, error)
	IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyGood model.CertifyGoodInputSpec) (*model.CertifyGood, error)
	IngestCertifyGoods(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyGoods []*model.CertifyGoodInputSpec) ([]*model.CertifyGood, error)
	IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, dependency model.IsDependencyInputSpec) (*model.IsDependency, error)
	IngestDependencies(ctx context.Context, pkgs []*model.PkgInputSpec, depPkgs []*model.PkgInputSpec, dependencies []*model.IsDependencyInputSpec) ([]*model.IsDependency, error)
	IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec) (*model.HasSbom, error)
	IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec) ([]*model.HasSbom, error)
	IngestHasSourceAt(ctx context.Context, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error)
	IngestHashEqual(ctx context.Context, artifact model.ArtifactInputSpec, equalArtifact model.ArtifactInputSpec, hashEqual model.HashEqualInputSpec) (*model.HashEqual, error)
	IngestHashEquals(ctx context.Context, artifacts []*model.ArtifactInputSpec, otherArtifacts []*model.ArtifactInputSpec, hashEquals []*model.HashEqualInputSpec) ([]*model.HashEqual, error)
	IngestVulnEqual(ctx context.Context, vulnerability model.VulnerabilityInputSpec, otherVulnerability model.VulnerabilityInputSpec, vulnEqual model.VulnEqualInputSpec) (*model.VulnEqual, error)
	IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error)
	IngestOccurrences(ctx context.Context, subjects model.PackageOrSourceInputs, artifacts []*model.ArtifactInputSpec, occurrences []*model.IsOccurrenceInputSpec) ([]*model.IsOccurrence, error)
	IngestPkgEqual(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec) (*model.PkgEqual, error)
	IngestSLSA(ctx context.Context, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error)
	IngestSLSAs(ctx context.Context, subjects []*model.ArtifactInputSpec, builtFromList [][]*model.ArtifactInputSpec, builtByList []*model.BuilderInputSpec, slsaList []*model.SLSAInputSpec) ([]*model.HasSlsa, error)
	IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInputSpec, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error)
	IngestCertifyVuln(ctx context.Context, pkg model.PkgInputSpec, vulnerability model.VulnerabilityInputSpec, certifyVuln model.ScanMetadataInput) (*model.CertifyVuln, error)
	IngestHasMetadata(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, hasMetadata model.HasMetadataInputSpec) (*model.HasMetadata, error)
	IngestPointOfContact(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, pointOfContact model.PointOfContactInputSpec) (*model.PointOfContact, error)

	// Topological queries: queries where node connectivity matters more than node type
	Neighbors(ctx context.Context, node string, usingOnly []model.Edge) ([]model.Node, error)
	Node(ctx context.Context, node string) (model.Node, error)
	Nodes(ctx context.Context, nodes []string) ([]model.Node, error)
	Path(ctx context.Context, subject string, target string, maxPathLength int, usingOnly []model.Edge) ([]model.Node, error)

	// Search queries: queries to help find data in GUAC based on text search
	FindSoftware(ctx context.Context, searchText string) ([]model.PackageSourceOrArtifact, error)
}

// BackendArgs interface allows each backend to specify the arguments needed to
// initialize (e.g., credentials).
type BackendArgs interface{}
