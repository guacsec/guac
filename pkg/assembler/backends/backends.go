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
	Licenses(ctx context.Context, licenseSpec *model.LicenseSpec) ([]*model.License, error)
	Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error)
	Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error)
	Vulnerabilities(ctx context.Context, vulnSpec *model.VulnerabilitySpec) ([]*model.Vulnerability, error)

	// Retrieval read-only queries for evidence trees
	CertifyBad(ctx context.Context, certifyBadSpec *model.CertifyBadSpec) ([]*model.CertifyBad, error)
	CertifyGood(ctx context.Context, certifyGoodSpec *model.CertifyGoodSpec) ([]*model.CertifyGood, error)
	CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error)
	CertifyVuln(ctx context.Context, certifyVulnSpec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error)
	CertifyLegal(ctx context.Context, certifyLegalSpec *model.CertifyLegalSpec) ([]*model.CertifyLegal, error)
	HasSBOM(ctx context.Context, hasSBOMSpec *model.HasSBOMSpec) ([]*model.HasSbom, error)
	HasSlsa(ctx context.Context, hasSLSASpec *model.HasSLSASpec) ([]*model.HasSlsa, error)
	HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error)
	HasMetadata(ctx context.Context, hasMetadataSpec *model.HasMetadataSpec) ([]*model.HasMetadata, error)
	HashEqual(ctx context.Context, hashEqualSpec *model.HashEqualSpec) ([]*model.HashEqual, error)
	IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error)
	IsOccurrence(ctx context.Context, isOccurrenceSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error)
	PkgEqual(ctx context.Context, pkgEqualSpec *model.PkgEqualSpec) ([]*model.PkgEqual, error)
	PointOfContact(ctx context.Context, pointOfContactSpec *model.PointOfContactSpec) ([]*model.PointOfContact, error)
	Scorecards(ctx context.Context, certifyScorecardSpec *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error)
	VulnEqual(ctx context.Context, vulnEqualSpec *model.VulnEqualSpec) ([]*model.VulnEqual, error)
	VulnerabilityMetadata(ctx context.Context, vulnerabilityMetadataSpec *model.VulnerabilityMetadataSpec) ([]*model.VulnerabilityMetadata, error)

	// Mutations for software trees (read-write queries)

	IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (string, error)
	IngestArtifacts(ctx context.Context, artifacts []*model.ArtifactInputSpec) ([]string, error)
	IngestBuilder(ctx context.Context, builder *model.BuilderInputSpec) (string, error)
	IngestBuilders(ctx context.Context, builders []*model.BuilderInputSpec) ([]string, error)
	IngestVulnerability(ctx context.Context, vuln model.VulnerabilityInputSpec) (string, error)
	IngestVulnerabilities(ctx context.Context, vulns []*model.VulnerabilityInputSpec) ([]string, error)
	IngestPackage(ctx context.Context, pkg model.PkgInputSpec) (string, error)
	IngestPackages(ctx context.Context, pkgs []*model.PkgInputSpec) ([]string, error)
	IngestSource(ctx context.Context, source model.SourceInputSpec) (string, error)
	IngestSources(ctx context.Context, sources []*model.SourceInputSpec) ([]string, error)
	IngestLicense(ctx context.Context, license *model.LicenseInputSpec) (string, error)
	IngestLicenses(ctx context.Context, licenses []*model.LicenseInputSpec) ([]string, error)

	// Mutations for evidence trees (read-write queries, assume software trees ingested)
	IngestScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (string, error)
	IngestScorecards(ctx context.Context, sources []*model.SourceInputSpec, scorecards []*model.ScorecardInputSpec) ([]string, error)
	IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (string, error)
	IngestCertifyBads(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyBads []*model.CertifyBadInputSpec) ([]string, error)
	IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyGood model.CertifyGoodInputSpec) (string, error)
	IngestCertifyGoods(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyGoods []*model.CertifyGoodInputSpec) ([]string, error)
	IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependency model.IsDependencyInputSpec) (string, error)
	IngestDependencies(ctx context.Context, pkgs []*model.PkgInputSpec, depPkgs []*model.PkgInputSpec, depPkgMatchType model.MatchFlags, dependencies []*model.IsDependencyInputSpec) ([]string, error)
	IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec) (string, error)
	IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec) ([]string, error)
	IngestHasSourceAt(ctx context.Context, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (string, error)
	IngestHashEqual(ctx context.Context, artifact model.ArtifactInputSpec, equalArtifact model.ArtifactInputSpec, hashEqual model.HashEqualInputSpec) (string, error)
	IngestHashEquals(ctx context.Context, artifacts []*model.ArtifactInputSpec, otherArtifacts []*model.ArtifactInputSpec, hashEquals []*model.HashEqualInputSpec) ([]string, error)
	IngestVulnEqual(ctx context.Context, vulnerability model.VulnerabilityInputSpec, otherVulnerability model.VulnerabilityInputSpec, vulnEqual model.VulnEqualInputSpec) (string, error)
	IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (string, error)
	IngestOccurrences(ctx context.Context, subjects model.PackageOrSourceInputs, artifacts []*model.ArtifactInputSpec, occurrences []*model.IsOccurrenceInputSpec) ([]string, error)
	IngestPkgEqual(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec) (string, error)
	IngestSLSA(ctx context.Context, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (string, error)
	IngestSLSAs(ctx context.Context, subjects []*model.ArtifactInputSpec, builtFromList [][]*model.ArtifactInputSpec, builtByList []*model.BuilderInputSpec, slsaList []*model.SLSAInputSpec) ([]string, error)
	IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.VulnerabilityInputSpec, vexStatement model.VexStatementInputSpec) (string, error)
	IngestVEXStatements(ctx context.Context, subjects model.PackageOrArtifactInputs, vulnerabilities []*model.VulnerabilityInputSpec, vexStatements []*model.VexStatementInputSpec) ([]string, error)
	IngestCertifyVuln(ctx context.Context, pkg model.PkgInputSpec, vulnerability model.VulnerabilityInputSpec, certifyVuln model.ScanMetadataInput) (string, error)
	IngestCertifyVulns(ctx context.Context, pkgs []*model.PkgInputSpec, vulnerabilities []*model.VulnerabilityInputSpec, certifyVulns []*model.ScanMetadataInput) ([]string, error)
	IngestCertifyLegal(ctx context.Context, subject model.PackageOrSourceInput, declaredLicenses []*model.LicenseInputSpec, discoveredLicenses []*model.LicenseInputSpec, certifyLegal *model.CertifyLegalInputSpec) (string, error)
	IngestCertifyLegals(ctx context.Context, subjects model.PackageOrSourceInputs, declaredLicensesList [][]*model.LicenseInputSpec, discoveredLicensesList [][]*model.LicenseInputSpec, certifyLegals []*model.CertifyLegalInputSpec) ([]string, error)
	IngestHasMetadata(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, hasMetadata model.HasMetadataInputSpec) (string, error)
	IngestPointOfContact(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, pointOfContact model.PointOfContactInputSpec) (string, error)
	IngestVulnerabilityMetadata(ctx context.Context, vulnerability model.VulnerabilityInputSpec, vulnerabilityMetadata model.VulnerabilityMetadataInputSpec) (string, error)
	IngestBulkVulnerabilityMetadata(ctx context.Context, vulnerabilities []*model.VulnerabilityInputSpec, vulnerabilityMetadataList []*model.VulnerabilityMetadataInputSpec) ([]string, error)

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
