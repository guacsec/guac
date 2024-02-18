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
	IngestArtifact(ctx context.Context, artifact *model.IDorArtifactInput) (string, error)
	IngestArtifacts(ctx context.Context, artifacts []*model.IDorArtifactInput) ([]string, error)
	IngestBuilder(ctx context.Context, builder *model.IDorBuilderInput) (string, error)
	IngestBuilders(ctx context.Context, builders []*model.IDorBuilderInput) ([]string, error)
	IngestLicense(ctx context.Context, license *model.IDorLicenseInput) (string, error)
	IngestLicenses(ctx context.Context, licenses []*model.IDorLicenseInput) ([]string, error)
	IngestPackage(ctx context.Context, pkg model.IDorPkgInput) (*model.PackageIDs, error)
	IngestPackages(ctx context.Context, pkgs []*model.IDorPkgInput) ([]*model.PackageIDs, error)
	IngestSource(ctx context.Context, source model.IDorSourceInput) (*model.SourceIDs, error)
	IngestSources(ctx context.Context, sources []*model.IDorSourceInput) ([]*model.SourceIDs, error)
	IngestVulnerability(ctx context.Context, vuln model.IDorVulnerabilityInput) (*model.VulnerabilityIDs, error)
	IngestVulnerabilities(ctx context.Context, vulns []*model.IDorVulnerabilityInput) ([]*model.VulnerabilityIDs, error)

	// Mutations for evidence trees (read-write queries, assume software trees ingested)
	IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (string, error)
	IngestCertifyBads(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyBads []*model.CertifyBadInputSpec) ([]string, error)
	IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyGood model.CertifyGoodInputSpec) (string, error)
	IngestCertifyGoods(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyGoods []*model.CertifyGoodInputSpec) ([]string, error)
	IngestCertifyVuln(ctx context.Context, pkg model.IDorPkgInput, vulnerability model.IDorVulnerabilityInput, certifyVuln model.ScanMetadataInput) (string, error)
	IngestCertifyVulns(ctx context.Context, pkgs []*model.IDorPkgInput, vulnerabilities []*model.IDorVulnerabilityInput, certifyVulns []*model.ScanMetadataInput) ([]string, error)
	IngestCertifyLegal(ctx context.Context, subject model.PackageOrSourceInput, declaredLicenses []*model.IDorLicenseInput, discoveredLicenses []*model.IDorLicenseInput, certifyLegal *model.CertifyLegalInputSpec) (string, error)
	IngestCertifyLegals(ctx context.Context, subjects model.PackageOrSourceInputs, declaredLicensesList [][]*model.IDorLicenseInput, discoveredLicensesList [][]*model.IDorLicenseInput, certifyLegals []*model.CertifyLegalInputSpec) ([]string, error)
	IngestDependency(ctx context.Context, pkg model.IDorPkgInput, depPkg model.IDorPkgInput, depPkgMatchType model.MatchFlags, dependency model.IsDependencyInputSpec) (string, error)
	IngestDependencies(ctx context.Context, pkgs []*model.IDorPkgInput, depPkgs []*model.IDorPkgInput, depPkgMatchType model.MatchFlags, dependencies []*model.IsDependencyInputSpec) ([]string, error)
	IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec, includes model.HasSBOMIncludesInputSpec) (string, error)
	IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) ([]string, error)
	IngestHasSourceAt(ctx context.Context, pkg model.IDorPkgInput, pkgMatchType model.MatchFlags, source model.IDorSourceInput, hasSourceAt model.HasSourceAtInputSpec) (string, error)
	IngestHasSourceAts(ctx context.Context, pkgs []*model.IDorPkgInput, pkgMatchType *model.MatchFlags, sources []*model.IDorSourceInput, hasSourceAts []*model.HasSourceAtInputSpec) ([]string, error)
	IngestHasMetadata(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, hasMetadata model.HasMetadataInputSpec) (string, error)
	IngestBulkHasMetadata(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, hasMetadataList []*model.HasMetadataInputSpec) ([]string, error)
	IngestHashEqual(ctx context.Context, artifact model.IDorArtifactInput, equalArtifact model.IDorArtifactInput, hashEqual model.HashEqualInputSpec) (string, error)
	IngestHashEquals(ctx context.Context, artifacts []*model.IDorArtifactInput, otherArtifacts []*model.IDorArtifactInput, hashEquals []*model.HashEqualInputSpec) ([]string, error)
	IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.IDorArtifactInput, occurrence model.IsOccurrenceInputSpec) (string, error)
	IngestOccurrences(ctx context.Context, subjects model.PackageOrSourceInputs, artifacts []*model.IDorArtifactInput, occurrences []*model.IsOccurrenceInputSpec) ([]string, error)
	IngestPkgEqual(ctx context.Context, pkg model.IDorPkgInput, depPkg model.IDorPkgInput, pkgEqual model.PkgEqualInputSpec) (string, error)
	IngestPkgEquals(ctx context.Context, pkgs []*model.IDorPkgInput, otherPackages []*model.IDorPkgInput, pkgEquals []*model.PkgEqualInputSpec) ([]string, error)
	IngestPointOfContact(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, pointOfContact model.PointOfContactInputSpec) (string, error)
	IngestPointOfContacts(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, pointOfContacts []*model.PointOfContactInputSpec) ([]string, error)
	IngestSLSA(ctx context.Context, subject model.IDorArtifactInput, builtFrom []*model.IDorArtifactInput, builtBy model.IDorBuilderInput, slsa model.SLSAInputSpec) (string, error)
	IngestSLSAs(ctx context.Context, subjects []*model.IDorArtifactInput, builtFromList [][]*model.IDorArtifactInput, builtByList []*model.IDorBuilderInput, slsaList []*model.SLSAInputSpec) ([]string, error)
	IngestScorecard(ctx context.Context, source model.IDorSourceInput, scorecard model.ScorecardInputSpec) (string, error)
	IngestScorecards(ctx context.Context, sources []*model.IDorSourceInput, scorecards []*model.ScorecardInputSpec) ([]string, error)
	IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.IDorVulnerabilityInput, vexStatement model.VexStatementInputSpec) (string, error)
	IngestVEXStatements(ctx context.Context, subjects model.PackageOrArtifactInputs, vulnerabilities []*model.IDorVulnerabilityInput, vexStatements []*model.VexStatementInputSpec) ([]string, error)
	IngestVulnEqual(ctx context.Context, vulnerability model.IDorVulnerabilityInput, otherVulnerability model.IDorVulnerabilityInput, vulnEqual model.VulnEqualInputSpec) (string, error)
	IngestVulnEquals(ctx context.Context, vulnerabilities []*model.IDorVulnerabilityInput, otherVulnerabilities []*model.IDorVulnerabilityInput, vulnEquals []*model.VulnEqualInputSpec) ([]string, error)
	IngestVulnerabilityMetadata(ctx context.Context, vulnerability model.IDorVulnerabilityInput, vulnerabilityMetadata model.VulnerabilityMetadataInputSpec) (string, error)
	IngestBulkVulnerabilityMetadata(ctx context.Context, vulnerabilities []*model.IDorVulnerabilityInput, vulnerabilityMetadataList []*model.VulnerabilityMetadataInputSpec) ([]string, error)

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
