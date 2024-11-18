//
// Copyright 2024 The GUAC Authors.
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

package clients

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Khan/genqlient/graphql"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

const (
	// nouns
	defaultHashAlgorithm   = "sha256"
	defaultSourceType      = "test-type"
	defaultSourceNamespace = "test-namespace"

	// IsOccurrence
	defaultIsOccurrenceJustification = "test-justification"
	defaultIsOccurrenceOrigin        = "test-origin"
	defaultIsOccurrenceCollector     = "test-collector"

	// HasSbom
	defaultHasSbomOrigin           = "test-origin"
	defaultHasSbomCollector        = "test-collector"
	defaultHasSbomUri              = "test-uri"
	defaultHasSbomDownloadLocation = "test-download-loc"
	defaultHasSbomDigest           = "test-digest"

	// IsDependency
	defaultIsDependencyDependencyType = gql.DependencyTypeUnknown
	defaultIsDependencyJustification  = "test-justification"
	defaultIsDependencyOrigin         = "test-origin"
	defaultIsDependencyCollector      = "test-collector"

	// HashEquals
	defaultHashEqualJustification = "test-justification"
	defaultHashEqualOrigin        = "test-origin"
	defaultHashEqualCollector     = "test-collector"

	// HasSlsa
	defaultHasSlsaBuildType      = "test-builder=type"
	defaultHasSlsaVersion        = "test-slsa-version"
	defaultHasSlsaOrigin         = "test-origin"
	defaultHasSlsaCollector      = "test-collector"
	defaultHasSlsaPredicateKey   = "test-predicate-key"
	defaultHasSlsaPredicateValue = "test-predicate-value"
)

// GuacData Defines the Guac graph, to test clients of the Graphql server.
//
// This type, along with the Ingest function, is similar to the backend IngestPredicates
// type and the corresponding assembler function, but allows for significantly less verbose
// tests by specifying each noun with a single string and making the various InputSpec
// structs optional. Additionally, t.Fatalf is called upon any errors. However, this also means
// that a few inputs aren't supported, such as finer-grained definition of nouns.
//
// All verbs are currently attached to packge version nodes, but a configuration for this
// could be added if needed.
type GuacData struct {
	/** the nouns need to be specified here in order to be referenced from a verb **/
	Packages        []string // packages are specified by purl
	Artifacts       []string // artifacts are specified by digest
	Sources         []string // sources are specified by the name in the SourceName node
	Builders        []string // builders are specified by URI
	Vulnerabilities []string // vulnerabilities are specified by type and ID. The type and ID are separated by a "/".

	/** verbs **/
	HasSboms       []HasSbom
	IsOccurrences  []IsOccurrence
	IsDependencies []IsDependency
	HashEquals     []HashEqual
	HasSlsas       []HasSlsa
	CertifyVulns   []CertifyVuln

	// Other graphql verbs still need to be added here
}

type IsDependency struct {
	DependentPkg  string                     // a previously ingested purl
	DependencyPkg string                     // a previously ingested purl
	Spec          *gql.IsDependencyInputSpec // if nil, a default will be used
}

type IsOccurrence struct {
	Subject  string                     // a previously ingested purl or source
	Artifact string                     // a previously ingested digest
	Spec     *gql.IsOccurrenceInputSpec // if nil, a default will be used
}

type HasSbom struct {
	Subject                string   // a previously ingested purl or digest
	IncludedSoftware       []string // a list of previously ingested purls and digests
	IncludedIsDependencies []IsDependency
	IncludedIsOccurrences  []IsOccurrence
	Spec                   *gql.HasSBOMInputSpec // if nil, a default will be used
}

type HashEqual struct {
	ArtifactA string                  // a previously ingested digest
	ArtifactB string                  // a previously ingested digest
	Spec      *gql.HashEqualInputSpec // if nil, a default will be used
}

type HasSlsa struct {
	Subject   string             // a previously ingested digest
	BuiltFrom []string           // a list of previously ingested digests
	BuiltBy   string             // a previously ingested builder
	Spec      *gql.SLSAInputSpec // if nil, a default will be used
}

type CertifyVuln struct {
	Package       string
	Vulnerability string
	Metadata      *gql.ScanMetadataInput // if nil, a default will be used
}

// maintains the ids of nouns, to use when ingesting verbs
type nounIds struct {
	PackageIds       map[string]string // map from purls to IDs of PackageName nodes
	ArtifactIds      map[string]string // map from digest to IDs of Artifact nodes
	SourceIds        map[string]string // map from source names to IDs of SourceName nodes
	BuilderIds       map[string]string // map from URI to IDs of Builder nodes
	VulnerabilityIds map[string]string // map from vulnerability type and ID to IDs of Vulnerability nodes
}

func Ingest(ctx context.Context, t *testing.T, gqlClient graphql.Client, data GuacData) nounIds {
	packageIds := map[string]string{}
	for _, pkg := range data.Packages {
		packageIds[pkg] = ingestPackage(ctx, t, gqlClient, pkg)
	}

	artifactIds := map[string]string{}
	for _, artifact := range data.Artifacts {
		artifactIds[artifact] = ingestArtifact(ctx, t, gqlClient, artifact)
	}

	sourceIds := map[string]string{}
	for _, source := range data.Sources {
		sourceIds[source] = ingestSource(ctx, t, gqlClient, source)
	}

	builderIds := map[string]string{}
	for _, builder := range data.Builders {
		builderIds[builder] = ingestBuilder(ctx, t, gqlClient, builder)
	}

	vulnerabilityIds := map[string]string{}
	for _, vuln := range data.Vulnerabilities {
		vulnerabilityIds[vuln] = ingestVulnerability(ctx, t, gqlClient, vuln)
	}

	i := nounIds{
		PackageIds:       packageIds,
		ArtifactIds:      artifactIds,
		SourceIds:        sourceIds,
		BuilderIds:       builderIds,
		VulnerabilityIds: vulnerabilityIds,
	}

	for _, sbom := range data.HasSboms {
		i.ingestHasSbom(ctx, t, gqlClient, sbom)
	}

	for _, isDependency := range data.IsDependencies {
		i.ingestIsDependency(ctx, t, gqlClient, isDependency)
	}

	for _, isOccurrence := range data.IsOccurrences {
		i.ingestIsOccurrence(ctx, t, gqlClient, isOccurrence)
	}

	for _, hashEqual := range data.HashEquals {
		i.ingestHashEqual(ctx, t, gqlClient, hashEqual)
	}

	for _, hasSlsa := range data.HasSlsas {
		i.ingestHasSlsa(ctx, t, gqlClient, hasSlsa)
	}

	for _, certifyVuln := range data.CertifyVulns {
		i.ingestCertifyVuln(ctx, t, gqlClient, certifyVuln)
	}

	return i
}

func (i nounIds) ingestHasSlsa(ctx context.Context, t *testing.T, gqlClient graphql.Client, hasSlsa HasSlsa) {
	slsaSpec := hasSlsa.Spec
	if slsaSpec == nil {
		slsaSpec = &gql.SLSAInputSpec{
			BuildType: defaultHasSlsaBuildType,
			SlsaPredicate: []gql.SLSAPredicateInputSpec{
				{Key: defaultHasSlsaPredicateKey, Value: defaultHasSlsaPredicateValue},
			},
			SlsaVersion: defaultHasSlsaVersion,
			Origin:      defaultHasSlsaOrigin,
			Collector:   defaultHasSlsaCollector,
		}
	}

	subjectId, ok := i.ArtifactIds[hasSlsa.Subject]
	if !ok {
		t.Fatalf("The digest %s has not been ingested", hasSlsa.Subject)
	}
	subjectSpec := gql.IDorArtifactInput{ArtifactID: &subjectId}

	builtFromSpecs := []gql.IDorArtifactInput{}
	for _, buildMaterial := range hasSlsa.BuiltFrom {
		buildMaterialId, ok := i.ArtifactIds[buildMaterial]
		if !ok {
			t.Fatalf("The digest %s has not been ingested", buildMaterial)
		}
		builtFromSpec := gql.IDorArtifactInput{ArtifactID: &buildMaterialId}
		builtFromSpecs = append(builtFromSpecs, builtFromSpec)
	}

	builderId, ok := i.BuilderIds[hasSlsa.BuiltBy]
	if !ok {
		t.Fatalf("The builder %s has not been ingested", hasSlsa.BuiltBy)
	}
	builtBySpec := gql.IDorBuilderInput{BuilderID: &builderId}

	_, err := gql.IngestSLSAForArtifact(ctx, gqlClient, subjectSpec, builtFromSpecs, builtBySpec, *slsaSpec)
	if err != nil {
		t.Fatalf("Error ingesting HasSlsa when setting up test: %s", err)
	}
}

func (i nounIds) ingestHashEqual(ctx context.Context, t *testing.T, gqlClient graphql.Client, hashEqual HashEqual) {
	spec := hashEqual.Spec
	if spec == nil {
		spec = &gql.HashEqualInputSpec{
			Justification: defaultHashEqualJustification,
			Origin:        defaultHashEqualOrigin,
			Collector:     defaultHashEqualCollector,
		}
	}

	artifactAId, ok := i.ArtifactIds[hashEqual.ArtifactA]
	if !ok {
		t.Fatalf("The digest %s has not been ingested", hashEqual.ArtifactA)
	}
	artifactBId, ok := i.ArtifactIds[hashEqual.ArtifactB]
	if !ok {
		t.Fatalf("The digest %s has not been ingested", hashEqual.ArtifactB)
	}

	artifactASpec := gql.IDorArtifactInput{ArtifactID: &artifactAId}
	artifactBSpec := gql.IDorArtifactInput{ArtifactID: &artifactBId}
	_, err := gql.IngestHashEqual(ctx, gqlClient, artifactASpec, artifactBSpec, *spec)
	if err != nil {
		t.Fatalf("Error ingesting HashEqual when setting up test: %s", err)
	}
}

// Returns the id of the IsDependency node
func (i nounIds) ingestIsDependency(ctx context.Context, t *testing.T, gqlClient graphql.Client, isDependency IsDependency) string {
	spec := isDependency.Spec
	if spec == nil {
		spec = &gql.IsDependencyInputSpec{
			DependencyType: defaultIsDependencyDependencyType,
			Justification:  defaultIsDependencyJustification,
			Origin:         defaultIsDependencyOrigin,
			Collector:      defaultIsDependencyCollector,
		}
	}

	dependentId, ok := i.PackageIds[isDependency.DependentPkg]
	if !ok {
		t.Fatalf("The purl %s has not been ingested", isDependency.DependentPkg)
	}
	dependencyId := i.PackageIds[isDependency.DependencyPkg]
	if !ok {
		t.Fatalf("The purl %s has not been ingested", isDependency.DependencyPkg)
	}

	// The IsDependency is attached to the package version node
	dependentSpec := gql.IDorPkgInput{PackageVersionID: &dependentId}
	dependencySpec := gql.IDorPkgInput{PackageVersionID: &dependencyId}

	res, err := gql.IngestIsDependency(ctx, gqlClient, dependentSpec, dependencySpec, *spec)
	if err != nil {
		t.Fatalf("Error ingesting IsDependency when setting up test: %s", err)
	}
	return res.GetIngestDependency()
}

// Returns the ID of the IsOccurrence node.
func (i nounIds) ingestIsOccurrence(ctx context.Context, t *testing.T, gqlClient graphql.Client, isOccurrence IsOccurrence) string {
	spec := isOccurrence.Spec
	if spec == nil {
		spec = &gql.IsOccurrenceInputSpec{
			Justification: defaultIsOccurrenceJustification,
			Origin:        defaultIsOccurrenceOrigin,
			Collector:     defaultIsOccurrenceCollector,
		}
	}

	artifactId, ok := i.ArtifactIds[isOccurrence.Artifact]
	if !ok {
		t.Fatalf("The digest %s has not been ingested", isOccurrence.Artifact)
	}
	artifactSpec := gql.IDorArtifactInput{ArtifactID: &artifactId}

	// the subject can be either a package or a source
	if v, ok := i.PackageIds[isOccurrence.Subject]; ok {
		pkgSpec := gql.IDorPkgInput{PackageVersionID: &v}
		res, err := gql.IngestIsOccurrencePkg(ctx, gqlClient, pkgSpec, artifactSpec, *spec)
		if err != nil {
			t.Fatalf("Error ingesting IsOccurrence: %s", err)
		}
		return res.GetIngestOccurrence()

	} else if v, ok := i.SourceIds[isOccurrence.Subject]; ok {
		sourceSpec := gql.IDorSourceInput{SourceNameID: &v}
		res, err := gql.IngestIsOccurrenceSrc(ctx, gqlClient, sourceSpec, artifactSpec, *spec)
		if err != nil {
			t.Fatalf("Error ingesting IsOccurrence: %s", err)
		}
		return res.GetIngestOccurrence()
	}

	t.Fatalf("The purl or source %s has not been ingested", isOccurrence.Subject)
	return ""
}

func (i nounIds) ingestHasSbom(ctx context.Context, t *testing.T, gqlClient graphql.Client, hasSbom HasSbom) {
	isDependencyIds := []string{}
	for _, dependency := range hasSbom.IncludedIsDependencies {
		id := i.ingestIsDependency(ctx, t, gqlClient, dependency)
		isDependencyIds = append(isDependencyIds, id)
	}

	isOccurrenceIds := []string{}
	for _, occurrence := range hasSbom.IncludedIsOccurrences {
		id := i.ingestIsOccurrence(ctx, t, gqlClient, occurrence)
		isOccurrenceIds = append(isOccurrenceIds, id)
	}

	includedPackageIds := []string{}
	includedArtifactIds := []string{}
	for _, software := range hasSbom.IncludedSoftware {
		if id, ok := i.PackageIds[software]; ok {
			includedPackageIds = append(includedPackageIds, id)
		} else if id, ok := i.ArtifactIds[software]; ok {
			includedArtifactIds = append(includedArtifactIds, id)
		} else {
			t.Fatalf("The purl or digest %s has not been ingested", software)
		}
	}

	sbomSpec := hasSbom.Spec
	if hasSbom.Spec == nil {
		sbomSpec = &gql.HasSBOMInputSpec{
			Uri:              defaultHasSbomUri,
			Algorithm:        defaultHashAlgorithm,
			Digest:           defaultHasSbomDigest,
			DownloadLocation: defaultHasSbomDownloadLocation,
			Origin:           defaultHasSbomOrigin,
			Collector:        defaultHasSbomCollector,
			KnownSince:       time.Now(),
		}
	}
	includesSpec := gql.HasSBOMIncludesInputSpec{
		Packages:     includedPackageIds,
		Artifacts:    includedArtifactIds,
		Dependencies: isDependencyIds,
		Occurrences:  isOccurrenceIds,
	}

	// the subject can be either a package or an artifact
	if v, ok := i.PackageIds[hasSbom.Subject]; ok {
		pkgSpec := gql.IDorPkgInput{PackageVersionID: &v}
		_, err := gql.IngestHasSBOMPkg(ctx, gqlClient, pkgSpec, *sbomSpec, includesSpec)
		if err != nil {
			t.Fatalf("Error ingesting sbom when setting up test: %s", err)
		}
	} else if v, ok := i.ArtifactIds[hasSbom.Subject]; ok {
		artifactSpec := gql.IDorArtifactInput{ArtifactID: &v}
		_, err := gql.IngestHasSBOMArtifact(ctx, gqlClient, artifactSpec, *sbomSpec, includesSpec)
		if err != nil {
			t.Fatalf("Error ingesting sbom when setting up test: %s", err)
		}
	} else {
		t.Fatalf("The purl or digest %s has not been ingested", hasSbom.Subject)
	}
}

// Returns the ID of the version node in the package trie
func ingestPackage(ctx context.Context, t *testing.T, gqlClient graphql.Client, purl string) string {
	spec, err := helpers.PurlToPkg(purl)
	if err != nil {
		t.Fatalf("Could not create a package input spec from a purl: %s", err)
	}
	idOrInputSpec := gql.IDorPkgInput{PackageInput: spec}
	res, err := gql.IngestPackage(ctx, gqlClient, idOrInputSpec)
	if err != nil {
		t.Fatalf("Error ingesting package when setting up test: %s", err)
	}
	return res.IngestPackage.PackageVersionID
}

func ingestArtifact(ctx context.Context, t *testing.T, gqlClient graphql.Client, digest string) string {
	spec := gql.ArtifactInputSpec{
		Algorithm: defaultHashAlgorithm,
		Digest:    digest,
	}
	idOrInputSpec := gql.IDorArtifactInput{ArtifactInput: &spec}
	res, err := gql.IngestArtifact(ctx, gqlClient, idOrInputSpec)
	if err != nil {
		t.Fatalf("Error ingesting artifact when setting up test: %s", err)
	}
	return res.GetIngestArtifact()
}

// Returns the ID of the SourceName node in the trie.
func ingestSource(ctx context.Context, t *testing.T, gqlClient graphql.Client, name string) string {
	spec := gql.SourceInputSpec{
		Type:      defaultSourceType,
		Namespace: defaultSourceNamespace,
	}
	idorInputSpec := gql.IDorSourceInput{SourceInput: &spec}
	res, err := gql.IngestSource(ctx, gqlClient, idorInputSpec)
	if err != nil {
		t.Fatalf("Error ingesting source when setting up test: %s", err)
	}
	return res.GetIngestSource().SourceNameID
}

func ingestBuilder(ctx context.Context, t *testing.T, gqlClient graphql.Client, uri string) string {
	spec := gql.BuilderInputSpec{
		Uri: defaultSourceType,
	}
	idorInputSpec := gql.IDorBuilderInput{BuilderInput: &spec}
	res, err := gql.IngestBuilder(ctx, gqlClient, idorInputSpec)
	if err != nil {
		t.Fatalf("Error ingesting builder when setting up test: %s", err)
	}
	return res.GetIngestBuilder()
}

func ingestVulnerability(ctx context.Context, t *testing.T, gqlClient graphql.Client, vuln string) string {
	parts := strings.SplitN(vuln, "/", 2)
	if len(parts) != 2 {
		t.Fatalf("Invalid vulnerability format: %s", vuln)
	}
	vulnType, vulnID := parts[0], parts[1]

	spec := gql.VulnerabilityInputSpec{
		Type:            vulnType,
		VulnerabilityID: vulnID,
	}
	idOrInputSpec := gql.IDorVulnerabilityInput{VulnerabilityInput: &spec}
	res, err := gql.IngestVulnerability(ctx, gqlClient, idOrInputSpec)
	if err != nil {
		t.Fatalf("Error ingesting vulnerability when setting up test: %s", err)
	}
	return res.IngestVulnerability.VulnerabilityNodeID
}

func (i nounIds) ingestCertifyVuln(ctx context.Context, t *testing.T, gqlClient graphql.Client, certifyVuln CertifyVuln) {
	spec := certifyVuln.Metadata
	if spec == nil {
		spec = &gql.ScanMetadataInput{}
	}

	packageId, ok := i.PackageIds[certifyVuln.Package]
	if !ok {
		t.Fatalf("The package %s has not been ingested", certifyVuln.Package)
	}
	pkgSpec := gql.IDorPkgInput{PackageVersionID: &packageId}

	vulnerabilityId, ok := i.VulnerabilityIds[certifyVuln.Vulnerability]
	if !ok {
		t.Fatalf("The vulnerability %s has not been ingested", certifyVuln.Vulnerability)
	}
	vulnSpec := gql.IDorVulnerabilityInput{VulnerabilityNodeID: &vulnerabilityId}

	_, err := gql.IngestCertifyVulnPkg(ctx, gqlClient, pkgSpec, vulnSpec, *spec)
	if err != nil {
		t.Fatalf("Error ingesting CertifyVuln when setting up test: %s", err)
	}
}
