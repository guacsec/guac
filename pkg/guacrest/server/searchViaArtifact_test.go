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

//go:build integration

package server

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	clients "github.com/guacsec/guac/internal/testing/graphqlClients"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
)

func TestSearchDependenciesByArtifact_BasicRetrieval(t *testing.T) {
	ctx := context.Background()
	gqlClient := clients.SetupTest(t)

	// Ingest a package
	pkgNS := "github.com/hashicorp/consul"
	pkgName := "sdk"
	pkgVersion := "v1.0.0"
	pkgType := "golang"
	pkgInput := model.IDorPkgInput{
		PackageInput: &model.PkgInputSpec{
			Type:      pkgType,
			Namespace: &pkgNS,
			Name:      pkgName,
			Version:   &pkgVersion,
		},
	}

	_, err := model.IngestPackage(ctx, gqlClient, pkgInput)
	if err != nil {
		t.Fatalf("Failed to ingest package: %v", err)
	}

	// Ingest an artifact
	artifactAlgorithm := "sha256"
	artifactDigest := "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"
	artifactInput := model.IDorArtifactInput{
		ArtifactInput: &model.ArtifactInputSpec{
			Algorithm: artifactAlgorithm,
			Digest:    artifactDigest,
		},
	}

	_, err = model.IngestArtifact(ctx, gqlClient, artifactInput)
	if err != nil {
		t.Fatalf("Failed to ingest artifact: %v", err)
	}

	// Create an IsOccurrence relationship between the package and the artifact
	occurrenceInput := model.IsOccurrenceInputSpec{
		Justification: "test-justification",
		Origin:        "test-origin",
		Collector:     "test-collector",
	}

	_, err = model.IngestIsOccurrencePkg(ctx, gqlClient, pkgInput, artifactInput, occurrenceInput)
	if err != nil {
		t.Fatalf("Failed to ingest IsOccurrence: %v", err)
	}

	// Ingest a dependency package
	depPkgNS := "github.com/hashicorp/consul-dep"
	depPkgName := "dependency"
	depPkgVersion := "v1.0.0-dep"
	depPkgInput := model.IDorPkgInput{
		PackageInput: &model.PkgInputSpec{
			Type:      pkgType,
			Namespace: &depPkgNS,
			Name:      depPkgName,
			Version:   &depPkgVersion,
		},
	}

	_, err = model.IngestPackage(ctx, gqlClient, depPkgInput)
	if err != nil {
		t.Fatalf("Failed to ingest dependency package: %v", err)
	}

	// Create an IsDependency relationship
	depPkgID, err := model.IngestIsDependency(ctx, gqlClient, pkgInput, depPkgInput, model.IsDependencyInputSpec{
		DependencyType: model.DependencyTypeDirect,
	})
	if err != nil {
		t.Fatalf("Failed to ingest IsDependency: %v", err)
	}

	// Ingest a HasSBOM that includes the dependency
	hasSBOMInput := model.HasSBOMInputSpec{
		KnownSince: time.Now(),
		Origin:     "test-origin",
		Collector:  "test-collector",
	}

	_, err = model.IngestHasSBOMArtifact(ctx, gqlClient, model.IDorArtifactInput{
		ArtifactInput: &model.ArtifactInputSpec{
			Algorithm: artifactAlgorithm,
			Digest:    artifactDigest,
		},
	}, hasSBOMInput, model.HasSBOMIncludesInputSpec{
		Dependencies: []string{depPkgID.IngestDependency},
		Packages:     []string{},
		Artifacts:    []string{},
		Occurrences:  []string{},
	})
	if err != nil {
		t.Fatalf("Failed to ingest HasSBOM: %v", err)
	}

	// Prepare the artifact specification for searchDependenciesByArtifact
	artifactSpec := model.ArtifactSpec{
		Algorithm: &artifactAlgorithm,
		Digest:    &artifactDigest,
	}

	// Call searchDependenciesByArtifact
	nodeMap, queue, err := searchDependenciesByArtifact(ctx, gqlClient, artifactSpec, false, model.AllHasSBOMTree{})
	if err != nil {
		t.Fatalf("searchDependenciesByArtifact failed: %v", err)
	}

	// Build expected results
	expectedNodeMap := map[string]dfsNode{
		// Include the pkgID of the dependency package
		// Assuming that the pkgID can be retrieved or is known
		// For simplicity, the keys can be any placeholder strings
		"pkg_dependency_id": {
			depth: 1,
			purl:  "pkg:golang/github.com/hashicorp/consul-dep/dependency@v1.0.0-dep",
		},
	}

	expectedQueue := []string{"pkg_dependency_id"}

	// Since we don't have access to the exact IDs, we'll compare the lengths and structure
	if len(nodeMap) != len(expectedNodeMap) {
		t.Errorf("Expected nodeMap length %d, got %d", len(expectedNodeMap), len(nodeMap))
	}

	if len(queue) != len(expectedQueue) {
		t.Errorf("Expected queue length %d, got %d", len(expectedQueue), len(queue))
	}

	// Further validation can be done by comparing the PURLs in nodeMap
	var actualPURLs []string
	for _, node := range nodeMap {
		actualPURLs = append(actualPURLs, node.purl)
	}

	expectedPURLs := []string{
		"pkg:golang/github.com/hashicorp/consul-dep/dependency@v1.0.0-dep",
	}

	if diff := cmp.Diff(expectedPURLs, actualPURLs); diff != "" {
		t.Errorf("PURL mismatch (-expected +got):\n%s", diff)
	}
}

func TestSearchVulnerabilitiesViaArtifact_BasicRetrieval(t *testing.T) {
	ctx := context.Background()
	gqlClient := clients.SetupTest(t)

	// Ingest main package
	pkgNS := "github.com/hashicorp/consul"
	pkgName := "sdk"
	pkgVersion := "v1.0.0"
	pkgType := "golang"
	pkgInput := model.IDorPkgInput{
		PackageInput: &model.PkgInputSpec{
			Type:      pkgType,
			Namespace: &pkgNS,
			Name:      pkgName,
			Version:   &pkgVersion,
		},
	}

	_, err := model.IngestPackage(ctx, gqlClient, pkgInput)
	if err != nil {
		t.Fatalf("Failed to ingest package: %v", err)
	}

	// Ingest artifact
	artifactAlgorithm := "sha256"
	artifactDigest := "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"
	artifactInput := model.IDorArtifactInput{
		ArtifactInput: &model.ArtifactInputSpec{
			Algorithm: artifactAlgorithm,
			Digest:    artifactDigest,
		},
	}

	_, err = model.IngestArtifact(ctx, gqlClient, artifactInput)
	if err != nil {
		t.Fatalf("Failed to ingest artifact: %v", err)
	}

	// Create IsOccurrence relationship between package and artifact
	isOccurrenceInput := model.IsOccurrenceInputSpec{
		Justification: "test-justification",
		Origin:        "test-origin",
		Collector:     "test-collector",
	}

	_, err = model.IngestIsOccurrencePkg(ctx, gqlClient, pkgInput, artifactInput, isOccurrenceInput)
	if err != nil {
		t.Fatalf("Failed to ingest IsOccurrence: %v", err)
	}

	// Ingest dependency package
	depPkgNS := "github.com/hashicorp/consul-dep"
	depPkgName := "dependency"
	depPkgVersion := "v1.0.0-dep"
	depPkgInput := model.IDorPkgInput{
		PackageInput: &model.PkgInputSpec{
			Type:      pkgType,
			Namespace: &depPkgNS,
			Name:      depPkgName,
			Version:   &depPkgVersion,
		},
	}

	_, err = model.IngestPackage(ctx, gqlClient, depPkgInput)
	if err != nil {
		t.Fatalf("Failed to ingest dependency package: %v", err)
	}

	// Create IsDependency relationship between main package and dependency package
	depID, err := model.IngestIsDependency(ctx, gqlClient, pkgInput, depPkgInput, model.IsDependencyInputSpec{
		DependencyType: model.DependencyTypeDirect,
	})
	if err != nil {
		t.Fatalf("Failed to ingest IsDependency: %v", err)
	}

	// Ingest vulnerability associated with the dependency package
	vulnType := "osv"
	vulnID := "osv-2022-0001"
	vulnInput := model.VulnerabilityInputSpec{
		Type:            vulnType,
		VulnerabilityID: vulnID,
	}

	vulnIDInput := model.IDorVulnerabilityInput{
		VulnerabilityInput: &vulnInput,
	}

	_, err = model.IngestVulnerability(ctx, gqlClient, vulnIDInput)
	if err != nil {
		t.Fatalf("Failed to ingest vulnerability: %v", err)
	}

	// Create CertifyVuln relationship between dependency package and vulnerability
	scanner := "test-scanner"
	dbURI := "https://vuln-db.example.com"
	timeScanned := time.Now()
	certifyVulnInput := model.ScanMetadataInput{
		TimeScanned:    timeScanned,
		DbUri:          dbURI,
		ScannerUri:     scanner,
		ScannerVersion: "1.0.0",
		Collector:      "test-collector",
		Origin:         "test-origin",
	}

	_, err = model.IngestCertifyVulnPkg(ctx, gqlClient, depPkgInput, vulnIDInput, certifyVulnInput)
	if err != nil {
		t.Fatalf("Failed to ingest CertifyVuln: %v", err)
	}

	// Ingest HasSBOM for the artifact including the dependency
	hasSBOMInput := model.HasSBOMInputSpec{
		KnownSince: time.Now(),
		Origin:     "test-origin",
		Collector:  "test-collector",
	}

	hasSBOMIncludesInput := model.HasSBOMIncludesInputSpec{
		Dependencies: []string{depID.IngestDependency},
		Packages:     []string{},
		Artifacts:    []string{},
		Occurrences:  []string{},
	}

	// Ingest HasSBOMArtifact
	_, err = model.IngestHasSBOMArtifact(ctx, gqlClient, artifactInput, hasSBOMInput, hasSBOMIncludesInput)
	if err != nil {
		t.Fatalf("Failed to ingest HasSBOM: %v", err)
	}

	// Prepare artifact specification
	artifactSpec := model.ArtifactSpec{
		Algorithm: &artifactAlgorithm,
		Digest:    &artifactDigest,
	}

	// Call searchVulnerabilitiesViaArtifact
	vulnerabilities, err := searchVulnerabilitiesViaArtifact(ctx, gqlClient, artifactSpec, false, model.AllHasSBOMTree{})
	if err != nil {
		t.Fatalf("searchVulnerabilitiesViaArtifact failed: %v", err)
	}

	// Define expected vulnerabilities
	expectedVulnerabilities := []gen.Vulnerability{
		{
			Metadata: gen.ScanMetadata{
				Collector:      &certifyVulnInput.Collector,
				DbUri:          &certifyVulnInput.DbUri,
				DbVersion:      &certifyVulnInput.DbVersion,
				Origin:         &certifyVulnInput.Origin,
				ScannerUri:     &certifyVulnInput.ScannerUri,
				ScannerVersion: &certifyVulnInput.ScannerVersion,
				TimeScanned:    &certifyVulnInput.TimeScanned,
			},
			Packages: []string{
				"pkg:golang/github.com/hashicorp/consul-dep/dependency@v1.0.0-dep",
			},
			Vulnerability: gen.VulnerabilityDetails{
				Type: &vulnType,
				VulnerabilityIDs: []string{
					vulnID,
				},
			},
		},
	}

	// Compare the results using cmp
	if diff := cmp.Diff(expectedVulnerabilities, vulnerabilities); diff != "" {
		t.Errorf("Vulnerabilities mismatch (-expected +got):\n%s", diff)
	}
}
