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
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"log"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	clients "github.com/guacsec/guac/internal/testing/graphqlClients"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
)

// TestSearchVulnerabilitiesViaPkg_BasicRetrieval tests the searchVulnerabilitiesViaPkg function
func TestSearchVulnerabilitiesViaPkg_BasicRetrieval(t *testing.T) {
	ctx := context.Background()
	gqlClient := clients.SetupTest(t)

	// Ingest main package
	pkgNS := "github.com/hashicorp/consul"
	pkgVersion := "v1.0.0"
	pkgName := "sdk"
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
		t.Fatalf("unable to ingest package: %v", err)
	}

	// Ingest a vulnerability
	vulnType := "osv"
	vulnID := "osv-2022-0001"
	vulnSpec := model.VulnerabilityInputSpec{
		Type:            vulnType,
		VulnerabilityID: vulnID,
	}

	vulnInput := model.IDorVulnerabilityInput{
		VulnerabilityInput: &vulnSpec,
	}

	_, err = model.IngestVulnerability(ctx, gqlClient, vulnInput)
	if err != nil {
		t.Fatalf("unable to ingest vulnerability: %v", err)
	}

	// Ingest CertifyVuln relationship between the package and the vulnerability
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

	_, err = model.IngestCertifyVulnPkg(ctx, gqlClient, pkgInput, vulnInput, certifyVulnInput)
	if err != nil {
		t.Fatalf("unable to ingest CertifyVuln: %v", err)
	}

	// Prepare the package specification for searchVulnerabilitiesViaPkg
	pkgSpec := model.PkgSpec{
		Type:      &pkgType,
		Namespace: &pkgNS,
		Name:      &pkgName,
		Version:   &pkgVersion,
	}

	// Call searchVulnerabilitiesViaPkg
	vulnerabilities, err := searchVulnerabilitiesViaPkg(ctx, gqlClient, pkgSpec, false, model.AllHasSBOMTree{})
	if err != nil {
		t.Fatalf("searchVulnerabilitiesViaPkg failed: %v", err)
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
			Vulnerability: gen.VulnerabilityDetails{
				Type: &vulnInput.VulnerabilityInput.Type,
				VulnerabilityIDs: []string{
					vulnID,
				},
			},
			Packages: []string{
				"pkg:golang/github.com/hashicorp/consul/sdk@v1.0.0",
			},
		},
	}

	// Compare the results using cmp
	if diff := cmp.Diff(expectedVulnerabilities, vulnerabilities); diff != "" {
		t.Errorf("Vulnerabilities mismatch (-expected +got):\n%s", diff)
	}
}

// Test for basic dependency retrieval
func TestSearchDependencies_BasicRetrieval(t *testing.T) {
	ctx := context.Background()
	gqlClient := clients.SetupTest(t)

	// Ingest main package
	pkgNS := "github.com/hashicorp/consul"
	pkgVersion := "v1.0.0"
	pkgInput := model.IDorPkgInput{
		PackageInput: &model.PkgInputSpec{
			Type:      "golang",
			Namespace: &pkgNS,
			Name:      "sdk",
			Version:   &pkgVersion,
		},
	}

	pkgID, err := model.IngestPackage(ctx, gqlClient, pkgInput)
	if err != nil {
		t.Fatalf("unable to ingest package: %v", err)
	}

	// Ingest dependent package
	depPkgNS := "github.com/hashicorp/consul-dep"
	depPkgVersion := "v1.0.0-dep"
	depPkgInput := model.IDorPkgInput{
		PackageInput: &model.PkgInputSpec{
			Type:      "golang",
			Namespace: &depPkgNS,
			Name:      "dependency",
			Version:   &depPkgVersion,
		},
	}

	_, err = model.IngestPackage(ctx, gqlClient, depPkgInput)
	if err != nil {
		t.Fatalf("unable to ingest dependency package: %v", err)
	}

	depID, err := model.IngestIsDependency(ctx, gqlClient, pkgInput, depPkgInput, model.IsDependencyInputSpec{
		DependencyType: model.DependencyTypeDirect,
	})
	if err != nil {
		t.Fatalf("unable to ingest dependency node: %v", err)
	}

	// Ingest a SBOM that includes the dependency
	hasSBOMInput := model.HasSBOMInputSpec{
		KnownSince: time.Now(),
	}

	_, err = model.IngestHasSBOMPkg(ctx, gqlClient, model.IDorPkgInput{PackageInput: &model.PkgInputSpec{
		Type:      "golang",
		Namespace: &pkgNS,
		Name:      "sdk",
		Version:   &pkgVersion,
	}}, hasSBOMInput, model.HasSBOMIncludesInputSpec{
		Dependencies: []string{depID.IngestDependency},
		Packages:     []string{},
		Artifacts:    []string{},
		Occurrences:  []string{},
	})
	if err != nil {
		log.Fatalf("Failed to ingest HasSBOM: %v", err)
	}

	pkgType := "golang"
	pkgName := "sdk"
	// Prepare the package specification for searchDependencies
	pkgSpec := model.PkgSpec{
		Type:      &pkgType,
		Namespace: &pkgNS,
		Name:      &pkgName,
		Version:   &pkgVersion,
	}

	// Call searchDependencies
	dependencies, err := searchDependencies(ctx, gqlClient, pkgSpec, false, model.AllHasSBOMTree{})
	if err != nil {
		t.Fatalf("searchDependencies failed: %v", err)
	}

	// Define expected dependencies
	expectedDependencies := map[string]string{
		pkgID.IngestPackage.PackageVersionID: "pkg:golang/github.com/hashicorp/consul/sdk@v1.0.0",
	}

	// Compare the results using cmp
	if diff := cmp.Diff(expectedDependencies, dependencies); diff != "" {
		t.Errorf("Dependencies mismatch (-expected +got):\n%s", diff)
	}
}
