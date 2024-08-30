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

package helpers

import (
	"context"
	"log"
	"sort"
	"testing"
	"time"

	clients "github.com/guacsec/guac/internal/testing/graphqlClients"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"

	"github.com/google/go-cmp/cmp"
)

func TestGetInfoForPackage_Integration(t *testing.T) {
	ctx := context.Background()
	gqlClient := clients.SetupTest(t)

	ns := "test-namespace-1"
	version := "v1.0.0"

	// Prepare the package input specification
	pkgInput := model.IDorPkgInput{
		PackageInput: &model.PkgInputSpec{
			Type:      "golang",
			Namespace: &ns,
			Name:      "test-name-1",
			Version:   &version,
		},
	}

	// Ingest the package with our exact input specification
	_, err := model.IngestPackage(ctx, gqlClient, pkgInput)
	if err != nil {
		log.Fatalf("Failed to ingest package: %v", err)
	}

	ns2 := "test-namespace-2"
	version2 := "v2.0.0"

	// Prepare the package input specification
	pkgInput2 := model.IDorPkgInput{
		PackageInput: &model.PkgInputSpec{
			Type:      "golang",
			Namespace: &ns2,
			Name:      "test-name-2",
			Version:   &version2,
		},
	}

	// Ingest the package with our exact input specification
	pkg2, err := model.IngestPackage(ctx, gqlClient, pkgInput2)
	if err != nil {
		log.Fatalf("Failed to ingest package: %v", err)
	}

	depId, err := model.IngestIsDependency(ctx, gqlClient, pkgInput2, pkgInput, model.IsDependencyInputSpec{
		DependencyType: model.DependencyTypeDirect,
	})
	if err != nil {
		log.Fatalf("Failed to ingest dependency: %v", err)
	}

	hasSBOMInput := model.HasSBOMInputSpec{
		KnownSince: time.Now(),
	}

	x := model.HasSBOMIncludesInputSpec{
		Packages:     []string{pkg2.IngestPackage.PackageVersionID},
		Artifacts:    []string{},
		Dependencies: []string{depId.IngestDependency},
		Occurrences:  []string{},
	}

	_, err = model.IngestHasSBOMPkg(ctx, gqlClient, pkgInput, hasSBOMInput, x)
	if err != nil {
		log.Fatalf("Failed to ingest HasSBOM: %v", err)
	}

	hasSBOMInput2 := model.HasSBOMInputSpec{
		KnownSince: time.Now(),
	}

	x2 := model.HasSBOMIncludesInputSpec{
		Packages:     []string{},
		Artifacts:    []string{},
		Dependencies: []string{},
		Occurrences:  []string{},
	}

	_, err = model.IngestHasSBOMPkg(ctx, gqlClient, pkgInput2, hasSBOMInput2, x2)
	if err != nil {
		log.Fatalf("Failed to ingest HasSBOM: %v", err)
	}

	// Prepare the vulnerability input specification
	vulnInput := model.IDorVulnerabilityInput{
		VulnerabilityInput: &model.VulnerabilityInputSpec{
			Type:            "CVE",
			VulnerabilityID: "CVE-2023-1234",
		},
	}

	// Ingest the vulnerability
	_, err = model.IngestVulnerability(ctx, gqlClient, vulnInput)
	if err != nil {
		log.Fatalf("Failed to ingest vulnerability: %v", err)
	}

	// Prepare the scan metadata input specification
	scanMetadataInput := model.ScanMetadataInput{
		TimeScanned:    time.Now(),
		DbUri:          "http://example.com/db",
		DbVersion:      "2023.01.01",
		ScannerUri:     "http://example.com/scanner",
		ScannerVersion: "v1.0.0",
		Origin:         "example-origin",
		Collector:      "example-collector",
		DocumentRef:    "example-document-ref",
	}

	// Link the vulnerability to the package with certification
	_, err = model.IngestCertifyVulnPkg(ctx, gqlClient, pkgInput2, vulnInput, scanMetadataInput)
	if err != nil {
		log.Fatalf("Failed to link vulnerability to package: %v", err)
	}

	resp, err := GetInfoForPackage(ctx, gqlClient, pkgInput.PackageInput, QueryType{
		Vulns:        true,
		Dependencies: true,
	})
	if err != nil {
		t.Fatalf("Failed to get info for package: %v", err)
	}

	if diff := cmp.Diff("cve-2023-1234", (*resp.Vulnerabilities)[0].Vulnerability.VulnerabilityIDs[0]); diff != "" {
		t.Errorf("Vulnerability ID mismatch (-want +got):\n%s", diff)
	}

	sort.Slice(*resp.Dependencies, func(i, j int) bool {
		return (*resp.Dependencies)[i] < (*resp.Dependencies)[j]
	})

	if diff := cmp.Diff("pkg:golang/test-namespace-1/test-name-1@v1.0.0", (*resp.Dependencies)[0]); diff != "" {
		t.Errorf("Dependency mismatch (-want +got):\n%s", diff)
	}
}
