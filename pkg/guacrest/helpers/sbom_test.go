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
	"testing"
	"time"

	clients "github.com/guacsec/guac/internal/testing/graphqlClients"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"

	"github.com/stretchr/testify/assert"
)

type compareSbomTestData struct {
	pkgVersion string
	knownSince time.Time
}

func TestLatestSBOMFromID_Integration(t *testing.T) {
	startTime := time.Now()

	tests := []struct {
		name          string
		pkgType       string
		pkgNamespace  string
		pkgName       string
		compareData   []compareSbomTestData
		knownSince    []time.Time
		expectedIndex int // Index of the expected latest SBOM
	}{
		{
			name:         "Latest version SBOM",
			pkgType:      "test-type",
			pkgNamespace: "",
			pkgName:      "test-package",
			compareData: []compareSbomTestData{
				{
					pkgVersion: "v1.0.0",
					knownSince: startTime,
				},
				{
					pkgVersion: "v1.1.0",
					knownSince: startTime,
				},
				{
					pkgVersion: "v1.2.0",
					knownSince: startTime,
				},
			},
			expectedIndex: 2,
		},
		{
			name:         "Latest SBOM by time (same version)",
			pkgType:      "test-type",
			pkgNamespace: "",
			pkgName:      "test-name-same-versions",
			compareData: []compareSbomTestData{
				{
					pkgVersion: "1.0.0",
					knownSince: startTime,
				},
				{
					pkgVersion: "1.0.0",
					knownSince: startTime.Add(time.Hour),
				},
				{
					pkgVersion: "1.0.0",
					knownSince: startTime.Add(2 * time.Hour),
				},
			},
			expectedIndex: 2,
		},
		{
			name:         "Latest SBOM by time (empty versions)",
			pkgType:      "test-type",
			pkgNamespace: "test-namespace",
			pkgName:      "test-name-empty-version",
			compareData: []compareSbomTestData{
				{
					pkgVersion: "",
					knownSince: startTime,
				},
				{
					pkgVersion: "",
					knownSince: startTime.Add(time.Hour),
				},
				{
					pkgVersion: "",
					knownSince: startTime.Add(2 * time.Hour),
				},
			},
			expectedIndex: 2,
		},
		{
			name:         "Latest SBOM by time (sha256 versions)",
			pkgType:      "test-type",
			pkgNamespace: "test-namespace",
			pkgName:      "test-name-sha256",
			compareData: []compareSbomTestData{
				{
					pkgVersion: "sha256:123",
					knownSince: startTime,
				},
				{
					pkgVersion: "sha256:789",
					knownSince: startTime.Add(2 * time.Hour),
				},
				{
					pkgVersion: "sha256:456",
					knownSince: startTime.Add(time.Hour),
				},
			},
			expectedIndex: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			gqlClient := clients.SetupTest(t)

			sbomIDMap := make(map[string]int)
			var pkgIds []string

			// Ingest packages and SBOMs
			for i, sbomTestData := range tt.compareData {
				pkgInput := model.PkgInputSpec{
					Type:      tt.pkgType,
					Namespace: &tt.pkgNamespace,
					Name:      tt.pkgName,
					Version:   &sbomTestData.pkgVersion,
				}

				pkg, err := model.IngestPackage(ctx, gqlClient, model.IDorPkgInput{PackageInput: &pkgInput})
				assert.NoError(t, err)
				pkgIds = append(pkgIds, pkg.IngestPackage.PackageVersionID)

				sbomInput := model.HasSBOMInputSpec{
					KnownSince: sbomTestData.knownSince,
				}

				sbomResult, err := model.IngestHasSBOMPkg(ctx, gqlClient, model.IDorPkgInput{PackageVersionID: &pkg.IngestPackage.PackageVersionID}, sbomInput, model.HasSBOMIncludesInputSpec{
					Packages:     []string{},
					Artifacts:    []string{},
					Occurrences:  []string{},
					Dependencies: []string{},
				})
				assert.NoError(t, err)

				// Store the ID of the ingested SBOM with its index in the array
				sbomIDMap[sbomResult.IngestHasSBOM] = i
			}

			// Retrieve the latest SBOM
			latestPkg, err := LatestSBOMFromID(ctx, gqlClient, pkgIds)
			assert.NoError(t, err)
			assert.NotNil(t, latestPkg)

			// Check if the retrieved SBOM is the expected one by comparing the index
			actualIndex, exists := sbomIDMap[latestPkg.Id]
			assert.True(t, exists, "The returned SBOM ID does not exist in the map")
			assert.Equal(t, tt.expectedIndex, actualIndex, "The index of the latest SBOM does not match the expected index")

			// Additional checks to ensure the content is correct
			pkgSubject, ok := latestPkg.Subject.(*model.AllHasSBOMTreeSubjectPackage)
			if !ok {
				t.Fatalf("Unexpected subject type: %T", latestPkg.Subject)
			}
			assert.Equal(t, tt.compareData[tt.expectedIndex].pkgVersion, pkgSubject.Namespaces[0].Names[0].Versions[0].Version)
		})
	}
}
