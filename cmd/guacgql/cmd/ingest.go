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

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
)

func ingestData(port int) {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	// ensure server is up
	time.Sleep(1 * time.Second)

	// Create a http client to send the mutation through
	url := fmt.Sprintf("http://localhost:%d/query", port)
	httpClient := http.Client{}
	gqlclient := graphql.NewClient(url, &httpClient)

	start := time.Now()

	logger.Infof("Ingesting test data into backend server")
	ingestScorecards(ctx, gqlclient)
	ingestSLSA(ctx, gqlclient)
	ingestDependency(ctx, gqlclient)
	ingestOccurrence(ctx, gqlclient)
	ingestVulnerability(ctx, gqlclient)
	bulkIngestVulnerabilities(ctx, gqlclient)
	ingestVulnerabilityMetadata(ctx, gqlclient)
	bulkIngestVulnerabilityMetadata(ctx, gqlclient)
	ingestPkgEqual(ctx, gqlclient)
	ingestCertifyBad(ctx, gqlclient)
	bulkIngestCertifyBad(ctx, gqlclient)
	ingestCertifyGood(ctx, gqlclient)
	bulkIngestCertifyGood(ctx, gqlclient)
	ingestHashEqual(ctx, gqlclient)
	ingestHasSBOM(ctx, gqlclient)
	ingestHasSourceAt(ctx, gqlclient)
	ingestIsVulnerability(ctx, gqlclient)
	ingestVEXStatement(ctx, gqlclient)
	bulkIngestVEXStatement(ctx, gqlclient)
	ingestReachabilityTestData(ctx, gqlclient)
	time := time.Since(start)
	logger.Infof("Ingesting test data into backend server took %v", time)
}

func ingestScorecards(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	source := model.SourceInputSpec{
		Type:      "git",
		Namespace: "github",
		Name:      "github.com/tensorflow/tensorflow",
		Tag:       ptrfrom.String("v2.12.0"),
	}
	checks := []model.ScorecardCheckInputSpec{
		{Check: "Binary_Artifacts", Score: 4},
		{Check: "Branch_Protection", Score: 3},
		{Check: "Code_Review", Score: 2},
		{Check: "Contributors", Score: 1},
	}
	scorecard := model.ScorecardInputSpec{
		Checks:           checks,
		AggregateScore:   2.9,
		TimeScanned:      time.Now(),
		ScorecardVersion: "v4.10.2",
		ScorecardCommit:  "5e6a521",
		Origin:           "Demo ingestion",
		Collector:        "Demo ingestion",
	}
	if _, err := model.IngestSource(ctx, client, source); err != nil {
		logger.Errorf("Error in ingesting source: %v\n", err)
	}
	if _, err := model.CertifyScorecard(ctx, client, source, scorecard); err != nil {
		logger.Errorf("Error in ingesting: %v\n", err)
	}
}

func ingestSLSA(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	startTime := time.Now()
	finishTime := time.Now().Add(10 * time.Second)
	predicate := []model.SLSAPredicateInputSpec{
		{
			Key:   "buildDefinition.externalParameters.repository",
			Value: "https://github.com/octocat/hello-world",
		},
		{
			Key:   "buildDefinition.externalParameters.ref",
			Value: "refs/heads/main",
		},
		{
			Key:   "buildDefinition.resolvedDependencies.uri",
			Value: "git+https://github.com/octocat/hello-world@refs/heads/main",
		},
	}
	ingestDependencies := []struct {
		buildType string
		artifact  model.ArtifactInputSpec
		materials []model.ArtifactInputSpec
		builder   model.BuilderInputSpec
	}{
		{
			buildType: "Test:SLSA",
			artifact: model.ArtifactInputSpec{
				Digest:    "5a787865sd676dacb0142afa0b83029cd7befd9",
				Algorithm: "sha1",
			},
			materials: []model.ArtifactInputSpec{
				{
					Digest:    "0123456789abcdef0000000fedcba9876543210",
					Algorithm: "sha1",
				},
			},
			builder: model.BuilderInputSpec{
				Uri: "https://github.com/BuildPythonWheel/HubHostedActions@v1",
			},
		},
		{
			buildType: "Test:SLSA2",
			artifact: model.ArtifactInputSpec{
				Digest:    "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7",
				Algorithm: "sha512",
			},
			materials: []model.ArtifactInputSpec{
				{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
				{
					Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
					Algorithm: "sha1",
				},
			},
			builder: model.BuilderInputSpec{
				Uri: "https://github.com/CreateFork/HubHostedActions@v1",
			},
		},
	}
	for _, ingest := range ingestDependencies {
		slsa := model.SLSAInputSpec{
			BuildType:     ingest.buildType,
			SlsaPredicate: predicate,
			SlsaVersion:   "v1",
			StartedOn:     &startTime,
			FinishedOn:    &finishTime,
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		}
		if _, err := model.IngestArtifact(ctx, client, ingest.artifact); err != nil {
			logger.Errorf("Error in ingesting artifact: %v\n", err)
		}
		if _, err := model.IngestArtifacts(ctx, client, ingest.materials); err != nil {
			logger.Errorf("Error in ingesting materials: %v\n", err)
		}
		if _, err := model.IngestBuilder(ctx, client, ingest.builder); err != nil {
			logger.Errorf("Error in ingesting builder: %v\n", err)
		}
		if _, err := model.SLSAForArtifact(ctx, client, ingest.artifact,
			ingest.materials, ingest.builder, slsa); err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
	}
}

func ingestDependency(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	ns := "ubuntu"
	version := "1.19.0.4"
	depns := "openssl.org"
	opensslVersion := "3.0.3"
	smartentryNs := "smartentry"
	ingestDependencies := []struct {
		name             string
		pkg              model.PkgInputSpec
		depPkg           model.PkgInputSpec
		depPkgMatchFlags model.MatchFlags
		dependency       model.IsDependencyInputSpec
	}{
		{
			name: "deb: part of SBOM - openssl",
			pkg: model.PkgInputSpec{
				Type:      "deb",
				Namespace: &ns,
				Name:      "dpkg",
				Version:   &version,
				Qualifiers: []model.PackageQualifierInputSpec{
					{Key: "arch", Value: "amd64"},
				},
			},
			depPkg: model.PkgInputSpec{
				Type:      "conan",
				Namespace: &depns,
				Name:      "openssl",
			},
			depPkgMatchFlags: model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions},
			dependency: model.IsDependencyInputSpec{
				VersionRange:   "3.0.3",
				DependencyType: model.DependencyTypeDirect,
				Justification:  "deb: part of SBOM - openssl",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
		{
			name: "docker: part of SBOM - openssl",
			pkg: model.PkgInputSpec{
				Type:      "docker",
				Namespace: &smartentryNs,
				Name:      "debian",
			},
			depPkg: model.PkgInputSpec{
				Type:      "conan",
				Namespace: &depns,
				Name:      "openssl",
				Version:   &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{
					{Key: "user", Value: "bincrafters"},
					{Key: "channel", Value: "stable"},
				},
			},
			depPkgMatchFlags: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
			dependency: model.IsDependencyInputSpec{
				VersionRange:   "3.0.3",
				DependencyType: model.DependencyTypeIndirect,
				Justification:  "docker: part of SBOM - openssl",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
		{
			name: "deb: part of SBOM - openssl (indirect)",
			pkg: model.PkgInputSpec{
				Type:      "deb",
				Namespace: &ns,
				Name:      "dpkg",
				Version:   &version,
				Qualifiers: []model.PackageQualifierInputSpec{
					{Key: "arch", Value: "amd64"},
				},
			},
			depPkg: model.PkgInputSpec{
				Type:      "conan",
				Namespace: &depns,
				Name:      "openssl",
				Version:   &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{
					{Key: "user", Value: "bincrafters"},
					{Key: "channel", Value: "stable"},
				},
			},
			depPkgMatchFlags: model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion},
			dependency: model.IsDependencyInputSpec{
				VersionRange:   "3.0.3",
				DependencyType: model.DependencyTypeDirect,
				Justification:  "deb: part of SBOM - openssl",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
	}
	for _, ingest := range ingestDependencies {
		if _, err := model.IngestPackage(ctx, client, ingest.pkg); err != nil {
			logger.Errorf("Error in ingesting package: %v\n", err)
		}
		if _, err := model.IngestPackage(ctx, client, ingest.depPkg); err != nil {
			logger.Errorf("Error in ingesting dependency package: %v\n", err)
		}
		if _, err := model.IsDependency(ctx, client, ingest.pkg, ingest.depPkg, ingest.depPkgMatchFlags, ingest.dependency); err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
	}
}

func ingestOccurrence(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	opensslNs := "openssl.org"
	opensslVersion := "3.0.3"
	smartentryNs := "smartentry"
	sourceTag := "v0.0.1"
	ingestOccurrences := []struct {
		name       string
		pkg        *model.PkgInputSpec
		src        *model.SourceInputSpec
		art        model.ArtifactInputSpec
		occurrence model.IsOccurrenceInputSpec
	}{
		{
			name: "this artifact is an occurrence of this openssl",
			pkg: &model.PkgInputSpec{
				Type:      "conan",
				Namespace: &opensslNs,
				Name:      "openssl",
				Version:   &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{
					{Key: "user", Value: "bincrafters"},
					{Key: "channel", Value: "stable"},
				},
			},
			src: nil,
			art: model.ArtifactInputSpec{
				Digest:    "5a787865sd676dacb0142afa0b83029cd7befd9",
				Algorithm: "sha1",
			},
			occurrence: model.IsOccurrenceInputSpec{
				Justification: "this artifact is an occurrence of this openssl",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "this artifact is an occurrence of this debian",
			pkg: &model.PkgInputSpec{
				Type:      "docker",
				Namespace: &smartentryNs,
				Name:      "debian",
			},
			src: nil,
			art: model.ArtifactInputSpec{
				Digest:    "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7",
				Algorithm: "sha512",
			},
			occurrence: model.IsOccurrenceInputSpec{
				Justification: "this artifact is an occurrence of this debian",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "this artifact is an occurrence of this source",
			pkg:  nil,
			src: &model.SourceInputSpec{
				Type:      "git",
				Namespace: "github",
				Name:      "github.com/guacsec/guac",
				Tag:       &sourceTag,
			},
			art: model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			occurrence: model.IsOccurrenceInputSpec{
				Justification: "this artifact is an occurrence of this source",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
	}
	for _, ingest := range ingestOccurrences {
		if _, err := model.IngestArtifact(ctx, client, ingest.art); err != nil {
			logger.Errorf("Error in ingesting artifact: %v\n", err)
		}
		if ingest.pkg != nil {
			if _, err := model.IngestPackage(ctx, client, *ingest.pkg); err != nil {
				logger.Errorf("Error in ingesting package: %v\n", err)
			}
			if _, err := model.IsOccurrencePkg(ctx, client, *ingest.pkg, ingest.art, ingest.occurrence); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.src != nil {
			if _, err := model.IngestSource(ctx, client, *ingest.src); err != nil {
				logger.Errorf("Error in ingesting source: %v\n", err)
			}
			if _, err := model.IsOccurrenceSrc(ctx, client, *ingest.src, ingest.art, ingest.occurrence); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else {
			fmt.Printf("input missing for pkg or src")
		}
	}
}

func ingestVulnerabilityMetadata(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	ingestVulnerabilityMetadata := []struct {
		name         string
		vuln         *model.VulnerabilityInputSpec
		vulnMetadata model.VulnerabilityMetadataInputSpec
	}{
		{
			name: "cve openssl",
			vuln: &model.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			},
			vulnMetadata: model.VulnerabilityMetadataInputSpec{
				Timestamp:  tm,
				ScoreType:  model.VulnerabilityScoreTypeCvssv2,
				ScoreValue: 5.6,
				Origin:     "Demo ingestion",
				Collector:  "Demo ingestion",
			},
		},
		{
			name: "osv openssl",
			vuln: &model.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "CVE-2019-13110",
			},
			vulnMetadata: model.VulnerabilityMetadataInputSpec{
				Timestamp:  tm,
				ScoreType:  model.VulnerabilityScoreTypeCvssv3,
				ScoreValue: 6.6,
				Origin:     "Demo ingestion",
				Collector:  "Demo ingestion",
			},
		},
		{
			name: "ghsa openssl",
			vuln: &model.VulnerabilityInputSpec{
				Type:            "ghsa",
				VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
			},
			vulnMetadata: model.VulnerabilityMetadataInputSpec{
				Timestamp:  tm,
				ScoreType:  model.VulnerabilityScoreTypeEpssv1,
				ScoreValue: 0.968,
				Origin:     "Demo ingestion",
				Collector:  "Demo ingestion",
			},
		},
		{
			name: "cve django",
			vuln: &model.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "CVE-2018-12310",
			},
			vulnMetadata: model.VulnerabilityMetadataInputSpec{
				Timestamp:  tm,
				ScoreType:  model.VulnerabilityScoreTypeEpssv2,
				ScoreValue: 0.768,
				Origin:     "Demo ingestion",
				Collector:  "Demo ingestion",
			},
		},
		{
			name: "cve (duplicate)",
			vuln: &model.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			},
			vulnMetadata: model.VulnerabilityMetadataInputSpec{
				Timestamp:  tm,
				ScoreType:  model.VulnerabilityScoreTypeCvssv2,
				ScoreValue: 5.6,
				Origin:     "Demo ingestion",
				Collector:  "Demo ingestion",
			},
		},
		{
			name: "ghsa (duplicate)",
			vuln: &model.VulnerabilityInputSpec{
				Type:            "ghsa",
				VulnerabilityID: "GHSA-f45f-jj4w-2rv2",
			},
			vulnMetadata: model.VulnerabilityMetadataInputSpec{
				Timestamp:  tm,
				ScoreType:  model.VulnerabilityScoreTypeEpssv1,
				ScoreValue: 0.968,
				Origin:     "Demo ingestion",
				Collector:  "Demo ingestion",
			},
		},
		{
			name: "osv (duplicate)",
			vuln: &model.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "CVE-2019-13110",
			},
			vulnMetadata: model.VulnerabilityMetadataInputSpec{
				Timestamp:  tm,
				ScoreType:  model.VulnerabilityScoreTypeCvssv3,
				ScoreValue: 6.6,
				Origin:     "Demo ingestion",
				Collector:  "Demo ingestion",
			},
		},
	}
	for _, ingest := range ingestVulnerabilityMetadata {
		if _, err := model.IngestVulnerability(ctx, client, *ingest.vuln); err != nil {
			logger.Errorf("Error in ingesting vulnerability: %v\n", err)
		}
		if _, err := model.VulnHasMetadata(ctx, client, *ingest.vuln, ingest.vulnMetadata); err != nil {
			logger.Errorf("Error in ingesting VulnHasMetadata: %v\n", err)
		}
	}
}

func bulkIngestVulnerabilityMetadata(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	ingestVulnerabilityMetadatas := []struct {
		name                      string
		vulns                     []model.VulnerabilityInputSpec
		vulnerabilityMetadataList []model.VulnerabilityMetadataInputSpec
	}{
		{
			name: "bulk ingest",
			vulns: []model.VulnerabilityInputSpec{
				{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				{
					Type:            "osv",
					VulnerabilityID: "CVE-2019-13110",
				},
				{
					Type:            "ghsa",
					VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
				},
				{
					Type:            "cve",
					VulnerabilityID: "CVE-2018-12310",
				},
				{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				{
					Type:            "osv",
					VulnerabilityID: "CVE-2019-13110",
				},
				{
					Type:            "ghsa",
					VulnerabilityID: "GHSA-f45f-jj4w-2rv2",
				},
			},
			vulnerabilityMetadataList: []model.VulnerabilityMetadataInputSpec{
				{
					Timestamp:  tm,
					ScoreType:  model.VulnerabilityScoreTypeCvssv2,
					ScoreValue: 5.6,
					Origin:     "Demo ingestion",
					Collector:  "Demo ingestion",
				},
				{
					Timestamp:  tm,
					ScoreType:  model.VulnerabilityScoreTypeCvssv3,
					ScoreValue: 6.6,
					Origin:     "Demo ingestion",
					Collector:  "Demo ingestion",
				},
				{
					Timestamp:  tm,
					ScoreType:  model.VulnerabilityScoreTypeEpssv1,
					ScoreValue: 0.968,
					Origin:     "Demo ingestion",
					Collector:  "Demo ingestion",
				},
				{
					Timestamp:  tm,
					ScoreType:  model.VulnerabilityScoreTypeEpssv2,
					ScoreValue: 0.768,
					Origin:     "Demo ingestion",
					Collector:  "Demo ingestion",
				},
				{
					Timestamp:  tm,
					ScoreType:  model.VulnerabilityScoreTypeCvssv2,
					ScoreValue: 5.6,
					Origin:     "Demo ingestion",
					Collector:  "Demo ingestion",
				},
				{
					Timestamp:  tm,
					ScoreType:  model.VulnerabilityScoreTypeCvssv3,
					ScoreValue: 6.6,
					Origin:     "Demo ingestion",
					Collector:  "Demo ingestion",
				},
				{
					Timestamp:  tm,
					ScoreType:  model.VulnerabilityScoreTypeEpssv1,
					ScoreValue: 0.968,
					Origin:     "Demo ingestion",
					Collector:  "Demo ingestion",
				},
			},
		},
	}
	for _, ingest := range ingestVulnerabilityMetadatas {
		if _, err := model.IngestVulnerabilities(ctx, client, ingest.vulns); err != nil {
			logger.Errorf("Error in ingesting vulnerabilities: %v\n", err)
		}
		if _, err := model.VulnHasMetadatas(ctx, client, ingest.vulns, ingest.vulnerabilityMetadataList); err != nil {
			logger.Errorf("Error in ingesting VulnHasMetadatas: %v\n", err)
		}
	}
}

func ingestVulnerability(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	opensslNs := "openssl.org"
	opensslVersion := "3.0.3"
	djangoNs := ""
	ingestVulnerabilities := []struct {
		name          string
		pkg           *model.PkgInputSpec
		vuln          *model.VulnerabilityInputSpec
		vulnerability model.ScanMetadataInput
	}{
		{
			name: "cve openssl",
			pkg: &model.PkgInputSpec{
				Type:      "conan",
				Namespace: &opensslNs,
				Name:      "openssl",
				Version:   &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{
					{Key: "user", Value: "bincrafters"},
					{Key: "channel", Value: "stable"},
				},
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			},
			vulnerability: model.ScanMetadataInput{
				TimeScanned:    tm,
				DbUri:          "MITRE",
				DbVersion:      "v1.0.0",
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
		{
			name: "osv openssl",
			pkg: &model.PkgInputSpec{
				Type:      "conan",
				Namespace: &opensslNs,
				Name:      "openssl",
				Version:   &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{
					{Key: "user", Value: "bincrafters"},
					{Key: "channel", Value: "stable"},
				},
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "CVE-2019-13110",
			},
			vulnerability: model.ScanMetadataInput{
				TimeScanned:    tm,
				DbUri:          "MITRE",
				DbVersion:      "v1.0.0",
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
		{
			name: "ghsa openssl",
			pkg: &model.PkgInputSpec{
				Type:      "conan",
				Namespace: &opensslNs,
				Name:      "openssl",
				Version:   &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{
					{Key: "user", Value: "bincrafters"},
					{Key: "channel", Value: "stable"},
				},
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "ghsa",
				VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
			},
			vulnerability: model.ScanMetadataInput{
				TimeScanned:    tm,
				DbUri:          "MITRE",
				DbVersion:      "v1.0.0",
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
		{
			name: "cve django",
			pkg: &model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNs,
				Name:      "django",
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "CVE-2018-12310",
			},
			vulnerability: model.ScanMetadataInput{
				TimeScanned:    tm,
				DbUri:          "MITRE",
				DbVersion:      "v1.2.0",
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
		{
			name: "osv django",
			pkg: &model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNs,
				Name:      "django",
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "CVE-2018-12310",
			},
			vulnerability: model.ScanMetadataInput{
				TimeScanned:    tm,
				DbUri:          "MITRE",
				DbVersion:      "v1.2.0",
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
		{
			name: "ghsa django",
			pkg: &model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNs,
				Name:      "django",
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "ghsa",
				VulnerabilityID: "GHSA-f45f-jj4w-2rv2",
			},
			vulnerability: model.ScanMetadataInput{
				TimeScanned:    tm,
				DbUri:          "MITRE",
				DbVersion:      "v1.2.0",
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
		{
			name: "noVuln",
			pkg: &model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNs,
				Name:      "django",
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "noVuln",
				VulnerabilityID: "",
			},
			vulnerability: model.ScanMetadataInput{
				TimeScanned:    tm,
				DbUri:          "MITRE",
				DbVersion:      "v1.2.0",
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
		{
			name: "cve openssl (duplicate)",
			pkg: &model.PkgInputSpec{
				Type:      "conan",
				Namespace: &opensslNs,
				Name:      "openssl",
				Version:   &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{
					{Key: "user", Value: "bincrafters"},
					{Key: "channel", Value: "stable"},
				},
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			},
			vulnerability: model.ScanMetadataInput{
				TimeScanned:    tm,
				DbUri:          "MITRE",
				DbVersion:      "v1.0.0",
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
		{
			name: "ghsa django (duplicate)",
			pkg: &model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNs,
				Name:      "django",
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "ghsa",
				VulnerabilityID: "GHSA-f45f-jj4w-2rv2",
			},
			vulnerability: model.ScanMetadataInput{
				TimeScanned:    tm,
				DbUri:          "MITRE",
				DbVersion:      "v1.2.0",
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
		{
			name: "osv openssl (duplicate)",
			pkg: &model.PkgInputSpec{
				Type:      "conan",
				Namespace: &opensslNs,
				Name:      "openssl",
				Version:   &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{
					{Key: "user", Value: "bincrafters"},
					{Key: "channel", Value: "stable"},
				},
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "CVE-2019-13110",
			},
			vulnerability: model.ScanMetadataInput{
				TimeScanned:    tm,
				DbUri:          "MITRE",
				DbVersion:      "v1.0.0",
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
		{
			name: "noVuln (duplicate)",
			pkg: &model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNs,
				Name:      "django",
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "noVuln",
				VulnerabilityID: "",
			},
			vulnerability: model.ScanMetadataInput{
				TimeScanned:    tm,
				DbUri:          "MITRE",
				DbVersion:      "v1.2.0",
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
	}
	for _, ingest := range ingestVulnerabilities {
		if _, err := model.IngestPackage(ctx, client, *ingest.pkg); err != nil {
			logger.Errorf("Error in ingesting package: %v\n", err)
		}
		if _, err := model.IngestVulnerability(ctx, client, *ingest.vuln); err != nil {
			logger.Errorf("Error in ingesting vulnerability: %v\n", err)
		}
		if _, err := model.CertifyVulnPkg(ctx, client, *ingest.pkg, *ingest.vuln, ingest.vulnerability); err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}

	}
}

func bulkIngestVulnerabilities(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	opensslNs := "openssl.org"
	opensslVersion := "3.0.3"
	djangoNs := ""
	ingestVulnerabilities := []struct {
		name              string
		pkgs              []model.PkgInputSpec
		vulns             []model.VulnerabilityInputSpec
		vulnerabilityList []model.ScanMetadataInput
	}{
		{
			name: "bulk ingest",
			pkgs: []model.PkgInputSpec{
				{
					Type:      "conan",
					Namespace: &opensslNs,
					Name:      "openssl",
					Version:   &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{
						{Key: "user", Value: "bincrafters"},
						{Key: "channel", Value: "stable"},
					},
				},
				{
					Type:      "conan",
					Namespace: &opensslNs,
					Name:      "openssl",
					Version:   &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{
						{Key: "user", Value: "bincrafters"},
						{Key: "channel", Value: "stable"},
					},
				},
				{
					Type:      "conan",
					Namespace: &opensslNs,
					Name:      "openssl",
					Version:   &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{
						{Key: "user", Value: "bincrafters"},
						{Key: "channel", Value: "stable"},
					},
				},
				{
					Type:      "pypi",
					Namespace: &djangoNs,
					Name:      "django",
				},
				{
					Type:      "pypi",
					Namespace: &djangoNs,
					Name:      "django",
				},
				{
					Type:      "pypi",
					Namespace: &djangoNs,
					Name:      "django",
				},
				{
					Type:      "pypi",
					Namespace: &djangoNs,
					Name:      "django",
				},
				{
					Type:      "conan",
					Namespace: &opensslNs,
					Name:      "openssl",
					Version:   &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{
						{Key: "user", Value: "bincrafters"},
						{Key: "channel", Value: "stable"},
					},
				},
				{
					Type:      "pypi",
					Namespace: &djangoNs,
					Name:      "django",
				},
				{
					Type:      "conan",
					Namespace: &opensslNs,
					Name:      "openssl",
					Version:   &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{
						{Key: "user", Value: "bincrafters"},
						{Key: "channel", Value: "stable"},
					},
				},
				{
					Type:      "pypi",
					Namespace: &djangoNs,
					Name:      "django",
				},
			},
			vulns: []model.VulnerabilityInputSpec{
				{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				{
					Type:            "osv",
					VulnerabilityID: "CVE-2019-13110",
				},
				{
					Type:            "ghsa",
					VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
				},
				{
					Type:            "cve",
					VulnerabilityID: "CVE-2018-12310",
				},
				{
					Type:            "osv",
					VulnerabilityID: "CVE-2018-12310",
				},
				{
					Type:            "ghsa",
					VulnerabilityID: "GHSA-f45f-jj4w-2rv2",
				},
				{
					Type:            "noVuln",
					VulnerabilityID: "",
				},
				{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				{
					Type:            "ghsa",
					VulnerabilityID: "GHSA-f45f-jj4w-2rv2",
				},
				{
					Type:            "osv",
					VulnerabilityID: "CVE-2019-13110",
				},
				{
					Type:            "noVuln",
					VulnerabilityID: "",
				},
			},
			vulnerabilityList: []model.ScanMetadataInput{
				{
					TimeScanned:    tm,
					DbUri:          "MITRE",
					DbVersion:      "v1.0.0",
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
				{
					TimeScanned:    tm,
					DbUri:          "MITRE",
					DbVersion:      "v1.0.0",
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
				{
					TimeScanned:    tm,
					DbUri:          "MITRE",
					DbVersion:      "v1.0.0",
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
				{
					TimeScanned:    tm,
					DbUri:          "MITRE",
					DbVersion:      "v1.0.0",
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
				{
					TimeScanned:    tm,
					DbUri:          "MITRE",
					DbVersion:      "v1.0.0",
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
				{
					TimeScanned:    tm,
					DbUri:          "MITRE",
					DbVersion:      "v1.0.0",
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
				{
					TimeScanned:    tm,
					DbUri:          "MITRE",
					DbVersion:      "v1.0.0",
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
				{
					TimeScanned:    tm,
					DbUri:          "MITRE",
					DbVersion:      "v1.0.0",
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
				{
					TimeScanned:    tm,
					DbUri:          "MITRE",
					DbVersion:      "v1.0.0",
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
				{
					TimeScanned:    tm,
					DbUri:          "MITRE",
					DbVersion:      "v1.0.0",
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
				{
					TimeScanned:    tm,
					DbUri:          "MITRE",
					DbVersion:      "v1.0.0",
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
		},
	}
	for _, ingest := range ingestVulnerabilities {
		if _, err := model.IngestPackages(ctx, client, ingest.pkgs); err != nil {
			logger.Errorf("Error in ingesting packages: %v\n", err)
		}
		if _, err := model.IngestVulnerabilities(ctx, client, ingest.vulns); err != nil {
			logger.Errorf("Error in ingesting vulnerabilities: %v\n", err)
		}
		if _, err := model.CertifyVulnPkgs(ctx, client, ingest.pkgs, ingest.vulns, ingest.vulnerabilityList); err != nil {
			logger.Errorf("Error in ingesting CertifyVulnPkgs: %v\n", err)
		}

	}
}

func ingestPkgEqual(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	opensslNs := "openssl.org"
	opensslVersion := "3.0.3"
	djangoNameSpace := ""
	djangoVersion := "1.11.1"
	djangoSubPath := "subpath"
	debianNs := "debian"
	ubuntuNs := "ubuntu"
	attrVersion := "1:2.4.47-2"
	ingestPkgEqual := []struct {
		name     string
		pkg      model.PkgInputSpec
		depPkg   model.PkgInputSpec
		pkgEqual model.PkgEqualInputSpec
	}{
		{
			name: "these two openssl packages are the same",
			pkg: model.PkgInputSpec{
				Type:       "conan",
				Namespace:  &opensslNs,
				Name:       "openssl",
				Version:    &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
			},
			depPkg: model.PkgInputSpec{
				Type:      "conan",
				Namespace: &opensslNs,
				Name:      "openssl",
				Version:   &opensslVersion,
			},
			pkgEqual: model.PkgEqualInputSpec{
				Justification: "these two openssl packages are the same",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "these two pypi packages are the same",
			pkg: model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNameSpace,
				Name:      "django",
			},
			depPkg: model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNameSpace,
				Name:      "django",
				Version:   &djangoVersion,
				Subpath:   &djangoSubPath,
			},
			pkgEqual: model.PkgEqualInputSpec{
				Justification: "these two pypi packages are the same",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "these two debian packages are the same",
			pkg: model.PkgInputSpec{
				Type:      "deb",
				Namespace: &debianNs,
				Name:      "attr",
				Version:   &attrVersion,
			},
			depPkg: model.PkgInputSpec{
				Type:      "deb",
				Namespace: &debianNs,
				Name:      "attr",
			},
			pkgEqual: model.PkgEqualInputSpec{
				Justification: "these two debian packages are the same",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "these two dpkg packages are the same",
			pkg: model.PkgInputSpec{
				Type:      "deb",
				Namespace: &debianNs,
				Name:      "dpkg",
			},
			depPkg: model.PkgInputSpec{
				Type:      "deb",
				Namespace: &ubuntuNs,
				Name:      "attr",
			},
			pkgEqual: model.PkgEqualInputSpec{
				Justification: "these two dpkg packages are the same",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
	}
	for _, ingest := range ingestPkgEqual {
		if _, err := model.IngestPackage(ctx, client, ingest.pkg); err != nil {
			logger.Errorf("Error in ingesting package: %v\n", err)
		}
		if _, err := model.IngestPackage(ctx, client, ingest.depPkg); err != nil {
			logger.Errorf("Error in ingesting dependency package: %v\n", err)
		}
		if _, err := model.IngestPkgEqual(ctx, client, ingest.pkg, ingest.depPkg, ingest.pkgEqual); err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
	}
}

func ingestCertifyBad(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	opensslNs := "openssl.org"
	opensslVersion := "3.0.3"
	djangoNameSpace := ""
	sourceTag := "v0.0.1"
	ingestCertifyBad := []struct {
		name         string
		pkg          *model.PkgInputSpec
		pkgMatchType model.MatchFlags
		source       *model.SourceInputSpec
		artifact     *model.ArtifactInputSpec
		certifyBad   model.CertifyBadInputSpec
	}{
		{
			name: "this package as this specific version has a malware",
			pkg: &model.PkgInputSpec{
				Type:       "conan",
				Namespace:  &opensslNs,
				Name:       "openssl",
				Version:    &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			certifyBad: model.CertifyBadInputSpec{
				Justification: "this package as this specific version has a malware",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "this package (all versions) is a known typo-squat",
			pkg: &model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNameSpace,
				Name:      "django",
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			certifyBad: model.CertifyBadInputSpec{
				Justification: "this package (all versions) is a known typo-squat",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "this source repo is owned by a known attacker",
			source: &model.SourceInputSpec{
				Type:      "git",
				Namespace: "github",
				Name:      "github.com/guacsec/guac",
				Tag:       &sourceTag,
			},
			certifyBad: model.CertifyBadInputSpec{
				Justification: "this source repo is owned by a known attacker",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "artifact is associated with a malware package",
			artifact: &model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			certifyBad: model.CertifyBadInputSpec{
				Justification: "this artifact is associated with a malware package",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "this package as this specific version has a malware (duplicate)",
			pkg: &model.PkgInputSpec{
				Type:       "conan",
				Namespace:  &opensslNs,
				Name:       "openssl",
				Version:    &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			certifyBad: model.CertifyBadInputSpec{
				Justification: "this package as this specific version has a malware",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "this package (all versions) is a known typo-squat (duplicate)",
			pkg: &model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNameSpace,
				Name:      "django",
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			certifyBad: model.CertifyBadInputSpec{
				Justification: "this package (all versions) is a known typo-squat",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "this source repo is owned by a known attacker (duplicate)",
			source: &model.SourceInputSpec{
				Type:      "git",
				Namespace: "github",
				Name:      "github.com/guacsec/guac",
				Tag:       &sourceTag,
			},
			certifyBad: model.CertifyBadInputSpec{
				Justification: "this source repo is owned by a known attacker",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "artifact is associated with a malware package (duplicate)",
			artifact: &model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			certifyBad: model.CertifyBadInputSpec{
				Justification: "this artifact is associated with a malware package",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
	}
	for _, ingest := range ingestCertifyBad {
		if ingest.pkg != nil {
			if _, err := model.IngestPackage(ctx, client, *ingest.pkg); err != nil {
				logger.Errorf("Error in ingesting package: %v\n", err)
			}
			if _, err := model.CertifyBadPkg(ctx, client, *ingest.pkg, ingest.pkgMatchType, ingest.certifyBad); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.source != nil {
			if _, err := model.IngestSource(ctx, client, *ingest.source); err != nil {
				logger.Errorf("Error in ingesting source: %v\n", err)
			}
			if _, err := model.CertifyBadSrc(ctx, client, *ingest.source, ingest.certifyBad); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.artifact != nil {
			if _, err := model.IngestArtifact(ctx, client, *ingest.artifact); err != nil {
				logger.Errorf("Error in ingesting artifact: %v\n", err)
			}
			if _, err := model.CertifyBadArtifact(ctx, client, *ingest.artifact, ingest.certifyBad); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else {
			fmt.Printf("input missing for cve, osv or ghsa")
		}
	}
}

func bulkIngestCertifyBad(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	opensslNs := "openssl.org"
	opensslVersion := "3.0.3"
	djangoNameSpace := ""
	sourceTag := "v0.0.1"
	ingestCertifyBad := []struct {
		name         string
		pkg          []model.PkgInputSpec
		pkgMatchType model.MatchFlags
		source       []model.SourceInputSpec
		artifact     []model.ArtifactInputSpec
		certifyBad   []model.CertifyBadInputSpec
	}{
		{
			name: "this package as this specific version has a malware",
			pkg: []model.PkgInputSpec{
				{
					Type:       "conan",
					Namespace:  &opensslNs,
					Name:       "openssl",
					Version:    &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
				},
				{
					Type:       "conan",
					Namespace:  &opensslNs,
					Name:       "openssl",
					Version:    &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
				},
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			certifyBad: []model.CertifyBadInputSpec{
				{
					Justification: "this package as this specific version has a malware",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
				{
					Justification: "this package as this specific version has a malware",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
			},
		},
		{
			name: "this package (all versions) is a known typo-squat",
			pkg: []model.PkgInputSpec{
				{
					Type:      "pypi",
					Namespace: &djangoNameSpace,
					Name:      "django",
				},
				{
					Type:      "pypi",
					Namespace: &djangoNameSpace,
					Name:      "django",
				},
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			certifyBad: []model.CertifyBadInputSpec{
				{
					Justification: "this package (all versions) is a known typo-squat",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
				{
					Justification: "this package (all versions) is a known typo-squat",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
			},
		},
		{
			name: "this source repo is owned by a known attacker",
			source: []model.SourceInputSpec{
				{
					Type:      "git",
					Namespace: "github",
					Name:      "github.com/guacsec/guac",
					Tag:       &sourceTag,
				},
				{
					Type:      "git",
					Namespace: "github",
					Name:      "github.com/guacsec/guac",
					Tag:       &sourceTag,
				},
			},
			certifyBad: []model.CertifyBadInputSpec{
				{
					Justification: "this source repo is owned by a known attacker",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
				{
					Justification: "this source repo is owned by a known attacker",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
			},
		},
		{
			name: "artifact is associated with a malware package",
			artifact: []model.ArtifactInputSpec{
				{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
				{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
			},
			certifyBad: []model.CertifyBadInputSpec{
				{
					Justification: "this artifact is associated with a malware package",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
				{
					Justification: "this artifact is associated with a malware package",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
			},
		},
	}
	for _, ingest := range ingestCertifyBad {
		if ingest.pkg != nil {
			if _, err := model.IngestPackages(ctx, client, ingest.pkg); err != nil {
				logger.Errorf("Error in ingesting package: %v\n", err)
			}
			if _, err := model.CertifyBadPkgs(ctx, client, ingest.pkg, ingest.pkgMatchType, ingest.certifyBad); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.source != nil {
			if _, err := model.IngestSources(ctx, client, ingest.source); err != nil {
				logger.Errorf("Error in ingesting source: %v\n", err)
			}
			if _, err := model.CertifyBadSrcs(ctx, client, ingest.source, ingest.certifyBad); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.artifact != nil {
			if _, err := model.IngestArtifacts(ctx, client, ingest.artifact); err != nil {
				logger.Errorf("Error in ingesting artifact: %v\n", err)
			}
			if _, err := model.CertifyBadArtifacts(ctx, client, ingest.artifact, ingest.certifyBad); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else {
			fmt.Printf("input missing for cve, osv or ghsa")
		}
	}
}

func ingestCertifyGood(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	opensslNs := "openssl.org"
	opensslVersion := "3.0.3"
	djangoNameSpace := ""
	sourceTag := "v0.0.1"
	ingestCertifyGood := []struct {
		name         string
		pkg          *model.PkgInputSpec
		pkgMatchType model.MatchFlags
		source       *model.SourceInputSpec
		artifact     *model.ArtifactInputSpec
		certifyGood  model.CertifyGoodInputSpec
	}{
		{
			name: "this package as this specific version has been audited",
			pkg: &model.PkgInputSpec{
				Type:       "conan",
				Namespace:  &opensslNs,
				Name:       "openssl",
				Version:    &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			certifyGood: model.CertifyGoodInputSpec{
				Justification: "this package as this specific version has been audited",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "this package (all versions) is trusted",
			pkg: &model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNameSpace,
				Name:      "django",
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			certifyGood: model.CertifyGoodInputSpec{
				Justification: "this package (all versions) is trusted",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "this source repo is trusted",
			source: &model.SourceInputSpec{
				Type:      "git",
				Namespace: "github",
				Name:      "github.com/guacsec/guac",
				Tag:       &sourceTag,
			},
			certifyGood: model.CertifyGoodInputSpec{
				Justification: "this source repo is trusted",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "artifact is associated with an audited build",
			artifact: &model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			certifyGood: model.CertifyGoodInputSpec{
				Justification: "this artifact is associated with an audited build",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "this package as this specific version has been audited (duplicate)",
			pkg: &model.PkgInputSpec{
				Type:       "conan",
				Namespace:  &opensslNs,
				Name:       "openssl",
				Version:    &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			certifyGood: model.CertifyGoodInputSpec{
				Justification: "this package as this specific version has been audited",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "this package (all versions) is trusted (duplicate)",
			pkg: &model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNameSpace,
				Name:      "django",
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			certifyGood: model.CertifyGoodInputSpec{
				Justification: "this package (all versions) is trusted",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "this source repo is trusted (duplicate)",
			source: &model.SourceInputSpec{
				Type:      "git",
				Namespace: "github",
				Name:      "github.com/guacsec/guac",
				Tag:       &sourceTag,
			},
			certifyGood: model.CertifyGoodInputSpec{
				Justification: "this source repo is trusted",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "this artifact is associated with an audited build (duplicate)",
			artifact: &model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			certifyGood: model.CertifyGoodInputSpec{
				Justification: "this artifact is associated with an audited build",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
	}
	for _, ingest := range ingestCertifyGood {
		if ingest.pkg != nil {
			if _, err := model.IngestPackage(ctx, client, *ingest.pkg); err != nil {
				logger.Errorf("Error in ingesting package: %v\n", err)
			}
			if _, err := model.CertifyGoodPkg(ctx, client, *ingest.pkg, ingest.pkgMatchType, ingest.certifyGood); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.source != nil {
			if _, err := model.IngestSource(ctx, client, *ingest.source); err != nil {
				logger.Errorf("Error in ingesting source: %v\n", err)
			}
			if _, err := model.CertifyGoodSrc(ctx, client, *ingest.source, ingest.certifyGood); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.artifact != nil {
			if _, err := model.IngestArtifact(ctx, client, *ingest.artifact); err != nil {
				logger.Errorf("Error in ingesting artifact: %v\n", err)
			}
			if _, err := model.CertifyGoodArtifact(ctx, client, *ingest.artifact, ingest.certifyGood); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else {
			fmt.Printf("input missing for cve, osv or ghsa")
		}
	}
}

func bulkIngestCertifyGood(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	opensslNs := "openssl.org"
	opensslVersion := "3.0.3"
	djangoNameSpace := ""
	sourceTag := "v0.0.1"
	ingestCertifyGood := []struct {
		name         string
		pkg          []model.PkgInputSpec
		pkgMatchType model.MatchFlags
		source       []model.SourceInputSpec
		artifact     []model.ArtifactInputSpec
		certifyGood  []model.CertifyGoodInputSpec
	}{
		{
			name: "this package as this specific version has been audited",
			pkg: []model.PkgInputSpec{
				{
					Type:       "conan",
					Namespace:  &opensslNs,
					Name:       "openssl",
					Version:    &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
				},
				{
					Type:       "conan",
					Namespace:  &opensslNs,
					Name:       "openssl",
					Version:    &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
				},
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			certifyGood: []model.CertifyGoodInputSpec{
				{
					Justification: "this package as this specific version has been audited",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
				{
					Justification: "this package as this specific version has been audited",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
			},
		},
		{
			name: "this package (all versions) is trusted",
			pkg: []model.PkgInputSpec{
				{
					Type:      "pypi",
					Namespace: &djangoNameSpace,
					Name:      "django",
				},
				{
					Type:      "pypi",
					Namespace: &djangoNameSpace,
					Name:      "django",
				},
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			certifyGood: []model.CertifyGoodInputSpec{
				{
					Justification: "this package (all versions) is trusted",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
				{
					Justification: "this package (all versions) is trusted",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
			},
		},
		{
			name: "this source repo is trusted",
			source: []model.SourceInputSpec{
				{
					Type:      "git",
					Namespace: "github",
					Name:      "github.com/guacsec/guac",
					Tag:       &sourceTag,
				},
				{
					Type:      "git",
					Namespace: "github",
					Name:      "github.com/guacsec/guac",
					Tag:       &sourceTag,
				},
			},
			certifyGood: []model.CertifyGoodInputSpec{
				{
					Justification: "this source repo is trusted",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
				{
					Justification: "this source repo is trusted",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
			},
		},
		{
			name: "artifact is associated with an audited build",
			artifact: []model.ArtifactInputSpec{
				{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
				{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
			},
			certifyGood: []model.CertifyGoodInputSpec{
				{
					Justification: "this artifact is associated with an audited build",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
				{
					Justification: "this artifact is associated with an audited build",
					Origin:        "Demo ingestion",
					Collector:     "Demo ingestion",
				},
			},
		},
	}
	for _, ingest := range ingestCertifyGood {
		if ingest.pkg != nil {
			if _, err := model.IngestPackages(ctx, client, ingest.pkg); err != nil {
				logger.Errorf("Error in ingesting package: %v\n", err)
			}
			if _, err := model.CertifyGoodPkgs(ctx, client, ingest.pkg, ingest.pkgMatchType, ingest.certifyGood); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.source != nil {
			if _, err := model.IngestSources(ctx, client, ingest.source); err != nil {
				logger.Errorf("Error in ingesting source: %v\n", err)
			}
			if _, err := model.CertifyGoodSrcs(ctx, client, ingest.source, ingest.certifyGood); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.artifact != nil {
			if _, err := model.IngestArtifacts(ctx, client, ingest.artifact); err != nil {
				logger.Errorf("Error in ingesting artifact: %v\n", err)
			}
			if _, err := model.CertifyGoodArtifacts(ctx, client, ingest.artifact, ingest.certifyGood); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else {
			fmt.Printf("input missing for cve, osv or ghsa")
		}
	}
}

func ingestHashEqual(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	ingestHashEqual := []struct {
		name          string
		artifact      model.ArtifactInputSpec
		equalArtifact model.ArtifactInputSpec
		hashEqual     model.HashEqualInputSpec
	}{
		{
			name: "these sha1 and sha256 artifacts are the same",
			artifact: model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			equalArtifact: model.ArtifactInputSpec{
				Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
				Algorithm: "sha1",
			},
			hashEqual: model.HashEqualInputSpec{
				Justification: "these sha1 and sha256 artifacts are the same",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "these sha256 and sha512 artifacts are the same",
			artifact: model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			equalArtifact: model.ArtifactInputSpec{
				Digest:    "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7",
				Algorithm: "sha512",
			},
			hashEqual: model.HashEqualInputSpec{
				Justification: "these sha256 and sha512 artifacts are the same",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
	}
	for _, ingest := range ingestHashEqual {
		if _, err := model.IngestArtifact(ctx, client, ingest.artifact); err != nil {
			logger.Errorf("Error in ingesting artifact: %v\n", err)
		}
		if _, err := model.IngestArtifact(ctx, client, ingest.equalArtifact); err != nil {
			logger.Errorf("Error in ingesting equal artifact: %v\n", err)
		}
		if _, err := model.IngestHashEqual(ctx, client, ingest.artifact, ingest.equalArtifact, ingest.hashEqual); err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
	}
}

func ingestHasSBOM(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	opensslNs := "openssl.org"
	opensslVersion := "3.0.3"
	ingestHasSBOM := []struct {
		name     string
		pkg      *model.PkgInputSpec
		artifact *model.ArtifactInputSpec
		hasSBOM  model.HasSBOMInputSpec
	}{
		{
			name: "uri:location of package SBOM",
			pkg: &model.PkgInputSpec{
				Type:       "conan",
				Namespace:  &opensslNs,
				Name:       "openssl",
				Version:    &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
			},
			hasSBOM: model.HasSBOMInputSpec{
				Uri:              "uri:location of package SBOM",
				Algorithm:        "sha256",
				Digest:           "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				DownloadLocation: "uri: download location of the SBOM",
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "uri:location of artifact SBOM",
			artifact: &model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			hasSBOM: model.HasSBOMInputSpec{
				Uri:              "uri:location of artifact SBOM",
				Algorithm:        "sha1",
				Digest:           "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
				DownloadLocation: "uri: download location of the SBOM",
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "uri:location of package SBOM (duplicate)",
			pkg: &model.PkgInputSpec{
				Type:       "conan",
				Namespace:  &opensslNs,
				Name:       "openssl",
				Version:    &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
			},
			hasSBOM: model.HasSBOMInputSpec{
				Uri:              "uri:location of package SBOM",
				Algorithm:        "sha256",
				Digest:           "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				DownloadLocation: "uri: download location of the SBOM",
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "uri:location of source SBOM (duplicate)",
			artifact: &model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			hasSBOM: model.HasSBOMInputSpec{
				Uri:              "uri:location of artifact SBOM",
				Algorithm:        "sha1",
				Digest:           "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
				DownloadLocation: "uri: download location of the SBOM",
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
	}
	for _, ingest := range ingestHasSBOM {
		if ingest.pkg != nil {
			if _, err := model.IngestPackage(ctx, client, *ingest.pkg); err != nil {
				logger.Errorf("Error in ingesting package: %v\n", err)
			}
			if _, err := model.HasSBOMPkg(ctx, client, *ingest.pkg, ingest.hasSBOM); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.artifact != nil {
			if _, err := model.IngestArtifact(ctx, client, *ingest.artifact); err != nil {
				logger.Errorf("Error in ingesting artifact: %v\n", err)
			}
			if _, err := model.HasSBOMArtifact(ctx, client, *ingest.artifact, ingest.hasSBOM); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else {
			fmt.Printf("input missing for package or source")
		}
	}
}

func ingestHasSourceAt(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	djangoNameSpace := ""
	djangoTag := "1.11.1"
	kubetestNameSpace := ""
	kubetestVersion := "0.9.5"
	kubetestSubpath := ""
	kubetestTag := "0.9.5"
	ingestHasSourceAt := []struct {
		name         string
		pkg          model.PkgInputSpec
		pkgMatchType model.MatchFlags
		source       model.SourceInputSpec
		hasSourceAt  model.HasSourceAtInputSpec
	}{
		{
			name: "django located at the following source based on deps.dev",
			pkg: model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNameSpace,
				Name:      "django",
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			source: model.SourceInputSpec{
				Type:      "git",
				Namespace: "github",
				Name:      "https://github.com/django/django",
				Tag:       &djangoTag,
			},
			hasSourceAt: model.HasSourceAtInputSpec{
				KnownSince:    tm,
				Justification: "django located at the following source based on deps.dev",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "duplicate entry",
			pkg: model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &djangoNameSpace,
				Name:      "django",
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			source: model.SourceInputSpec{
				Type:      "git",
				Namespace: "github",
				Name:      "https://github.com/django/django",
				Tag:       &djangoTag,
			},
			hasSourceAt: model.HasSourceAtInputSpec{
				KnownSince:    tm,
				Justification: "django located at the following source based on deps.dev",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "kubetest located at the following source based on deps.dev",
			pkg: model.PkgInputSpec{
				Type:      "pypi",
				Namespace: &kubetestNameSpace,
				Name:      "kubetest",
				Version:   &kubetestVersion,
				Subpath:   &kubetestSubpath,
			},
			pkgMatchType: model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			source: model.SourceInputSpec{
				Type:      "git",
				Namespace: "github",
				Name:      "https://github.com/vapor-ware/kubetest",
				Tag:       &kubetestTag,
			},
			hasSourceAt: model.HasSourceAtInputSpec{
				KnownSince:    time.Now(),
				Justification: "kubetest located at the following source based on deps.dev",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
	}
	for _, ingest := range ingestHasSourceAt {
		if _, err := model.IngestPackage(ctx, client, ingest.pkg); err != nil {
			logger.Errorf("Error in ingesting package: %v\n", err)
		}
		if _, err := model.IngestSource(ctx, client, ingest.source); err != nil {
			logger.Errorf("Error in ingesting source: %v\n", err)
		}
		if _, err := model.HasSourceAt(ctx, client, ingest.pkg, ingest.pkgMatchType, ingest.source, ingest.hasSourceAt); err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
	}
}

func ingestIsVulnerability(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	ingestIsVulnerability := []struct {
		name      string
		vuln      *model.VulnerabilityInputSpec
		otherVuln *model.VulnerabilityInputSpec
		vulnEqual model.VulnEqualInputSpec
	}{
		{
			name: "OSV maps to CVE",
			vuln: &model.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "CVE-2019-13110",
			},
			otherVuln: &model.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			},
			vulnEqual: model.VulnEqualInputSpec{
				Justification: "OSV maps to CVE",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "OSV maps to GHSA",
			vuln: &model.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
			},
			otherVuln: &model.VulnerabilityInputSpec{
				Type:            "ghsa",
				VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
			},
			vulnEqual: model.VulnEqualInputSpec{
				Justification: "OSV maps to GHSA",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
		{
			name: "OSV maps to CVE (duplicate)",
			vuln: &model.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "CVE-2019-13110",
			},
			otherVuln: &model.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			},
			vulnEqual: model.VulnEqualInputSpec{
				Justification: "OSV maps to CVE",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		}, {
			name: "OSV maps to GHSA (duplicate)",
			vuln: &model.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
			},
			otherVuln: &model.VulnerabilityInputSpec{
				Type:            "ghsa",
				VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
			},
			vulnEqual: model.VulnEqualInputSpec{
				Justification: "OSV maps to GHSA",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
		},
	}
	for _, ingest := range ingestIsVulnerability {
		if _, err := model.IngestVulnerability(ctx, client, *ingest.vuln); err != nil {
			logger.Errorf("Error in ingesting vuln: %v\n", err)
		}
		if _, err := model.IngestVulnerability(ctx, client, *ingest.otherVuln); err != nil {
			logger.Errorf("Error in ingesting other vuln: %v\n", err)
		}
		if _, err := model.IngestVulnEqual(ctx, client, *ingest.vuln, *ingest.otherVuln, ingest.vulnEqual); err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}

	}
}

func ingestVEXStatement(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	opensslNs := "openssl.org"
	opensslVersion := "3.0.3"
	ingestCertifyVex := []struct {
		name         string
		pkg          *model.PkgInputSpec
		artifact     *model.ArtifactInputSpec
		vuln         *model.VulnerabilityInputSpec
		vexStatement model.VexStatementInputSpec
	}{
		{
			name: "this package is not vulnerable to this OSV",
			pkg: &model.PkgInputSpec{
				Type:       "conan",
				Namespace:  &opensslNs,
				Name:       "openssl",
				Version:    &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "CVE-2019-14750",
			},
			vexStatement: model.VexStatementInputSpec{
				Status:           model.VexStatusFixed,
				VexJustification: model.VexJustificationNotProvided,
				KnownSince:       tm,
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "this package is not vulnerable to this CVE",
			pkg: &model.PkgInputSpec{
				Type:       "conan",
				Namespace:  &opensslNs,
				Name:       "openssl",
				Version:    &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			},
			vexStatement: model.VexStatementInputSpec{
				Status:           model.VexStatusAffected,
				VexJustification: model.VexJustificationNotProvided,
				Statement:        "this package is vulnerable to this CVE",
				KnownSince:       tm,
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "this package is not vulnerable to this GHSA",
			pkg: &model.PkgInputSpec{
				Type:       "conan",
				Namespace:  &opensslNs,
				Name:       "openssl",
				Version:    &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "ghsa",
				VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
			},
			vexStatement: model.VexStatementInputSpec{
				Status:           model.VexStatusNotAffected,
				VexJustification: model.VexJustificationComponentNotPresent,
				KnownSince:       tm,
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "this artifact is not vulnerable to this OSV",
			artifact: &model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "CVE-2018-15710",
			},
			vexStatement: model.VexStatementInputSpec{
				Status:           model.VexStatusUnderInvestigation,
				VexJustification: model.VexJustificationNotProvided,
				KnownSince:       tm,
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "this artifact is not vulnerable to this CVE",
			artifact: &model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "CVE-2018-43610",
			},
			vexStatement: model.VexStatementInputSpec{
				Status:           model.VexStatusNotAffected,
				VexJustification: model.VexJustificationNotProvided,
				Statement:        "this artifact is not vulnerable to this CVE",
				StatusNotes:      "status not affected because code not in execution path",
				KnownSince:       tm,
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "this artifact is not vulnerable to this GHSA",
			artifact: &model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "ghsa",
				VulnerabilityID: "GHSA-hj5f-4gvw-4rv2",
			},
			vexStatement: model.VexStatementInputSpec{
				Status:           model.VexStatusNotAffected,
				VexJustification: model.VexJustificationVulnerableCodeNotInExecutePath,
				KnownSince:       tm,
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "this package is not vulnerable to this OSV (duplicate)",
			pkg: &model.PkgInputSpec{
				Type:       "conan",
				Namespace:  &opensslNs,
				Name:       "openssl",
				Version:    &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "CVE-2019-14750",
			},
			vexStatement: model.VexStatementInputSpec{
				Status:           model.VexStatusFixed,
				VexJustification: model.VexJustificationNotProvided,
				KnownSince:       tm,
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "this package is not vulnerable to this CVE (duplicate)",
			pkg: &model.PkgInputSpec{
				Type:       "conan",
				Namespace:  &opensslNs,
				Name:       "openssl",
				Version:    &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			},
			vexStatement: model.VexStatementInputSpec{
				Status:           model.VexStatusAffected,
				VexJustification: model.VexJustificationNotProvided,
				Statement:        "this package is vulnerable to this CVE",
				KnownSince:       tm,
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "this package is not vulnerable to this GHSA (duplicate)",
			pkg: &model.PkgInputSpec{
				Type:       "conan",
				Namespace:  &opensslNs,
				Name:       "openssl",
				Version:    &opensslVersion,
				Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "ghsa",
				VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
			},
			vexStatement: model.VexStatementInputSpec{
				Status:           model.VexStatusNotAffected,
				VexJustification: model.VexJustificationComponentNotPresent,
				KnownSince:       tm,
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "this artifact is not vulnerable to this OSV (duplicate)",
			artifact: &model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "CVE-2018-15710",
			},
			vexStatement: model.VexStatementInputSpec{
				Status:           model.VexStatusUnderInvestigation,
				VexJustification: model.VexJustificationNotProvided,
				KnownSince:       tm,
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "this artifact is not vulnerable to this CVE (duplicate)",
			artifact: &model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "CVE-2018-43610",
			},
			vexStatement: model.VexStatementInputSpec{
				Status:           model.VexStatusNotAffected,
				VexJustification: model.VexJustificationNotProvided,
				Statement:        "this artifact is not vulnerable to this CVE",
				StatusNotes:      "status not affected because code not in execution path",
				KnownSince:       tm,
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
		{
			name: "this artifact is not vulnerable to this GHSA (duplicate)",
			artifact: &model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "ghsa",
				VulnerabilityID: "GHSA-hj5f-4gvw-4rv2",
			},
			vexStatement: model.VexStatementInputSpec{
				Status:           model.VexStatusNotAffected,
				VexJustification: model.VexJustificationVulnerableCodeNotInExecutePath,
				KnownSince:       tm,
				Origin:           "Demo ingestion",
				Collector:        "Demo ingestion",
			},
		},
	}
	for _, ingest := range ingestCertifyVex {
		if ingest.pkg != nil {
			if _, err := model.IngestPackage(ctx, client, *ingest.pkg); err != nil {
				logger.Errorf("Error in ingesting package: %v\n", err)
			}
			if _, err := model.IngestVulnerability(ctx, client, *ingest.vuln); err != nil {
				logger.Errorf("Error in ingesting vulnerability: %v\n", err)
			}
			if _, err := model.CertifyVexPkg(ctx, client, *ingest.pkg, *ingest.vuln, ingest.vexStatement); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}

		} else if ingest.artifact != nil {
			if _, err := model.IngestArtifact(ctx, client, *ingest.artifact); err != nil {
				logger.Errorf("Error in ingesting artifact: %v\n", err)
			}
			if _, err := model.IngestVulnerability(ctx, client, *ingest.vuln); err != nil {
				logger.Errorf("Error in ingesting vulnerability: %v\n", err)
			}
			if _, err := model.CertifyVexArtifact(ctx, client, *ingest.artifact, *ingest.vuln, ingest.vexStatement); err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}

		} else {
			fmt.Printf("input missing for package or artifact")
		}
	}
}

func bulkIngestVEXStatement(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	opensslNs := "openssl.org"
	opensslVersion := "3.0.3"
	ingestCertifyVex := []struct {
		name          string
		pkgs          []model.PkgInputSpec
		artifacts     []model.ArtifactInputSpec
		vulns         []model.VulnerabilityInputSpec
		vexStatements []model.VexStatementInputSpec
	}{
		{
			name: "bulk ingest packages",
			pkgs: []model.PkgInputSpec{
				{
					Type:       "conan",
					Namespace:  &opensslNs,
					Name:       "openssl",
					Version:    &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
				},
				{
					Type:       "conan",
					Namespace:  &opensslNs,
					Name:       "openssl",
					Version:    &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
				},
				{
					Type:       "conan",
					Namespace:  &opensslNs,
					Name:       "openssl",
					Version:    &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
				},
				{
					Type:       "conan",
					Namespace:  &opensslNs,
					Name:       "openssl",
					Version:    &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
				},
				{
					Type:       "conan",
					Namespace:  &opensslNs,
					Name:       "openssl",
					Version:    &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
				},
				{
					Type:       "conan",
					Namespace:  &opensslNs,
					Name:       "openssl",
					Version:    &opensslVersion,
					Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
				},
			},
			vulns: []model.VulnerabilityInputSpec{
				{
					Type:            "osv",
					VulnerabilityID: "CVE-2019-14750",
				},
				{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				{
					Type:            "ghsa",
					VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
				},
				{
					Type:            "osv",
					VulnerabilityID: "CVE-2019-14750",
				},
				{
					Type:            "cve",
					VulnerabilityID: "CVE-2019-13110",
				},
				{
					Type:            "ghsa",
					VulnerabilityID: "GHSA-h45f-rjvw-2rv2",
				},
			},
			vexStatements: []model.VexStatementInputSpec{
				{
					Status:           model.VexStatusFixed,
					VexJustification: model.VexJustificationNotProvided,
					KnownSince:       tm,
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
				{
					Status:           model.VexStatusAffected,
					VexJustification: model.VexJustificationNotProvided,
					Statement:        "this package is vulnerable to this CVE",
					KnownSince:       tm,
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
				{
					Status:           model.VexStatusNotAffected,
					VexJustification: model.VexJustificationComponentNotPresent,
					KnownSince:       tm,
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
				{
					Status:           model.VexStatusFixed,
					VexJustification: model.VexJustificationNotProvided,
					KnownSince:       tm,
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
				{
					Status:           model.VexStatusAffected,
					VexJustification: model.VexJustificationNotProvided,
					Statement:        "this package is vulnerable to this CVE",
					KnownSince:       tm,
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
				{
					Status:           model.VexStatusNotAffected,
					VexJustification: model.VexJustificationComponentNotPresent,
					KnownSince:       tm,
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
			},
		},
		{
			name: "bulk ingest artifacts",
			artifacts: []model.ArtifactInputSpec{
				{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
				{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
				{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
				{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
				{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
				{
					Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					Algorithm: "sha256",
				},
			},
			vulns: []model.VulnerabilityInputSpec{
				{
					Type:            "osv",
					VulnerabilityID: "CVE-2018-15710",
				},
				{
					Type:            "cve",
					VulnerabilityID: "CVE-2018-43610",
				},
				{
					Type:            "ghsa",
					VulnerabilityID: "GHSA-hj5f-4gvw-4rv2",
				},
				{
					Type:            "osv",
					VulnerabilityID: "CVE-2018-15710",
				},
				{
					Type:            "cve",
					VulnerabilityID: "CVE-2018-43610",
				},
				{
					Type:            "ghsa",
					VulnerabilityID: "GHSA-hj5f-4gvw-4rv2",
				},
			},
			vexStatements: []model.VexStatementInputSpec{
				{
					Status:           model.VexStatusUnderInvestigation,
					VexJustification: model.VexJustificationNotProvided,
					KnownSince:       tm,
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
				{
					Status:           model.VexStatusNotAffected,
					VexJustification: model.VexJustificationNotProvided,
					Statement:        "this artifact is not vulnerable to this CVE",
					StatusNotes:      "status not affected because code not in execution path",
					KnownSince:       tm,
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
				{
					Status:           model.VexStatusNotAffected,
					VexJustification: model.VexJustificationVulnerableCodeNotInExecutePath,
					KnownSince:       tm,
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
				{
					Status:           model.VexStatusUnderInvestigation,
					VexJustification: model.VexJustificationNotProvided,
					KnownSince:       tm,
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
				{
					Status:           model.VexStatusNotAffected,
					VexJustification: model.VexJustificationNotProvided,
					Statement:        "this artifact is not vulnerable to this CVE",
					StatusNotes:      "status not affected because code not in execution path",
					KnownSince:       tm,
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
				{
					Status:           model.VexStatusNotAffected,
					VexJustification: model.VexJustificationVulnerableCodeNotInExecutePath,
					KnownSince:       tm,
					Origin:           "Demo ingestion",
					Collector:        "Demo ingestion",
				},
			},
		},
	}
	for _, ingest := range ingestCertifyVex {
		if ingest.pkgs != nil {
			if _, err := model.IngestPackages(ctx, client, ingest.pkgs); err != nil {
				logger.Errorf("Error in ingesting packages: %v\n", err)
			}
			if _, err := model.IngestVulnerabilities(ctx, client, ingest.vulns); err != nil {
				logger.Errorf("Error in ingesting vulnerabilities: %v\n", err)
			}
			if _, err := model.CertifyVexPkgs(ctx, client, ingest.pkgs, ingest.vulns, ingest.vexStatements); err != nil {
				logger.Errorf("Error in ingesting CertifyVexPkgs: %v\n", err)
			}

		} else if ingest.artifacts != nil {
			if _, err := model.IngestArtifacts(ctx, client, ingest.artifacts); err != nil {
				logger.Errorf("Error in ingesting artifacts: %v\n", err)
			}
			if _, err := model.IngestVulnerabilities(ctx, client, ingest.vulns); err != nil {
				logger.Errorf("Error in ingesting vulnerabilities: %v\n", err)
			}
			if _, err := model.CertifyVexArtifacts(ctx, client, ingest.artifacts, ingest.vulns, ingest.vexStatements); err != nil {
				logger.Errorf("Error in ingesting CertifyVexArtifacts: %v\n", err)
			}

		} else {
			fmt.Printf("input missing for package or artifact")
		}
	}
}

func ingestReachabilityTestData(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	ns := "ubuntu"
	version := "1.19.0.4"
	depns := "openssl.org"
	opensslVersion := "3.0.3"
	opensslTag := "3.0.3"
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	ingestDependencies := []struct {
		name              string
		pkg               model.PkgInputSpec
		depPkg            model.PkgInputSpec
		dependency        model.IsDependencyInputSpec
		depPkgWithVersion model.PkgInputSpec
		depPkgMatchFlags  model.MatchFlags
		art               model.ArtifactInputSpec
		occurrence        model.IsOccurrenceInputSpec
		source            model.SourceInputSpec
		hasSourceAt       model.HasSourceAtInputSpec
		sourceArt         model.ArtifactInputSpec
		sourceOccurrence  model.IsOccurrenceInputSpec
		vuln              *model.VulnerabilityInputSpec
		scanMetadata      model.ScanMetadataInput
	}{
		{
			name: "deb: part of SBOM - openssl",
			pkg: model.PkgInputSpec{
				Type:      "deb",
				Namespace: &ns,
				Name:      "dpkg",
				Version:   &version,
				Qualifiers: []model.PackageQualifierInputSpec{
					{Key: "arch", Value: "amd64"},
				},
			},
			depPkg: model.PkgInputSpec{
				Type:      "conan",
				Namespace: &depns,
				Name:      "openssl",
			},
			depPkgMatchFlags: model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions},
			dependency: model.IsDependencyInputSpec{
				VersionRange:   "3.0.3",
				DependencyType: model.DependencyTypeDirect,
				Justification:  "deb: part of SBOM - openssl",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
			depPkgWithVersion: model.PkgInputSpec{
				Type:      "conan",
				Namespace: &depns,
				Name:      "openssl",
				Version:   &opensslVersion,
			},
			art: model.ArtifactInputSpec{
				Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
				Algorithm: "sha256",
			},
			occurrence: model.IsOccurrenceInputSpec{
				Justification: "openssl v3.0.3 is represented by this artifact",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
			source: model.SourceInputSpec{
				Type:      "git",
				Namespace: "github",
				Name:      "https://github.com/openssl/openssl",
				Tag:       &opensslTag,
			},
			hasSourceAt: model.HasSourceAtInputSpec{
				KnownSince:    tm,
				Justification: "openssl 3.0.3 source repo based on deps.dev",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
			sourceArt: model.ArtifactInputSpec{
				Digest:    "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7",
				Algorithm: "sha512",
			},
			sourceOccurrence: model.IsOccurrenceInputSpec{
				Justification: "this artifact is an occurrence of openssl source repo",
				Origin:        "Demo ingestion",
				Collector:     "Demo ingestion",
			},
			vuln: &model.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "CVE-2019-13110",
			},
			scanMetadata: model.ScanMetadataInput{
				TimeScanned:    time.Now(),
				DbUri:          "MITRE",
				DbVersion:      "v1.0.0",
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
				Origin:         "Demo ingestion",
				Collector:      "Demo ingestion",
			},
		},
	}
	for _, ingest := range ingestDependencies {
		if _, err := model.IngestPackage(ctx, client, ingest.pkg); err != nil {
			logger.Errorf("Error in ingesting package: %v\n", err)
		}
		if _, err := model.IngestPackage(ctx, client, ingest.depPkg); err != nil {
			logger.Errorf("Error in ingesting dependency package: %v\n", err)
		}
		if _, err := model.IngestPackage(ctx, client, ingest.depPkgWithVersion); err != nil {
			logger.Errorf("Error in ingesting dependency package with version: %v\n", err)
		}
		if _, err := model.IngestArtifact(ctx, client, ingest.art); err != nil {
			logger.Errorf("Error in ingesting artifact: %v\n", err)
		}
		if _, err := model.IngestArtifact(ctx, client, ingest.sourceArt); err != nil {
			logger.Errorf("Error in ingesting source artifact: %v\n", err)
		}
		if _, err := model.IngestSource(ctx, client, ingest.source); err != nil {
			logger.Errorf("Error in ingesting source: %v\n", err)
		}
		if _, err := model.IngestVulnerability(ctx, client, *ingest.vuln); err != nil {
			logger.Errorf("Error in ingesting vuln: %v\n", err)
		}
		if _, err := model.IsDependency(ctx, client, ingest.pkg, ingest.depPkg, ingest.depPkgMatchFlags, ingest.dependency); err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
		if _, err := model.IsOccurrencePkg(ctx, client, ingest.depPkgWithVersion, ingest.art, ingest.occurrence); err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
		if _, err := model.HasSourceAt(ctx, client, ingest.depPkgWithVersion, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}, ingest.source, ingest.hasSourceAt); err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
		if _, err := model.IsOccurrenceSrc(ctx, client, ingest.source, ingest.sourceArt, ingest.sourceOccurrence); err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
		if _, err := model.CertifyVulnPkg(ctx, client, ingest.depPkgWithVersion, *ingest.vuln, ingest.scanMetadata); err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
	}
}
