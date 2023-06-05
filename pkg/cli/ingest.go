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

package cli

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
	ingestPkgEqual(ctx, gqlclient)
	ingestCertifyBad(ctx, gqlclient)
	ingestCertifyGood(ctx, gqlclient)
	ingestHashEqual(ctx, gqlclient)
	ingestHasSBOM(ctx, gqlclient)
	ingestHasSourceAt(ctx, gqlclient)
	ingestIsVulnerability(ctx, gqlclient)
	ingestVEXStatement(ctx, gqlclient)
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
	_, err := model.Scorecard(context.Background(), client, source, scorecard)
	if err != nil {
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

	artifact := model.ArtifactInputSpec{
		Digest:    "5a787865sd676dacb0142afa0b83029cd7befd9",
		Algorithm: "sha1",
	}
	materials := []model.ArtifactInputSpec{
		{
			Digest:    "0123456789abcdef0000000fedcba9876543210",
			Algorithm: "sha1",
		},
	}
	builder := model.BuilderInputSpec{
		Uri: "https://github.com/BuildPythonWheel/HubHostedActions@v1",
	}
	slsa := model.SLSAInputSpec{
		BuildType:     "Test:SLSA",
		SlsaPredicate: predicate,
		SlsaVersion:   "v1",
		StartedOn:     &startTime,
		FinishedOn:    &finishTime,
		Origin:        "Demo ingestion",
		Collector:     "Demo ingestion",
	}
	if _, err := model.SLSAForArtifact(ctx, client, artifact,
		materials, builder, slsa); err != nil {
		logger.Errorf("Error in ingesting: %v\n", err)
	}

	artifact = model.ArtifactInputSpec{
		Digest:    "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7",
		Algorithm: "sha512",
	}
	materials = []model.ArtifactInputSpec{
		{
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
			Algorithm: "sha256",
		},
		{
			Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
			Algorithm: "sha1",
		},
	}
	builder = model.BuilderInputSpec{
		Uri: "https://github.com/CreateFork/HubHostedActions@v1",
	}
	slsa = model.SLSAInputSpec{
		BuildType:     "Test:SLSA2",
		SlsaPredicate: predicate,
		SlsaVersion:   "v1",
		Origin:        "Demo ingestion",
		Collector:     "Demo ingestion",
	}
	if _, err := model.SLSAForArtifact(ctx, client, artifact,
		materials, builder, slsa); err != nil {
		logger.Errorf("Error in ingesting: %v\n", err)
	}
}

func ingestDependency(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)

	ns := "ubuntu"
	version := "1.19.0.4"
	depns := "openssl.org"
	smartentryNs := "smartentry"

	ingestDependencies := []struct {
		name       string
		pkg        model.PkgInputSpec
		depPkg     model.PkgInputSpec
		dependency model.IsDependencyInputSpec
	}{{
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
		dependency: model.IsDependencyInputSpec{
			VersionRange:   "3.0.3",
			DependencyType: model.DependencyTypeDirect,
			Justification:  "deb: part of SBOM - openssl",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
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
		},
		dependency: model.IsDependencyInputSpec{
			VersionRange:   "3.0.3",
			DependencyType: model.DependencyTypeIndirect,
			Justification:  "docker: part of SBOM - openssl",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "deb: part of SBOM - openssl (duplicate)",
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
		dependency: model.IsDependencyInputSpec{
			VersionRange:   "3.0.3",
			DependencyType: model.DependencyTypeDirect,
			Justification:  "deb: part of SBOM - openssl",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}}
	for _, ingest := range ingestDependencies {
		_, err := model.IsDependency(context.Background(), client, ingest.pkg, ingest.depPkg, ingest.dependency)
		if err != nil {
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
	}{{
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
	}, {
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
	}, {
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
	}}
	for _, ingest := range ingestOccurrences {
		if ingest.pkg != nil {
			_, err := model.IsOccurrencePkg(context.Background(), client, *ingest.pkg, ingest.art, ingest.occurrence)
			if err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.src != nil {
			_, err := model.IsOccurrenceSrc(context.Background(), client, *ingest.src, ingest.art, ingest.occurrence)
			if err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else {
			fmt.Printf("input missing for pkg or src")
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
		cve           *model.CVEInputSpec
		osv           *model.OSVInputSpec
		ghsa          *model.GHSAInputSpec
		vulnerability model.VulnerabilityMetaDataInput
	}{{
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
		cve: &model.CVEInputSpec{
			Year:  2019,
			CveId: "CVE-2019-13110",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "MITRE",
			DbVersion:      "v1.0.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
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
		osv: &model.OSVInputSpec{
			OsvId: "CVE-2019-13110",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "MITRE",
			DbVersion:      "v1.0.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
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
		ghsa: &model.GHSAInputSpec{
			GhsaId: "GHSA-h45f-rjvw-2rv2",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "MITRE",
			DbVersion:      "v1.0.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "cve django",
		pkg: &model.PkgInputSpec{
			Type:      "pypi",
			Namespace: &djangoNs,
			Name:      "django",
		},
		cve: &model.CVEInputSpec{
			Year:  2018,
			CveId: "CVE-2018-12310",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "MITRE",
			DbVersion:      "v1.2.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "osv django",
		pkg: &model.PkgInputSpec{
			Type:      "pypi",
			Namespace: &djangoNs,
			Name:      "django",
		},
		osv: &model.OSVInputSpec{
			OsvId: "CVE-2018-12310",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "MITRE",
			DbVersion:      "v1.2.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "ghsa django",
		pkg: &model.PkgInputSpec{
			Type:      "pypi",
			Namespace: &djangoNs,
			Name:      "django",
		},
		ghsa: &model.GHSAInputSpec{
			GhsaId: "GHSA-f45f-jj4w-2rv2",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "MITRE",
			DbVersion:      "v1.2.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
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
		cve: &model.CVEInputSpec{
			Year:  2019,
			CveId: "CVE-2019-13110",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "MITRE",
			DbVersion:      "v1.0.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "ghsa django (duplicate)",
		pkg: &model.PkgInputSpec{
			Type:      "pypi",
			Namespace: &djangoNs,
			Name:      "django",
		},
		ghsa: &model.GHSAInputSpec{
			GhsaId: "GHSA-f45f-jj4w-2rv2",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "MITRE",
			DbVersion:      "v1.2.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
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
		osv: &model.OSVInputSpec{
			OsvId: "CVE-2019-13110",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "MITRE",
			DbVersion:      "v1.0.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}}
	for _, ingest := range ingestVulnerabilities {
		if ingest.cve != nil {
			_, err := model.CertifyCVE(context.Background(), client, *ingest.pkg, *ingest.cve, ingest.vulnerability)
			if err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.osv != nil {
			_, err := model.CertifyOSV(context.Background(), client, *ingest.pkg, *ingest.osv, ingest.vulnerability)
			if err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.ghsa != nil {
			_, err := model.CertifyGHSA(context.Background(), client, *ingest.pkg, *ingest.ghsa, ingest.vulnerability)
			if err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else {
			fmt.Printf("input missing for cve, osv or ghsa")
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
	}{{
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
	}, {
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
	}, {
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
	}, {
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
	}}
	for _, ingest := range ingestPkgEqual {
		_, err := model.PkgEqual(context.Background(), client, ingest.pkg, ingest.depPkg, ingest.pkgEqual)
		if err != nil {
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
		pkgMatchType *model.MatchFlags
		source       *model.SourceInputSpec
		artifact     *model.ArtifactInputSpec
		certifyBad   model.CertifyBadInputSpec
	}{{
		name: "this package as this specific version has a malware",
		pkg: &model.PkgInputSpec{
			Type:       "conan",
			Namespace:  &opensslNs,
			Name:       "openssl",
			Version:    &opensslVersion,
			Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
		},
		pkgMatchType: &model.MatchFlags{
			Pkg: model.PkgMatchTypeSpecificVersion,
		},
		certifyBad: model.CertifyBadInputSpec{
			Justification: "this package as this specific version has a malware",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	}, {
		name: "this package (all versions) is a known typo-squat",
		pkg: &model.PkgInputSpec{
			Type:      "pypi",
			Namespace: &djangoNameSpace,
			Name:      "django",
		},
		pkgMatchType: &model.MatchFlags{
			Pkg: model.PkgMatchTypeAllVersions,
		},
		certifyBad: model.CertifyBadInputSpec{
			Justification: "this package (all versions) is a known typo-squat",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	}, {
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
	}, {
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
	}, {
		name: "this package as this specific version has a malware (duplicate)",
		pkg: &model.PkgInputSpec{
			Type:       "conan",
			Namespace:  &opensslNs,
			Name:       "openssl",
			Version:    &opensslVersion,
			Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
		},
		pkgMatchType: &model.MatchFlags{
			Pkg: model.PkgMatchTypeSpecificVersion,
		},
		certifyBad: model.CertifyBadInputSpec{
			Justification: "this package as this specific version has a malware",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	}, {
		name: "this package (all versions) is a known typo-squat (duplicate)",
		pkg: &model.PkgInputSpec{
			Type:      "pypi",
			Namespace: &djangoNameSpace,
			Name:      "django",
		},
		pkgMatchType: &model.MatchFlags{
			Pkg: model.PkgMatchTypeAllVersions,
		},
		certifyBad: model.CertifyBadInputSpec{
			Justification: "this package (all versions) is a known typo-squat",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	}, {
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
	}, {
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
	}}
	for _, ingest := range ingestCertifyBad {
		if ingest.pkg != nil {
			_, err := model.CertifyBadPkg(context.Background(), client, *ingest.pkg, ingest.pkgMatchType, ingest.certifyBad)
			if err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.source != nil {
			_, err := model.CertifyBadSrc(context.Background(), client, *ingest.source, ingest.certifyBad)
			if err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.artifact != nil {
			_, err := model.CertifyBadArtifact(context.Background(), client, *ingest.artifact, ingest.certifyBad)
			if err != nil {
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
		pkgMatchType *model.MatchFlags
		source       *model.SourceInputSpec
		artifact     *model.ArtifactInputSpec
		certifyGood  model.CertifyGoodInputSpec
	}{{
		name: "this package as this specific version has been audited",
		pkg: &model.PkgInputSpec{
			Type:       "conan",
			Namespace:  &opensslNs,
			Name:       "openssl",
			Version:    &opensslVersion,
			Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
		},
		pkgMatchType: &model.MatchFlags{
			Pkg: model.PkgMatchTypeSpecificVersion,
		},
		certifyGood: model.CertifyGoodInputSpec{
			Justification: "this package as this specific version has been audited",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	}, {
		name: "this package (all versions) is trusted",
		pkg: &model.PkgInputSpec{
			Type:      "pypi",
			Namespace: &djangoNameSpace,
			Name:      "django",
		},
		pkgMatchType: &model.MatchFlags{
			Pkg: model.PkgMatchTypeAllVersions,
		},
		certifyGood: model.CertifyGoodInputSpec{
			Justification: "this package (all versions) is trusted",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	}, {
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
	}, {
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
	}, {
		name: "this package as this specific version has been audited (duplicate)",
		pkg: &model.PkgInputSpec{
			Type:       "conan",
			Namespace:  &opensslNs,
			Name:       "openssl",
			Version:    &opensslVersion,
			Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
		},
		pkgMatchType: &model.MatchFlags{
			Pkg: model.PkgMatchTypeSpecificVersion,
		},
		certifyGood: model.CertifyGoodInputSpec{
			Justification: "this package as this specific version has been audited",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	}, {
		name: "this package (all versions) is trusted (duplicate)",
		pkg: &model.PkgInputSpec{
			Type:      "pypi",
			Namespace: &djangoNameSpace,
			Name:      "django",
		},
		pkgMatchType: &model.MatchFlags{
			Pkg: model.PkgMatchTypeAllVersions,
		},
		certifyGood: model.CertifyGoodInputSpec{
			Justification: "this package (all versions) is trusted",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	}, {
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
	}, {
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
	}}
	for _, ingest := range ingestCertifyGood {
		if ingest.pkg != nil {
			_, err := model.CertifyGoodPkg(context.Background(), client, *ingest.pkg, ingest.pkgMatchType, ingest.certifyGood)
			if err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.source != nil {
			_, err := model.CertifyGoodSrc(context.Background(), client, *ingest.source, ingest.certifyGood)
			if err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.artifact != nil {
			_, err := model.CertifyGoodArtifact(context.Background(), client, *ingest.artifact, ingest.certifyGood)
			if err != nil {
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
	}{{
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
	}, {
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
	}}
	for _, ingest := range ingestHashEqual {
		_, err := model.HashEqual(context.Background(), client, ingest.artifact, ingest.equalArtifact, ingest.hashEqual)
		if err != nil {
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
	}{{
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
			Annotations: []model.AnnotationInputSpec{
				{
					Key:   "scorecard",
					Value: "7",
				},
			},
			Origin:    "Demo ingestion",
			Collector: "Demo ingestion",
		},
	}, {
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
			Annotations: []model.AnnotationInputSpec{
				{
					Key:   "scorecard",
					Value: "10",
				},
			},
			Origin:    "Demo ingestion",
			Collector: "Demo ingestion",
		},
	}, {
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
			Annotations: []model.AnnotationInputSpec{
				{
					Key:   "scorecard",
					Value: "7",
				},
			},
			Origin:    "Demo ingestion",
			Collector: "Demo ingestion",
		},
	}, {
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
			Annotations: []model.AnnotationInputSpec{
				{
					Key:   "scorecard",
					Value: "10",
				},
			},
			Origin:    "Demo ingestion",
			Collector: "Demo ingestion",
		},
	}}
	for _, ingest := range ingestHasSBOM {
		if ingest.pkg != nil {
			_, err := model.HasSBOMPkg(context.Background(), client, *ingest.pkg, ingest.hasSBOM)
			if err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.artifact != nil {
			_, err := model.HasSBOMArtifact(context.Background(), client, *ingest.artifact, ingest.hasSBOM)
			if err != nil {
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
	}{{
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
	}, {
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
	}, {
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
	}}
	for _, ingest := range ingestHasSourceAt {
		_, err := model.HasSourceAt(context.Background(), client, ingest.pkg, ingest.pkgMatchType, ingest.source, ingest.hasSourceAt)
		if err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
	}
}

func ingestIsVulnerability(ctx context.Context, client graphql.Client) {

	logger := logging.FromContext(ctx)

	ingestIsVulnerability := []struct {
		name            string
		osv             *model.OSVInputSpec
		cve             *model.CVEInputSpec
		ghsa            *model.GHSAInputSpec
		isVulnerability model.IsVulnerabilityInputSpec
	}{{
		name: "OSV maps to CVE",
		osv: &model.OSVInputSpec{
			OsvId: "CVE-2019-13110",
		},
		cve: &model.CVEInputSpec{
			Year:  2019,
			CveId: "CVE-2019-13110",
		},
		isVulnerability: model.IsVulnerabilityInputSpec{
			Justification: "OSV maps to CVE",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	}, {
		name: "OSV maps to GHSA",
		osv: &model.OSVInputSpec{
			OsvId: "GHSA-h45f-rjvw-2rv2",
		},
		ghsa: &model.GHSAInputSpec{
			GhsaId: "GHSA-h45f-rjvw-2rv2",
		},
		isVulnerability: model.IsVulnerabilityInputSpec{
			Justification: "OSV maps to GHSA",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	}, {
		name: "OSV maps to CVE (duplicate)",
		osv: &model.OSVInputSpec{
			OsvId: "CVE-2019-13110",
		},
		cve: &model.CVEInputSpec{
			Year:  2019,
			CveId: "CVE-2019-13110",
		},
		isVulnerability: model.IsVulnerabilityInputSpec{
			Justification: "OSV maps to CVE",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	}, {
		name: "OSV maps to GHSA (duplicate)",
		osv: &model.OSVInputSpec{
			OsvId: "GHSA-h45f-rjvw-2rv2",
		},
		ghsa: &model.GHSAInputSpec{
			GhsaId: "GHSA-h45f-rjvw-2rv2",
		},
		isVulnerability: model.IsVulnerabilityInputSpec{
			Justification: "OSV maps to GHSA",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	}}
	for _, ingest := range ingestIsVulnerability {
		if ingest.cve != nil {
			_, err := model.IsVulnerabilityCVE(context.Background(), client, *ingest.osv, *ingest.cve, ingest.isVulnerability)
			if err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else if ingest.ghsa != nil {
			_, err := model.IsVulnerabilityGHSA(context.Background(), client, *ingest.osv, *ingest.ghsa, ingest.isVulnerability)
			if err != nil {
				logger.Errorf("Error in ingesting: %v\n", err)
			}
		} else {
			fmt.Printf("input missing for cve or ghsa")
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
		cve          *model.CVEInputSpec
		ghsa         *model.GHSAInputSpec
		osv          *model.OSVInputSpec
		vexStatement model.VexStatementInputSpec
	}{{
		name: "this package is not vulnerable to this OSV",
		pkg: &model.PkgInputSpec{
			Type:       "conan",
			Namespace:  &opensslNs,
			Name:       "openssl",
			Version:    &opensslVersion,
			Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
		},
		osv: &model.OSVInputSpec{
			OsvId: "CVE-2019-14750",
		},
		vexStatement: model.VexStatementInputSpec{
			Status:           model.VexStatusFixed,
			VexJustification: model.VexJustificationNotProvided,
			KnownSince:       tm,
			Origin:           "Demo ingestion",
			Collector:        "Demo ingestion",
		},
	}, {
		name: "this package is not vulnerable to this CVE",
		pkg: &model.PkgInputSpec{
			Type:       "conan",
			Namespace:  &opensslNs,
			Name:       "openssl",
			Version:    &opensslVersion,
			Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
		},
		cve: &model.CVEInputSpec{
			Year:  2019,
			CveId: "CVE-2019-13110",
		},
		vexStatement: model.VexStatementInputSpec{
			Status:           model.VexStatusAffected,
			VexJustification: model.VexJustificationNotProvided,
			Statement:        "this package is vulnerable to this CVE",
			KnownSince:       tm,
			Origin:           "Demo ingestion",
			Collector:        "Demo ingestion",
		},
	}, {
		name: "this package is not vulnerable to this GHSA",
		pkg: &model.PkgInputSpec{
			Type:       "conan",
			Namespace:  &opensslNs,
			Name:       "openssl",
			Version:    &opensslVersion,
			Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
		},
		ghsa: &model.GHSAInputSpec{
			GhsaId: "GHSA-h45f-rjvw-2rv2",
		},
		vexStatement: model.VexStatementInputSpec{
			Status:           model.VexStatusNotAffected,
			VexJustification: model.VexJustificationComponentNotPresent,
			KnownSince:       tm,
			Origin:           "Demo ingestion",
			Collector:        "Demo ingestion",
		},
	}, {
		name: "this artifact is not vulnerable to this OSV",
		artifact: &model.ArtifactInputSpec{
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
			Algorithm: "sha256",
		},
		osv: &model.OSVInputSpec{
			OsvId: "CVE-2018-15710",
		},
		vexStatement: model.VexStatementInputSpec{
			Status:           model.VexStatusUnderInvestigation,
			VexJustification: model.VexJustificationNotProvided,
			KnownSince:       tm,
			Origin:           "Demo ingestion",
			Collector:        "Demo ingestion",
		},
	}, {
		name: "this artifact is not vulnerable to this CVE",
		artifact: &model.ArtifactInputSpec{
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
			Algorithm: "sha256",
		},
		cve: &model.CVEInputSpec{
			Year:  2018,
			CveId: "CVE-2018-43610",
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
	}, {
		name: "this artifact is not vulnerable to this GHSA",
		artifact: &model.ArtifactInputSpec{
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
			Algorithm: "sha256",
		},
		ghsa: &model.GHSAInputSpec{
			GhsaId: "GHSA-hj5f-4gvw-4rv2",
		},
		vexStatement: model.VexStatementInputSpec{
			Status:           model.VexStatusNotAffected,
			VexJustification: model.VexJustificationVulnerableCodeNotInExecutePath,
			KnownSince:       tm,
			Origin:           "Demo ingestion",
			Collector:        "Demo ingestion",
		},
	}, {
		name: "this package is not vulnerable to this OSV (duplicate)",
		pkg: &model.PkgInputSpec{
			Type:       "conan",
			Namespace:  &opensslNs,
			Name:       "openssl",
			Version:    &opensslVersion,
			Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
		},
		osv: &model.OSVInputSpec{
			OsvId: "CVE-2019-14750",
		},
		vexStatement: model.VexStatementInputSpec{
			Status:           model.VexStatusFixed,
			VexJustification: model.VexJustificationNotProvided,
			KnownSince:       tm,
			Origin:           "Demo ingestion",
			Collector:        "Demo ingestion",
		},
	}, {
		name: "this package is not vulnerable to this CVE (duplicate)",
		pkg: &model.PkgInputSpec{
			Type:       "conan",
			Namespace:  &opensslNs,
			Name:       "openssl",
			Version:    &opensslVersion,
			Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
		},
		cve: &model.CVEInputSpec{
			Year:  2019,
			CveId: "CVE-2019-13110",
		},
		vexStatement: model.VexStatementInputSpec{
			Status:           model.VexStatusAffected,
			VexJustification: model.VexJustificationNotProvided,
			Statement:        "this package is vulnerable to this CVE",
			KnownSince:       tm,
			Origin:           "Demo ingestion",
			Collector:        "Demo ingestion",
		},
	}, {
		name: "this package is not vulnerable to this GHSA (duplicate)",
		pkg: &model.PkgInputSpec{
			Type:       "conan",
			Namespace:  &opensslNs,
			Name:       "openssl",
			Version:    &opensslVersion,
			Qualifiers: []model.PackageQualifierInputSpec{{Key: "user", Value: "bincrafters"}, {Key: "channel", Value: "stable"}},
		},
		ghsa: &model.GHSAInputSpec{
			GhsaId: "GHSA-h45f-rjvw-2rv2",
		},
		vexStatement: model.VexStatementInputSpec{
			Status:           model.VexStatusNotAffected,
			VexJustification: model.VexJustificationComponentNotPresent,
			KnownSince:       tm,
			Origin:           "Demo ingestion",
			Collector:        "Demo ingestion",
		},
	}, {
		name: "this artifact is not vulnerable to this OSV (duplicate)",
		artifact: &model.ArtifactInputSpec{
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
			Algorithm: "sha256",
		},
		osv: &model.OSVInputSpec{
			OsvId: "CVE-2018-15710",
		},
		vexStatement: model.VexStatementInputSpec{
			Status:           model.VexStatusUnderInvestigation,
			VexJustification: model.VexJustificationNotProvided,
			KnownSince:       tm,
			Origin:           "Demo ingestion",
			Collector:        "Demo ingestion",
		},
	}, {
		name: "this artifact is not vulnerable to this CVE (duplicate)",
		artifact: &model.ArtifactInputSpec{
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
			Algorithm: "sha256",
		},
		cve: &model.CVEInputSpec{
			Year:  2018,
			CveId: "CVE-2018-43610",
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
	}, {
		name: "this artifact is not vulnerable to this GHSA (duplicate)",
		artifact: &model.ArtifactInputSpec{
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
			Algorithm: "sha256",
		},
		ghsa: &model.GHSAInputSpec{
			GhsaId: "GHSA-hj5f-4gvw-4rv2",
		},
		vexStatement: model.VexStatementInputSpec{
			Status:           model.VexStatusNotAffected,
			VexJustification: model.VexJustificationVulnerableCodeNotInExecutePath,
			KnownSince:       tm,
			Origin:           "Demo ingestion",
			Collector:        "Demo ingestion",
		},
	}}
	for _, ingest := range ingestCertifyVex {
		if ingest.pkg != nil {
			if ingest.cve != nil {
				_, err := model.VexPackageAndCve(context.Background(), client, *ingest.pkg, *ingest.cve, ingest.vexStatement)
				if err != nil {
					logger.Errorf("Error in ingesting: %v\n", err)
				}
			} else if ingest.ghsa != nil {
				_, err := model.VEXPackageAndGhsa(context.Background(), client, *ingest.pkg, *ingest.ghsa, ingest.vexStatement)
				if err != nil {
					logger.Errorf("Error in ingesting: %v\n", err)
				}
			} else if ingest.osv != nil {
				_, err := model.VexPackageAndOsv(context.Background(), client, *ingest.pkg, *ingest.osv, ingest.vexStatement)
				if err != nil {
					logger.Errorf("Error in ingesting: %v\n", err)
				}
			} else {
				fmt.Printf("input missing for cve, ghsa or osv")
			}
		} else if ingest.artifact != nil {
			if ingest.cve != nil {
				_, err := model.VexArtifactAndCve(context.Background(), client, *ingest.artifact, *ingest.cve, ingest.vexStatement)
				if err != nil {
					logger.Errorf("Error in ingesting: %v\n", err)
				}
			} else if ingest.ghsa != nil {
				_, err := model.VexArtifactAndGhsa(context.Background(), client, *ingest.artifact, *ingest.ghsa, ingest.vexStatement)
				if err != nil {
					logger.Errorf("Error in ingesting: %v\n", err)
				}
			} else if ingest.osv != nil {
				_, err := model.VexArtifactAndOsv(context.Background(), client, *ingest.artifact, *ingest.osv, ingest.vexStatement)
				if err != nil {
					logger.Errorf("Error in ingesting: %v\n", err)
				}
			} else {
				fmt.Printf("input missing for cve, ghsa or osv")
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
		art               model.ArtifactInputSpec
		occurrence        model.IsOccurrenceInputSpec
		source            model.SourceInputSpec
		hasSourceAt       model.HasSourceAtInputSpec
		sourceArt         model.ArtifactInputSpec
		sourceOccurrence  model.IsOccurrenceInputSpec
		cve               *model.CVEInputSpec
		vulnerability     model.VulnerabilityMetaDataInput
	}{{
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
		cve: &model.CVEInputSpec{
			Year:  2019,
			CveId: "CVE-2019-13110",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    time.Now(),
			DbUri:          "MITRE",
			DbVersion:      "v1.0.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}}
	for _, ingest := range ingestDependencies {
		_, err := model.IsDependency(context.Background(), client, ingest.pkg, ingest.depPkg, ingest.dependency)
		if err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
		_, err = model.IsOccurrencePkg(context.Background(), client, ingest.depPkgWithVersion, ingest.art, ingest.occurrence)
		if err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
		_, err = model.HasSourceAt(context.Background(), client, ingest.depPkgWithVersion, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}, ingest.source, ingest.hasSourceAt)
		if err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
		_, err = model.IsOccurrenceSrc(context.Background(), client, ingest.source, ingest.sourceArt, ingest.sourceOccurrence)
		if err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
		_, err = model.CertifyCVE(context.Background(), client, ingest.depPkgWithVersion, *ingest.cve, ingest.vulnerability)
		if err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
	}
}
