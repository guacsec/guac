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
	ingestDependency(ctx, gqlclient)
	ingestOccurrence(ctx, gqlclient)
	ingestVulnerability(ctx, gqlclient)
	ingestCertifyPkg(ctx, gqlclient)
	time := time.Now().Sub(start)
	logger.Infof("Ingesting test data into backend server took %v", time)
}

func ingestScorecards(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)

	tag := "v2.12.0"
	source := model.SourceInputSpec{
		Type:      "git",
		Namespace: "github",
		Name:      "github.com/tensorflow/tensorflow",
		Tag:       &tag,
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
			VersionRange:  "3.0.3",
			Justification: "deb: part of SBOM - openssl",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
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
			VersionRange:  "3.0.3",
			Justification: "docker: part of SBOM - openssl",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
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
			Year:  "2019",
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
			TimeScanned:    time.Now(),
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
			TimeScanned:    time.Now(),
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
			Year:  "2018",
			CveId: "CVE-2018-12310",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    time.Now(),
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
			TimeScanned:    time.Now(),
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
			TimeScanned:    time.Now(),
			DbUri:          "MITRE",
			DbVersion:      "v1.2.0",
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

func ingestCertifyPkg(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)

	opensslNs := "openssl.org"
	opensslVersion := "3.0.3"
	djangoNameSpace := ""
	djangoVersion := "1.11.1"
	djangoSubPath := "subpath"
	debianNs := "debian"
	ubuntuNs := "ubuntu"
	attrVersion := "1:2.4.47-2"

	ingestCertifyPkg := []struct {
		name       string
		pkg        model.PkgInputSpec
		depPkg     model.PkgInputSpec
		certifyPkg model.CertifyPkgInputSpec
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
		certifyPkg: model.CertifyPkgInputSpec{
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
		certifyPkg: model.CertifyPkgInputSpec{
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
		certifyPkg: model.CertifyPkgInputSpec{
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
		certifyPkg: model.CertifyPkgInputSpec{
			Justification: "these two dpkg packages are the same",
			Origin:        "Demo ingestion",
			Collector:     "Demo ingestion",
		},
	}}
	for _, ingest := range ingestCertifyPkg {
		_, err := model.CertifyPkg(context.Background(), client, ingest.pkg, ingest.depPkg, ingest.certifyPkg)
		if err != nil {
			logger.Errorf("Error in ingesting: %v\n", err)
		}
	}
}
