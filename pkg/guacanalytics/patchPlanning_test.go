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

package guacanalytics

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/guacsec/guac/pkg/assembler/backends/inmem"
	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	inmems = "inmem"
)

func ingestDependencies(ctx context.Context, client graphql.Client) {
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
		isDep      model.AllArtifactTree
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
			VersionRange:   "<3.0.3",
			DependencyType: model.DependencyTypeDirect,
			Justification:  "deb: part of SBOM - openssl",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
		isDep: model.AllArtifactTree{
			Id: "hi",
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
			VersionRange:   "<3.0.3",
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
			VersionRange:   "<3.0.3",
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

func ingestVulnerabilities(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")

	opensslNs := "openssl.org"
	opensslVersion := "3.0"
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

func Test_SearchSubgraphFromVuln(t *testing.T) {
	// testCases := []struct {
	// 	vulnID      string
	// 	retNodeList []string
	// 	retNodeMap  map[string]dfsNode
	// }{
	// 	{
	// 		vulnID:      "CVE-2019-13110",
	// 		retNodeList: nil,
	// 		retNodeMap:  nil,
	// 	},
	// }
	fmt.Printf("before start server\n")
	startTestServer()
	fmt.Printf("after start server\n")
	ctx := logging.WithLogger(context.Background())

	httpClient := http.Client{}
	gqlclient := graphql.NewClient("http://localhost:9090", &httpClient)
	ingestVulnerabilities(ctx, gqlclient)
	ingestDependencies(ctx, gqlclient)
	// startTestServer()

	//for _, tt := range testCases {

	t.Run("test1", func(t *testing.T) {
		got, _, err := searchSubgraphFromVuln(ctx, gqlclient, "hi", "", 0)
		if err != nil {
			t.Errorf("got err from Search: %v", err)
			return
		} else {
			fmt.Printf("test got " + got[0])
		}
	})
	//}
}

func startTestServer() {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	srv, err := getGraphqlTestServer()
	if err != nil {
		logger.Errorf("unable to initialize graphql server: %v", err)
		os.Exit(1)
	}
	http.Handle("/query", srv)

	server := &http.Server{Addr: fmt.Sprintf(":%d", 9090)}
	logger.Info("starting server")
	go func() {
		logger.Infof("server finished: %s", server.ListenAndServe())
	}()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM) // don't need for testing
	s := <-sigs
	logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
	done := make(chan bool, 1)
	ctx, cf := context.WithCancel(ctx)
	go func() {
		_ = server.Shutdown(ctx)
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		logger.Warnf("forcibly shutting down gql http server")
		cf()
		server.Close()
	}
	cf()
}

func getGraphqlTestServer() (*handler.Server, error) {
	var topResolver resolvers.Resolver
	args := inmem.DemoCredentials{}
	backend, err := inmem.GetBackend(&args)
	if err != nil {
		return nil, fmt.Errorf("Error creating inmem backend: %w", err)
	}

	topResolver = resolvers.Resolver{Backend: backend}

	config := generated.Config{Resolvers: &topResolver}
	srv := handler.NewDefaultServer(generated.NewExecutableSchema(config))

	return srv, nil
}
