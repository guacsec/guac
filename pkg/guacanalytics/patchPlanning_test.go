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
	"testing"
	"time"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"go.uber.org/zap"

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

	ns1 := "test_namespace1"
	version1 := "6.1.3"
	depns1 := "test_dep_namespace1"
	ns2 := "test_namespace2"

	ingestDependencies := []struct {
		name       string
		pkg        model.PkgInputSpec
		depPkg     model.PkgInputSpec
		dependency model.IsDependencyInputSpec
	}{{
		name: "part of SBOM",
		pkg: model.PkgInputSpec{
			Type:      "type1",
			Namespace: &ns1,
			Name:      "test_dpkg1",
			Version:   &version1,
			Qualifiers: []model.PackageQualifierInputSpec{
				{Key: "test_key", Value: "test_val"},
			},
		},
		depPkg: model.PkgInputSpec{
			Type:      "dep_type1",
			Namespace: &depns1,
			Name:      "dep_name1",
		},
		dependency: model.IsDependencyInputSpec{
			VersionRange:   ">3.0.3",
			DependencyType: model.DependencyTypeDirect,
			Justification:  "part of SBOM",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "part of SBOM",
		pkg: model.PkgInputSpec{
			Type:      "type2",
			Namespace: &ns2,
			Name:      "name2",
		},
		depPkg: model.PkgInputSpec{
			Type:      "dep_type2",
			Namespace: &depns1,
			Name:      "dep_name2",
		},
		dependency: model.IsDependencyInputSpec{
			VersionRange:   "<3.0.3",
			DependencyType: model.DependencyTypeIndirect,
			Justification:  "docker: part of SBOM - openssl",
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
	tm, _ := time.Parse(time.RFC3339, "2023-11-14T17:45:50.52Z")

	ns1 := "test_namespace1"
	version := "4.0"
	ns2 := "test_namespace2"

	ingestVulnerabilities := []struct {
		name          string
		pkg           *model.PkgInputSpec
		cve           *model.CVEInputSpec
		osv           *model.OSVInputSpec
		ghsa          *model.GHSAInputSpec
		vulnerability model.VulnerabilityMetaDataInput
	}{{
		name: "cve",
		pkg: &model.PkgInputSpec{
			Type:      "test_type1",
			Namespace: &ns1,
			Name:      "test_name1",
			Version:   &version,
			Qualifiers: []model.PackageQualifierInputSpec{
				{Key: "test_user", Value: "test_bincrafters"},
				{Key: "test_channel", Value: "test_stable"},
			},
		},
		cve: &model.CVEInputSpec{
			Year:  2019,
			CveId: "CVE-2023-61300",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "URI",
			DbVersion:      "v4.0.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "osv",
		pkg: &model.PkgInputSpec{
			Type:      "test_type1",
			Namespace: &ns1,
			Name:      "test_name1",
			Version:   &version,
			Qualifiers: []model.PackageQualifierInputSpec{
				{Key: "test_user", Value: "test_bincrafters"},
				{Key: "test_channel", Value: "test_stable"},
			},
		},
		osv: &model.OSVInputSpec{
			OsvId: "CVE-2023-61300",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "URI",
			DbVersion:      "v4.0.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "ghsa openssl",
		pkg: &model.PkgInputSpec{
			Type:      "test_type1",
			Namespace: &ns1,
			Name:      "openssl",
			Version:   &version,
			Qualifiers: []model.PackageQualifierInputSpec{
				{Key: "test_user", Value: "test_bincrafters"},
				{Key: "test_channel", Value: "test_stable"},
			},
		},
		ghsa: &model.GHSAInputSpec{
			GhsaId: "GHSA-h45f-rjvw-2rv2",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "URI",
			DbVersion:      "v4.0.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "cve django",
		pkg: &model.PkgInputSpec{
			Type:      "pypi",
			Namespace: &ns2,
			Name:      "test_name2",
		},
		cve: &model.CVEInputSpec{
			Year:  2018,
			CveId: "CVE-2014-11000",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "URI",
			DbVersion:      "v4.2.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "osv django",
		pkg: &model.PkgInputSpec{
			Type:      "pypi",
			Namespace: &ns2,
			Name:      "name_2",
		},
		osv: &model.OSVInputSpec{
			OsvId: "CVE-2014-11000",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "URI",
			DbVersion:      "v4.2.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "ghsa django",
		pkg: &model.PkgInputSpec{
			Type:      "pypi",
			Namespace: &ns2,
			Name:      "test_name2",
		},
		ghsa: &model.GHSAInputSpec{
			GhsaId: "GHSA-f45f-jj4w-2rv2",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "URI",
			DbVersion:      "v4.2.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "cve openssl (duplicate)",
		pkg: &model.PkgInputSpec{
			Type:      "type1",
			Namespace: &ns1,
			Name:      "openssl",
			Version:   &version,
			Qualifiers: []model.PackageQualifierInputSpec{
				{Key: "test_user", Value: "test_bincrafters"},
				{Key: "test_channel", Value: "test_stable"},
			},
		},
		cve: &model.CVEInputSpec{
			Year:  2019,
			CveId: "CVE-2023-61300",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "URI",
			DbVersion:      "v4.0.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "ghsa django (duplicate)",
		pkg: &model.PkgInputSpec{
			Type:      "pypi",
			Namespace: &ns2,
			Name:      "test_name2",
		},
		ghsa: &model.GHSAInputSpec{
			GhsaId: "GHSA-f45f-jj4w-2rv2",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "URI",
			DbVersion:      "v4.2.0",
			ScannerUri:     "osv.dev",
			ScannerVersion: "0.0.14",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}, {
		name: "osv openssl (duplicate)",
		pkg: &model.PkgInputSpec{
			Type:      "type1",
			Namespace: &ns1,
			Name:      "openssl",
			Version:   &version,
			Qualifiers: []model.PackageQualifierInputSpec{
				{Key: "test_user", Value: "test_bincrafters"},
				{Key: "test_channel", Value: "test_stable"},
			},
		},
		osv: &model.OSVInputSpec{
			OsvId: "CVE-2019-13110",
		},
		vulnerability: model.VulnerabilityMetaDataInput{
			TimeScanned:    tm,
			DbUri:          "URI",
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
	type1 := "test_type1"
	ns := "test_namespace1"
	nodeName := "test_name1"
	version := "4.0"
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
	server, logger := startTestServer()
	fmt.Printf("after start server\n")
	ctx := logging.WithLogger(context.Background())

	httpClient := http.Client{}
	gqlclient := graphql.NewClient("http://localhost:9090/query", &httpClient)
	ingestVulnerabilities(ctx, gqlclient)
	ingestDependencies(ctx, gqlclient)

	pkgFilter := &model.PkgSpec{
		Type:      &type1,
		Namespace: &ns,
		Name:      &nodeName,
		Version:   &version,
	}
	pkgResponse, err := model.Packages(ctx, gqlclient, pkgFilter)

	if err != nil {
		fmt.Println("ERROR")
	}
	id := pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id

	// startTestServer()

	//for _, tt := range testCases {

	// t.Run("test1", func(t *testing.T) {
	_, map1, err := searchSubgraphFromVuln(ctx, gqlclient, id, "", 2)
	if err != nil {
		t.Errorf("got err from Search: %v", err)
		return
	} else {
		for k, m := range map1 {
			fmt.Println(k, "value is", m)
		}
	}
	// })
	// }

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

func startTestServer() (*http.Server, *zap.SugaredLogger) {
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
	// sigs := make(chan os.Signal, 1)
	// signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM) // don't need for testing
	// s := <-sigs
	// logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
	return server, logger
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
