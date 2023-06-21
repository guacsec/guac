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
	"github.com/google/go-cmp/cmp"
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

func ingestTestData(ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)

	topns := "topns"
	topns1 := "topns1"
	topns2 := "topns2"
	topns3 := "topns3"
	ns := "ubuntu"
	version := "1.19.0"
	depns := "openssl.org"
	depns2 := "openssl.org2"
	opensslVersion := "3.0.3"

	ingestDependencies := []struct {
		topTopPkg1           model.PkgInputSpec
		topTopPkg2           model.PkgInputSpec
		topTopPkg3           model.PkgInputSpec
		topPkg               model.PkgInputSpec
		pkg                  model.PkgInputSpec
		depPkg1              model.PkgInputSpec
		depPkg2              model.PkgInputSpec
		dependencyDirect     model.IsDependencyInputSpec
		dependencyNotInRange model.IsDependencyInputSpec
		dependencyIndirect   model.IsDependencyInputSpec
	}{{
		topTopPkg1: model.PkgInputSpec{
			Type:      "top1",
			Namespace: &topns1,
			Name:      "toppkg1",
			Version:   &version,
		},
		topTopPkg2: model.PkgInputSpec{
			Type:      "top2",
			Namespace: &topns2,
			Name:      "toppkg2",
			Version:   &version,
		},
		topTopPkg3: model.PkgInputSpec{
			Type:      "top3",
			Namespace: &topns3,
			Name:      "toppkg3",
			Version:   &version,
		},
		topPkg: model.PkgInputSpec{
			Type:      "top",
			Namespace: &topns,
			Name:      "toppkg",
			Version:   &version,
		},
		pkg: model.PkgInputSpec{
			Type:      "deb",
			Namespace: &ns,
			Name:      "dpkg",
			Version:   &version,
			Qualifiers: []model.PackageQualifierInputSpec{
				{Key: "arch", Value: "amd64"},
			},
		},
		depPkg1: model.PkgInputSpec{
			Type:      "conan",
			Namespace: &depns,
			Name:      "openssl",
			Version:   &opensslVersion,
		},
		depPkg2: model.PkgInputSpec{
			Type:      "conan2",
			Namespace: &depns2,
			Name:      "openssl2",
			Version:   &opensslVersion,
		},
		dependencyDirect: model.IsDependencyInputSpec{
			VersionRange:   "=>1.19.0",
			DependencyType: model.DependencyTypeDirect,
			Justification:  "test justification one",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
		dependencyNotInRange: model.IsDependencyInputSpec{
			VersionRange:   "<1.19.0",
			DependencyType: model.DependencyTypeIndirect,
			Justification:  "test justification one",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
		dependencyIndirect: model.IsDependencyInputSpec{
			VersionRange:   "=>1.19.0",
			DependencyType: model.DependencyTypeIndirect,
			Justification:  "test justification one",
			Origin:         "Demo ingestion",
			Collector:      "Demo ingestion",
		},
	}}
	for _, ingest := range ingestDependencies {
		_, err1 := model.IsDependency(context.Background(), client, ingest.topPkg, ingest.pkg, ingest.dependencyDirect)
		if err1 != nil {
			logger.Errorf("Error in ingesting: %v\n", err1)
		}
		_, err2 := model.IsDependency(context.Background(), client, ingest.pkg, ingest.depPkg1, ingest.dependencyDirect)
		if err2 != nil {
			logger.Errorf("Error in ingesting: %v\n", err2)
		}
		_, err3 := model.IsDependency(context.Background(), client, ingest.pkg, ingest.depPkg2, ingest.dependencyDirect)
		if err3 != nil {
			logger.Errorf("Error in ingesting: %v\n", err3)
		}
		_, err4 := model.IsDependency(context.Background(), client, ingest.topTopPkg1, ingest.topPkg, ingest.dependencyDirect)
		if err4 != nil {
			logger.Errorf("Error in ingesting: %v\n", err4)
		}
		_, err5 := model.IsDependency(context.Background(), client, ingest.topTopPkg2, ingest.topPkg, ingest.dependencyIndirect)
		if err5 != nil {
			logger.Errorf("Error in ingesting: %v\n", err5)
		}
		_, err6 := model.IsDependency(context.Background(), client, ingest.topTopPkg3, ingest.topPkg, ingest.dependencyNotInRange)
		if err6 != nil {
			logger.Errorf("Error in ingesting: %v\n", err5)
		}
	}
}

func Test_SearchSubgraphFromVuln(t *testing.T) {
	type1 := "deb"
	ns1 := "ubuntu"
	nodeName1 := "dpkg"
	type2 := "top"
	ns2 := "topns"
	nodeName2 := "toppkg"
	type3 := "top1"
	ns3 := "topns1"
	nodeName3 := "toppkg1"
	type4 := "top2"
	ns4 := "topns2"
	nodeName4 := "toppkg2"
	type5 := "top3"
	ns5 := "topns3"
	nodeName5 := "toppkg3"

	server, logger := startTestServer()
	ctx := logging.WithLogger(context.Background())

	httpClient := http.Client{}
	gqlclient := graphql.NewClient("http://localhost:9090/query", &httpClient)

	ingestTestData(ctx, gqlclient)

	// filtering for packages IDs needed to be inputted into the tests
	pkgFilter1 := &model.PkgSpec{
		Type:      &type1,
		Namespace: &ns1,
		Name:      &nodeName1,
	}

	pkgResponse1, err := model.Packages(ctx, gqlclient, pkgFilter1)

	if err != nil {
		t.Errorf("Error getting first package node for test case: %s\n", err)
	}

	id1 := pkgResponse1.Packages[0].Namespaces[0].Names[0].Versions[0].Id

	pkgFilter2 := &model.PkgSpec{
		Type:      &type2,
		Namespace: &ns2,
		Name:      &nodeName2,
	}

	pkgResponse2, err := model.Packages(ctx, gqlclient, pkgFilter2)

	if err != nil {
		t.Errorf("Error getting second package node for test case: %s\n", err)
	}

	id2 := pkgResponse2.Packages[0].Namespaces[0].Names[0].Versions[0].Id

	pkgFilter3 := &model.PkgSpec{
		Type:      &type3,
		Namespace: &ns3,
		Name:      &nodeName3,
	}

	pkgResponse3, err := model.Packages(ctx, gqlclient, pkgFilter3)

	if err != nil {
		t.Errorf("Error getting third package node for test case: %s\n", err)
	}

	id3 := pkgResponse3.Packages[0].Namespaces[0].Names[0].Versions[0].Id

	pkgFilter4 := &model.PkgSpec{
		Type:      &type4,
		Namespace: &ns4,
		Name:      &nodeName4,
	}

	pkgResponse4, err := model.Packages(ctx, gqlclient, pkgFilter4)

	if err != nil {
		t.Errorf("Error getting fourth package node for test case: %s\n", err)
	}

	id4 := pkgResponse4.Packages[0].Namespaces[0].Names[0].Versions[0].Id

	pkgFilter5 := &model.PkgSpec{
		Type:      &type5,
		Namespace: &ns5,
		Name:      &nodeName5,
	}

	pkgResponse5, err := model.Packages(ctx, gqlclient, pkgFilter5)

	if err != nil {
		t.Errorf("Error getting fifth package node for  test case: %s\n", err)
	}

	id5 := pkgResponse5.Packages[0].Namespaces[0].Names[0].Versions[0].Id

	testCases := []struct {
		startID  string
		stopID   string
		maxDepth int
	}{
		{
			// test case with two dependencies at the same depth, no stopID and no limiting maxDepth
			startID:  id1,
			stopID:   "",
			maxDepth: 10,
		},
		{
			// test case with two levels of dependencies, no stopID and no limiting maxDepth
			startID:  id2,
			stopID:   "",
			maxDepth: 10,
		},
		{
			// test case with two levels of dependencies, a stopID at the first level and no limiting maxDepth
			startID:  id2,
			stopID:   id1,
			maxDepth: 10,
		},
		{
			// test case with two levels of dependencies, no stopID and a limiting maxDepth at the first level
			startID:  id3,
			stopID:   "",
			maxDepth: 1,
		},
		{
			// test case with two levels of dependencies, no stopID and a limiting maxDepth at the first level
			startID:  id3,
			stopID:   "",
			maxDepth: 1,
		},
		{
			// test case with indirect dependency
			startID:  id4,
			stopID:   "",
			maxDepth: 1,
		},
		{
			// test case with isDep range that does not include the dependency
			startID:  id5,
			stopID:   "",
			maxDepth: 10,
		},
	}
	for _, tt := range testCases {
		gotMap, err := searchDependenciesFromStartNode(ctx, gqlclient, tt.startID, tt.stopID, tt.maxDepth)

		t.Run("testing searchDependenciesFromStartNode", func(t *testing.T) {
			if err != nil {
				t.Errorf("got err from searchDependenciesFromStartNode: %v", err)
				return
			}

			if tt.stopID == "" && tt.maxDepth == 10 {
				for k, v := range gotMap {
					if !v.expanded {
						t.Errorf("All nodes should be expanded but this node was not: node %s \n", k)
					}
				}
			}

			if tt.startID == id1 {
				if diff := cmp.Diff(3, len(gotMap)); len(diff) > 0 {
					t.Errorf("Number of map entries (-want +got):\n%s", diff)
				}

				for k, v := range gotMap {
					if k != id1 && (v.parent != id1 || v.depth != 1) {
						t.Errorf("Incorrect dependency node entry")
					} else if k == id1 && (v.parent != "" || v.depth != 0) {
						t.Errorf("Incorrect starting node entry")
					}
				}
			}

			if tt.startID == id2 && tt.stopID == "" && tt.maxDepth == 10 {
				if diff := cmp.Diff(4, len(gotMap)); len(diff) > 0 {
					t.Errorf("Number of map entries (-want +got):\n%s", diff)
				}

				for k, v := range gotMap {
					if k == id2 && (v.parent != "" || v.depth != 0) {
						t.Errorf("Incorrect starting node entry")
					} else if k == id1 && (v.parent != id2 || v.depth != 1) {
						t.Errorf("Incorrect second node entry")
					} else if v.parent == id1 && v.depth != 2 {
						t.Errorf("Incorrect third or fourth node entry")
					}
				}
			}

			if tt.startID == id2 && tt.stopID == id1 {
				if diff := cmp.Diff(2, len(gotMap)); len(diff) > 0 {
					t.Errorf("Number of map entries (-want +got):\n%s", diff)
				}

				for k, v := range gotMap {
					if k == id2 && (v.parent != "" || v.depth != 0) {
						t.Errorf("Incorrect starting node entry")
					} else if k == id1 && (v.parent != id2 || v.depth != 1) {
						t.Errorf("Incorrect second node entry")
					}
				}
			}

			if tt.startID == id3 {
				if diff := cmp.Diff(2, len(gotMap)); len(diff) > 0 {
					t.Errorf("Number of map entries (-want +got):\n%s", diff)
				}

				for k, v := range gotMap {
					if k == id3 && (v.parent != "" || v.depth != 0) {
						t.Errorf("Incorrect starting node entry")
					} else if k == id2 && (v.parent != id3 || v.depth != 1) {
						t.Errorf("Incorrect second node entry")
					}
				}
			}

			if tt.startID == id4 {
				if diff := cmp.Diff(2, len(gotMap)); len(diff) > 0 {
					t.Errorf("Number of map entries (-want +got):\n%s", diff)
				}

				for k, v := range gotMap {
					if k == id4 && (v.parent != "" || v.depth != 0) {
						t.Errorf("Incorrect starting node entry")
					} else if k == id2 && (v.parent != id4 || v.depth != 1) {
						t.Errorf("Incorrect second node entry")
					}
				}
			}

			if tt.startID == id5 {
				if diff := cmp.Diff(1, len(gotMap)); len(diff) > 0 {
					t.Errorf("Number of map entries (-want +got):\n%s", diff)
				}

				for k, v := range gotMap {
					if k == id1 && (v.parent != "" || v.depth != 0) {
						t.Errorf("Incorrect starting node entry")
					}
				}
			}

		})
	}

	// cleaning up server instance
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
