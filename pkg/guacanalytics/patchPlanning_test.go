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

package guacanalytics

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/Khan/genqlient/graphql"
	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/backends/inmem"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
	"github.com/guacsec/guac/pkg/logging"
)

var (
	isDependencySimpleGraph = assembler.IngestPredicates{

		IsDependency: []assembler.IsDependencyIngest{

			{
				Pkg: &model.PkgInputSpec{
					Type:      "deb",
					Namespace: ptrfrom.String("ubuntu"),
					Name:      "dpkg",
					Version:   ptrfrom.String("1.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "conan",
					Namespace: ptrfrom.String("openssl.org"),
					Name:      "openssl",
					Version:   ptrfrom.String("3.0.3"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   ">=1.19.0",
					DependencyType: model.DependencyTypeDirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "top",
					Namespace: ptrfrom.String("topns"),
					Name:      "toppkg",
					Version:   ptrfrom.String("1.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "deb",
					Namespace: ptrfrom.String("ubuntu"),
					Name:      "dpkg",
					Version:   ptrfrom.String("1.19.0"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   ">=1.19.0",
					DependencyType: model.DependencyTypeDirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
			// {
			// 	Pkg: &model.PkgInputSpec{
			// 		Type:      "top1",
			// 		Namespace: ptrfrom.String("topns1"),
			// 		Name:      "toppkg1",
			// 		Version:   ptrfrom.String("1.19.0"),
			// 	},
			// 	DepPkg: &model.PkgInputSpec{
			// 		Type:      "top",
			// 		Namespace: ptrfrom.String("topns"),
			// 		Name:      "toppkg",
			// 		Version:   ptrfrom.String("1.19.0"),
			// 	},
			// 	IsDependency: &model.IsDependencyInputSpec{
			// 		VersionRange:   ">=1.19.0",
			// 		DependencyType: model.DependencyTypeDirect,
			// 		Justification:  "test justification one",
			// 		Origin:         "Demo ingestion",
			// 		Collector:      "Demo ingestion",
			// 	},
			// },
			// {
			// 	Pkg: &model.PkgInputSpec{
			// 		Type:      "top2",
			// 		Namespace: ptrfrom.String("topns2"),
			// 		Name:      "toppkg2",
			// 		Version:   ptrfrom.String("1.19.0"),
			// 	},
			// 	DepPkg: &model.PkgInputSpec{
			// 		Type:      "top",
			// 		Namespace: ptrfrom.String("topns"),
			// 		Name:      "toppkg",
			// 		Version:   ptrfrom.String("1.19.0"),
			// 	},
			// 	IsDependency: &model.IsDependencyInputSpec{
			// 		VersionRange:   ">=1.19.0",
			// 		DependencyType: model.DependencyTypeIndirect,
			// 		Justification:  "test justification one",
			// 		Origin:         "Demo ingestion",
			// 		Collector:      "Demo ingestion",
			// 	},
			// },
			// {
			// 	Pkg: &model.PkgInputSpec{
			// 		Type:      "deb",
			// 		Namespace: ptrfrom.String("ubuntu"),
			// 		Name:      "dpkg",
			// 		Version:   ptrfrom.String("1.19.0"),
			// 	},
			// 	DepPkg: &model.PkgInputSpec{
			// 		Type:      "conan2",
			// 		Namespace: ptrfrom.String("openssl.org2"),
			// 		Name:      "openssl2",
			// 		Version:   ptrfrom.String("3.0.3"),
			// 	},
			// 	IsDependency: &model.IsDependencyInputSpec{
			// 		VersionRange:   ">=1.19.0",
			// 		DependencyType: model.DependencyTypeDirect,
			// 		Justification:  "test justification one",
			// 		Origin:         "Demo ingestion",
			// 		Collector:      "Demo ingestion",
			// 	},
			// },
			{
				Pkg: &model.PkgInputSpec{
					Type:      "extraType",
					Namespace: ptrfrom.String("extraNamespace"),
					Name:      "extraName",
					Version:   ptrfrom.String("1.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "conan3",
					Namespace: ptrfrom.String("openssl.org3"),
					Name:      "openssl3",
					Version:   ptrfrom.String("3.0.3"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   "=1.19.0",
					DependencyType: model.DependencyTypeDirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
		},
	}
)

func ingestIsDependency(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {

	for _, ingest := range graph.IsDependency {
		_, err := model.IngestPackage(context.Background(), client, *ingest.Pkg)

		if err != nil {
			return fmt.Errorf("Error in ingesting package: %v\n", err)
		}

		_, err = model.IngestPackage(context.Background(), client, *ingest.DepPkg)

		if err != nil {
			return fmt.Errorf("Error in ingesting dependent package: %v\n", err)
		}
		_, err = model.IsDependency(context.Background(), client, *ingest.Pkg, *ingest.DepPkg, *ingest.IsDependency)

		if err != nil {
			return fmt.Errorf("Error in ingesting isDependency: %v\n", err)
		}
	}
	return nil
}

func ingestTestData(ctx context.Context, client graphql.Client, graphInput string) error {
	switch graphInput {
	case "isDependencySimpleGraph":
		err := ingestIsDependency(ctx, client, isDependencySimpleGraph)
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("Graph input did not match any test graph")
}

func Test_SearchSubgraphFromVuln(t *testing.T) {
	server := startTestServer()

	ctx := logging.WithLogger(context.Background())

	httpClient := http.Client{}
	gqlclient := graphql.NewClient("http://localhost:9090/query", &httpClient)

	testCases := []struct {
		name           string
		startType      string
		startNamespace *string
		startName      string
		startVersion   *string
		stopType       string
		stopNamespace  *string
		stopName       string
		stopVersion    *string
		maxDepth       int
		expectedLen    int
		graphInput     string
	}{

		{
			name:           "1: test case with two dependencies at the same depth, no stopID and no limiting maxDepth",
			startType:      "conan",
			startNamespace: ptrfrom.String("openssl.org"),
			startName:      "openssl",
			startVersion:   ptrfrom.String("3.0.3"),
			stopType:       "",
			maxDepth:       10,
			expectedLen:    4,
			graphInput:     "isDependencySimpleGraph",
		},
		// {
		// 	name:           "2: two levels of dependencies, no stopID and no limiting maxDepth",
		// 	startType:      "top",
		// 	startNamespace: ptrfrom.String("topns"),
		// 	startName:      "toppkg",
		// 	startVersion:   ptrfrom.String("1.19.0"),
		// 	stopType:       "",
		// 	maxDepth:       10,
		// 	expectedLen:    4,
		// 	graphInput:     "isDependency",
		// },

		// {
		// 	name:           "3: two levels of dependencies, a stopID at the first level and no limiting maxDepth",
		// 	startType:      "top",
		// 	startNamespace: ptrfrom.String("topns"),
		// 	startName:      "toppkg",
		// 	startVersion:   ptrfrom.String("1.19.0"),
		// 	stopType:       "deb",
		// 	stopNamespace:  ptrfrom.String("ubuntu"),
		// 	stopName:       "dpkg",
		// 	stopVersion:    ptrfrom.String("1.19.0"),
		// 	maxDepth:       10,
		// 	expectedLen:    2,
		// 	graphInput:     "isDependency",
		// },

		// {
		// 	name:           "4: two levels of dependencies, no stopID and a limiting maxDepth at the first level",
		// 	startType:      "top1",
		// 	startNamespace: ptrfrom.String("topns1"),
		// 	startName:      "toppkg1",
		// 	startVersion:   ptrfrom.String("1.19.0"),
		// 	stopType:       "",
		// 	maxDepth:       1,
		// 	expectedLen:    2,
		// 	graphInput:     "isDependency",
		// },
		// {
		// 	name:           "5: isDependency indirect dependency",
		// 	startType:      "top2",
		// 	startNamespace: ptrfrom.String("topns2"),
		// 	startName:      "toppkg2",
		// 	startVersion:   ptrfrom.String("1.19.0"),
		// 	stopType:       "",
		// 	maxDepth:       10,
		// 	expectedLen:    5,
		// 	graphInput:     "isDependency",
		// },
		// {
		// 	name:           "6: direct isDependency not included in range",
		// 	startType:      "extraType",
		// 	startNamespace: ptrfrom.String("extraNamespace"),
		// 	startName:      "extraName",
		// 	startVersion:   ptrfrom.String("1.19.0"),
		// 	stopType:       "",
		// 	maxDepth:       10,
		// 	expectedLen:    1,
		// 	graphInput:     "isDependency",
		// },
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("Test case %s\n", tt.name), func(t *testing.T) {
			ingestTestData(ctx, gqlclient, tt.graphInput)
			startID := getPackageId(ctx, gqlclient, "isDependency", tt.startType, tt.startNamespace, tt.startName, tt.startVersion)

			var stopID string
			if tt.stopType != "" {
				stopID = getPackageId(ctx, gqlclient, "isDependency", tt.stopType, tt.stopNamespace, tt.stopName, tt.stopVersion)
			} else {
				stopID = ""
			}

			gotMap, err := SearchDependenciesFromStartNode(ctx, gqlclient, startID, stopID, tt.maxDepth)

			if err != nil {
				t.Errorf("got err from SearchDependenciesFromStartNode: %v", err)
				return
			}

			if stopID == "" && tt.maxDepth == 10 {
				for k, v := range gotMap {
					if !v.Expanded {
						t.Errorf("All nodes should be expanded but this node was not: node %s \n", k)
					}

					fmt.Printf("key: %s\n", k)
				}
			}

			if diff := cmp.Diff(tt.expectedLen, len(gotMap)); len(diff) > 0 {
				t.Errorf("Number of map entries (-want +got):\n%s", diff)
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
		cf()
		server.Close()
	}
	cf()
}

func startTestServer() *http.Server {
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
	return server
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

func getPackageId(ctx context.Context, gqlclient graphql.Client, graph string, nodeType string, nodeNamespace *string, nodeName string, nodeVersion *string) string {
	pkgFilter := &model.PkgSpec{
		Type:      &nodeType,
		Namespace: nodeNamespace,
		Name:      &nodeName,
		Version:   nodeVersion,
	}
	pkgResponse, err := model.Packages(ctx, gqlclient, pkgFilter)

	if err != nil {
		fmt.Printf("Error getting id for isDependency test case: %s\n", err)
		return ""
	}

	fmt.Printf(pkgResponse.Packages[0].Namespaces[0].Names[0].Name)
	return pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id
}
