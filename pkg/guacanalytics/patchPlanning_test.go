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
	"go.uber.org/zap"
)

var (
	isDepTestData = assembler.IngestPredicates{

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
			{
				Pkg: &model.PkgInputSpec{
					Type:      "top1",
					Namespace: ptrfrom.String("topns1"),
					Name:      "toppkg1",
					Version:   ptrfrom.String("1.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "top",
					Namespace: ptrfrom.String("topns"),
					Name:      "toppkg",
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
			{
				Pkg: &model.PkgInputSpec{
					Type:      "top2",
					Namespace: ptrfrom.String("topns2"),
					Name:      "toppkg2",
					Version:   ptrfrom.String("1.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "top",
					Namespace: ptrfrom.String("topns"),
					Name:      "toppkg",
					Version:   ptrfrom.String("1.19.0"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   ">=1.19.0",
					DependencyType: model.DependencyTypeIndirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "top3",
					Namespace: ptrfrom.String("topns3"),
					Name:      "toppkg3",
					Version:   ptrfrom.String("1.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "top",
					Namespace: ptrfrom.String("topns"),
					Name:      "toppkg",
					Version:   ptrfrom.String("1.19.0"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   "<1.19.0",
					DependencyType: model.DependencyTypeDirect,
					Justification:  "test justification one",
					Origin:         "Demo ingestion",
					Collector:      "Demo ingestion",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "deb",
					Namespace: ptrfrom.String("ubuntu"),
					Name:      "dpkg",
					Version:   ptrfrom.String("1.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "conan2",
					Namespace: ptrfrom.String("openssl.org2"),
					Name:      "openssl2",
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
		},
	}
)

func ingestTestData(graphInput string, ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)
	switch graphInput {
	case "isDependency":
		for _, ingest := range isDepTestData.IsDependency {

			_, err := model.IsDependency(context.Background(), client, *ingest.Pkg, *ingest.DepPkg, *ingest.IsDependency)

			if err != nil {

				logger.Errorf("Error in ingesting: %v\n", err)
			}
		}
	}
}

func Test_SearchConnectionsFromStartNode(t *testing.T) {
	server, logger := startTestServer()
	ctx := logging.WithLogger(context.Background())

	httpClient := http.Client{}
	gqlclient := graphql.NewClient("http://localhost:9090/query", &httpClient)

	testCases := []struct {
		name        string
		start       int
		stop        int
		maxDepth    int
		expectedLen int
		graphInput  string
	}{
		{
			name:        "1: test case with two dependencies at the same depth, no stopID and no limiting maxDepth",
			start:       0,
			stop:        -1,
			maxDepth:    10,
			expectedLen: 5,
			graphInput:  "isDependency",
		},
		{
			name:        " 2: two levels of dependencies, no stopID and no limiting maxDepth",
			start:       1,
			stop:        -1,
			maxDepth:    10,
			expectedLen: 7,
			graphInput:  "isDependency",
		},
		{
			name:        "3: two levels of dependencies, a stopID at the first level and no limiting maxDepth",
			start:       1,
			stop:        0,
			maxDepth:    10,
			expectedLen: 3,
			graphInput:  "isDependency",
		},
		{
			name:        "4: two levels of dependencies, no stopID and a limiting maxDepth at the first level",
			start:       2,
			stop:        -1,
			maxDepth:    1,
			expectedLen: 3,
			graphInput:  "isDependency",
		},
		{
			name:        "5: indirect dependency",
			start:       3,
			stop:        -1,
			maxDepth:    10,
			expectedLen: 9,
			graphInput:  "isDependency",
		},
		{
			name:        "6: isDependency range that does not include the dependency",
			start:       4,
			stop:        -1,
			maxDepth:    10,
			expectedLen: 1,
			graphInput:  "isDependency",
		},
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("test case %s\n", tt.name), func(t *testing.T) {
			ingestTestData(tt.graphInput, ctx, gqlclient)
			startID := getPackageId("isDependency", tt.start, ctx, gqlclient)

			var stopID string
			if tt.stop >= 0 {
				stopID = getPackageId("isDependency", tt.stop, ctx, gqlclient)
			} else {
				stopID = ""
			}

			gotMap, err := SearchConnectionsFromStartNode(ctx, gqlclient, startID, stopID, "packageVersion", tt.maxDepth)

			if err != nil {
				t.Errorf("got err from SearchDependenciesFromStartNode: %v", err)
				return
			}

			if stopID == "" && tt.maxDepth == 10 {
				for k, v := range gotMap {
					if !v.expanded {
						t.Errorf("All nodes should be expanded but this node was not: node %s \n", k)
					}
				}
			}

			if diff := cmp.Diff(tt.expectedLen, len(gotMap)); len(diff) > 0 {
				t.Errorf("Number of map entries (-want +got):\n%s", diff)
			}

			for k, v := range gotMap {
				if k == startID && (v.Parent != "" || v.depth != 0) {
					t.Errorf("Incorrect starting node entry")
				}
				if k != startID && (v.Parent == "" || v.depth < 1) {
					t.Errorf("Incorrect dependency node entry")
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

func getPackageId(graph string, entry int, ctx context.Context, gqlclient graphql.Client) string {
	if graph == "isDependency" {
		pkgFilter := &model.PkgSpec{
			Type:      &isDepTestData.IsDependency[entry].Pkg.Type,
			Namespace: isDepTestData.IsDependency[entry].Pkg.Namespace,
			Name:      &isDepTestData.IsDependency[entry].Pkg.Name,
		}
		pkgResponse, err := model.Packages(ctx, gqlclient, pkgFilter)
		if err != nil {
			fmt.Printf("Error getting id for isDependency test case: %s\n", err)
			return ""
		}
		return pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id
	}
	return ""
}
