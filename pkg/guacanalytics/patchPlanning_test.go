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
			{
				Pkg: &model.PkgInputSpec{
					Type:      "conan",
					Namespace: ptrfrom.String("openssl.org"),
					Name:      "openssl",
					Version:   ptrfrom.String("3.0.3"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "bottom",
					Namespace: ptrfrom.String("bottomns"),
					Name:      "bottompkg",
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
		},
	}
	isDependencyNotInRangeGraph = assembler.IngestPredicates{
		IsDependency: []assembler.IsDependencyIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "conan3",
					Namespace: ptrfrom.String("openssl.org3"),
					Name:      "openssl3",
					Version:   ptrfrom.String("3.0.3"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "extraType",
					Namespace: ptrfrom.String("extraNamespace"),
					Name:      "extraName",
					Version:   ptrfrom.String("1.19.0"),
				},
				IsDependency: &model.IsDependencyInputSpec{
					VersionRange:   "=3.0.3",
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
			return fmt.Errorf("Error in ingesting package: %s\n", err)
		}

		_, err = model.IngestPackage(context.Background(), client, *ingest.DepPkg)

		if err != nil {
			return fmt.Errorf("Error in ingesting dependent package: %s\n", err)
		}
		_, err = model.IsDependency(context.Background(), client, *ingest.Pkg, *ingest.DepPkg, *ingest.IsDependency)

		if err != nil {
			return fmt.Errorf("Error in ingesting isDependency: %s\n", err)
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
	case "isDependencyNotInRangeGraph":
		err := ingestIsDependency(ctx, client, isDependencyNotInRangeGraph)
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("Graph input did not match any test graph")
}

func Test_SearchSubgraphFromVuln(t *testing.T) {
	server, err := startTestServer()

	if err != nil {
		t.Errorf("Error starting server: %s \n", err)
		os.Exit(1)
	}

	ctx := logging.WithLogger(context.Background())

	httpClient := http.Client{}
	gqlclient := graphql.NewClient("http://localhost:9090/query", &httpClient)

	testCases := []struct {
		name           string
		startType      string
		startNamespace string
		startName      string
		startVersion   *string
		stopType       *string
		stopNamespace  string
		stopName       string
		stopVersion    *string
		maxDepth       int
		expectedLen    int
		expectedPkgs   []string
		graphInput     string
	}{
		{
			name:           "1: two levels of dependencies, no stopID and no limiting maxDepth",
			startType:      "conan",
			startNamespace: "openssl.org",
			startName:      "openssl",
			startVersion:   ptrfrom.String("3.0.3"),
			maxDepth:       10,
			expectedLen:    6,
			expectedPkgs:   []string{"top", "deb", "conan"},
			graphInput:     "isDependencySimpleGraph",
		},
		{
			name:           "2:  one level of dependencies, no stopID and no limiting maxDepth",
			startType:      "deb",
			startNamespace: "ubuntu",
			startName:      "dpkg",
			startVersion:   ptrfrom.String("1.19.0"),
			maxDepth:       10,
			expectedLen:    4,
			expectedPkgs:   []string{"top", "deb"},
			graphInput:     "isDependencySimpleGraph",
		},
		{
			name:           "3: two levels of dependencies, a stopID at the first level and no limiting maxDepth",
			startType:      "conan",
			startNamespace: "openssl.org",
			startName:      "openssl",
			startVersion:   ptrfrom.String("3.0.3"),
			stopType:       ptrfrom.String("deb"),
			stopNamespace:  "ubuntu",
			stopName:       "dpkg",
			stopVersion:    ptrfrom.String("1.19.0"),
			maxDepth:       10,
			expectedLen:    4,
			expectedPkgs:   []string{"deb", "conan"},
			graphInput:     "isDependencySimpleGraph",
		},
		{
			name:           "4: two levels of dependencies, no stopID and a limiting maxDepth at the first level",
			startType:      "conan",
			startNamespace: "openssl.org",
			startName:      "openssl",
			startVersion:   ptrfrom.String("3.0.3"),
			maxDepth:       1,
			expectedLen:    4,
			expectedPkgs:   []string{"deb", "conan"},
			graphInput:     "isDependencySimpleGraph",
		},
		{
			name:           "5: isDependency indirect dependency",
			startType:      "bottom",
			startNamespace: "bottomns",
			startName:      "bottompkg",
			startVersion:   ptrfrom.String("1.19.0"),
			maxDepth:       10,
			expectedLen:    8,
			expectedPkgs:   []string{"top", "deb", "conan", "bottom"},
			graphInput:     "isDependencySimpleGraph",
		},
		{
			name:           "6: isDependency no dependents returns no extra",
			startType:      "top",
			startNamespace: "topns",
			startName:      "toppkg",
			startVersion:   ptrfrom.String("1.19.0"),
			maxDepth:       10,
			expectedLen:    2,
			expectedPkgs:   []string{"top"},
			graphInput:     "isDependencySimpleGraph",
		},
		{
			name:           "7: direct isDependency not included in range",
			startType:      "extraType",
			startNamespace: "extraNamespace",
			startName:      "extraName",
			startVersion:   ptrfrom.String("1.19.0"),
			maxDepth:       10,
			expectedLen:    2,
			expectedPkgs:   []string{"extraType"},
			graphInput:     "isDependencyNotInRangeGraph",
		},
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("Test case %s\n", tt.name), func(t *testing.T) {
			err = ingestTestData(ctx, gqlclient, tt.graphInput)

			if err != nil {
				t.Errorf("Error ingesting test data: %s", err)
				return
			}

			var startIDs []*string
			if tt.startVersion != nil {
				startIDs, err = getPackageIDs(ctx, gqlclient, ptrfrom.String(tt.startType), tt.startNamespace, tt.startName, tt.startVersion, true, false)
			} else {
				startIDs, err = getPackageIDs(ctx, gqlclient, ptrfrom.String(tt.startType), tt.startNamespace, tt.startName, nil, false, true)
			}

			if err != nil {
				t.Errorf("Error finding startNode: %s", err)
				return
			}

			if len(startIDs) > 1 {
				t.Errorf("Found more than one matching node for the test case start ID input\n")
				return
			}

			var stopIDs []*string
			if tt.stopType != nil {

				if tt.stopVersion != nil {
					stopIDs, err = getPackageIDs(ctx, gqlclient, tt.stopType, tt.stopNamespace, tt.stopName, tt.stopVersion, true, false)
				} else {
					stopIDs, err = getPackageIDs(ctx, gqlclient, tt.stopType, tt.stopNamespace, tt.stopName, nil, false, true)
				}
				if err != nil {
					t.Errorf("Error finding stopNode: %s", err)
				}

				if len(stopIDs) > 1 {
					t.Errorf("Found more than one matching node for the test case stop ID input\n")
					return
				}
			} else {
				stopIDs = append(stopIDs, nil)
			}

			gotMap, err := SearchDependenciesFromStartNode(ctx, gqlclient, *startIDs[0], stopIDs[0], tt.maxDepth)

			if err != nil {
				t.Errorf("got err from SearchDependenciesFromStartNode: %s", err)
			}

			if diff := cmp.Diff(tt.expectedLen, len(gotMap)); len(diff) > 0 {
				t.Errorf("Number of map entries (-want +got):\n%s", diff)
			}

			var expectedIDs []string
			for _, pkg := range tt.expectedPkgs {
				pkgIDs, err := getPackageIDs(ctx, gqlclient, &pkg, "", "", nil, false, false)
				if err != nil {
					t.Errorf("Expected package %s not found: %s\n", pkg, err)
				}

				for _, ID := range pkgIDs {
					expectedIDs = append(expectedIDs, *ID)
				}

				// only applicable to cases with one version node
				if len(pkgIDs) == 2 {
					if gotMap[*pkgIDs[0]].NodeType == "" {
						t.Errorf("First expected package %s is not in results\n", pkg)
					}

					if gotMap[*pkgIDs[1]].NodeType == "" {
						t.Errorf("Second expected package %s is not in results\n", pkg)
					}
				}
			}

			for gotID, node := range gotMap {

				if stopIDs[0] == nil && tt.maxDepth == 10 {
					if !node.Expanded {
						t.Errorf("All nodes should be expanded but this node was not: node %s \n", gotID)
					}
				}
				//check that other pkgs are not present in return map
				inExpected := false
				for _, expectedID := range expectedIDs {
					if expectedID == gotID {
						inExpected = true
						break
					}
				}

				if !inExpected {
					t.Errorf("This ID appears in the returned map but is not expected: %s \n", gotID)
					return
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
		cf()
		server.Close()
	}
	cf()
}

func startTestServer() (*http.Server, error) {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	srv, err := getGraphqlTestServer()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize graphql server: %s", err)
	}
	http.Handle("/query", srv)

	server := &http.Server{Addr: fmt.Sprintf(":%d", 9090)}
	logger.Info("starting server")

	go func() {
		logger.Infof("server finished: %s", server.ListenAndServe())
	}()
	return server, nil
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

// This function return matching packageName and/or packageVersion node IDs
func getPackageIDs(ctx context.Context, gqlclient graphql.Client, nodeType *string, nodeNamespace string, nodeName string, nodeVersion *string, justFindVersion bool, justFindName bool) ([]*string, error) {
	var pkgFilter model.PkgSpec
	if nodeVersion != nil {
		pkgFilter = model.PkgSpec{
			Type:      nodeType,
			Namespace: &nodeNamespace,
			Name:      &nodeName,
			Version:   nodeVersion,
		}
	} else {
		pkgFilter = model.PkgSpec{
			Type: nodeType,
		}
	}
	pkgResponse, err := model.Packages(ctx, gqlclient, &pkgFilter)

	if err != nil {
		return nil, fmt.Errorf("Error getting id for test case: %s\n", err)
	}
	var foundIDs []*string

	if len(pkgResponse.Packages[0].Namespaces[0].Names) > 0 && !justFindVersion {
		for _, name := range pkgResponse.Packages[0].Namespaces[0].Names {
			foundIDs = append(foundIDs, &name.Id)
		}
	}

	if len(pkgResponse.Packages[0].Namespaces[0].Names[0].Versions) > 0 && !justFindName {
		for _, version := range pkgResponse.Packages[0].Namespaces[0].Names[0].Versions {
			foundIDs = append(foundIDs, &version.Id)
		}
	}

	if len(foundIDs) < 1 {
		return nil, fmt.Errorf("No matching nodes found\n")
	}

	return foundIDs, nil
}
