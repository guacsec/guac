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
	simpleTestData = assembler.IngestPredicates{

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
		IsOccurrence: []assembler.IsOccurrenceIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType1",
					Namespace: ptrfrom.String("pkgNamespace1"),
					Name:      "pkgName1",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm1",
					Digest:    "testArtifactDigest1",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg1 and artifact1",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType2",
					Namespace: ptrfrom.String("pkgNamespace2"),
					Name:      "pkgName2",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm2",
					Digest:    "testArtifactDigest2",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg2 and artifact2",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType4",
					Namespace: ptrfrom.String("pkgNamespace4"),
					Name:      "pkgName4",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm1",
					Digest:    "testArtifactDigest1",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg4 and artifact1",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType4",
					Namespace: ptrfrom.String("pkgNamespace4"),
					Name:      "pkgName4",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm1",
					Digest:    "testArtifactDigest1",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg1 and artifact4",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType5",
					Namespace: ptrfrom.String("pkgNamespace5"),
					Name:      "pkgName5",
					Version:   ptrfrom.String("1.19.0"),
				},
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm3",
					Digest:    "testArtifactDigest3",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg5 and artifact3",
				},
			},
		},
		HasSlsa: []assembler.HasSlsaIngest{
			{
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm2",
					Digest:    "testArtifactDigest2",
				},
				Builder: &model.BuilderInputSpec{
					Uri: "testUri",
				},
				Materials: []model.ArtifactInputSpec{{
					Algorithm: "testArtifactAlgorithm1",
					Digest:    "testArtifactDigest1",
				}},
				HasSlsa: &model.SLSAInputSpec{
					BuildType:   "testBuildType",
					SlsaVersion: "testSlsaVersion",
					SlsaPredicate: []model.SLSAPredicateInputSpec{
						{Key: "slsa.testKey", Value: "testValue"},
					},
				},
			},
			{
				Artifact: &model.ArtifactInputSpec{
					Algorithm: "testArtifactAlgorithm3",
					Digest:    "testArtifactDigest3",
				},
				Builder: &model.BuilderInputSpec{
					Uri: "testUri",
				},
				Materials: []model.ArtifactInputSpec{{
					Algorithm: "testArtifactAlgorithm4",
					Digest:    "testArtifactDigest4",
				}},
				HasSlsa: &model.SLSAInputSpec{
					BuildType:   "testBuildType",
					SlsaVersion: "testSlsaVersion",
					SlsaPredicate: []model.SLSAPredicateInputSpec{
						{Key: "slsa.testKey", Value: "testValue"},
					},
				},
			},
		},
	}

	isDependencyAndHasSLSAGraph = assembler.IngestPredicates{
		IsDependency: []assembler.IsDependencyIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgType3",
					Namespace: ptrfrom.String("pkgNamespace3"),
					Name:      "pkgName3",
					Version:   ptrfrom.String("1.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "pkgType1",
					Namespace: ptrfrom.String("pkgNamespace1"),
					Name:      "pkgName1",
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

func ingestIsDependency(ctx context.Context, client graphql.Client, logger *zap.SugaredLogger, graph assembler.IngestPredicates) {
	for _, ingest := range graph.IsDependency {

		_, err := model.IngestPackage(context.Background(), client, *ingest.Pkg)

		if err != nil {
			logger.Errorf("Error in ingesting package: %v\n", err)
		}

		_, err = model.IngestPackage(context.Background(), client, *ingest.DepPkg)

		if err != nil {
			logger.Errorf("Error in ingesting dependency package: %v\n", err)
		}
		_, err = model.IsDependency(context.Background(), client, *ingest.Pkg, *ingest.DepPkg, *ingest.IsDependency)

		if err != nil {
			logger.Errorf("Error in ingesting isDependency: %v\n", err)
		}
	}
}

func ingestTestData(graphInput string, ctx context.Context, client graphql.Client) {
	logger := logging.FromContext(ctx)

	switch graphInput {
	case "isDependencyAndHasSLSAGraph":
		ingestIsDependency(ctx, client, logger, isDependencyAndHasSLSAGraph)
		ingestIsDependency(ctx, client, logger, simpleTestData)
		// Change graph input so hasSLSA simple graph is ingested too
		graphInput = "simpleHasSLSAGraph"
		break
	case "simpleIsDependencyGraph":
		ingestIsDependency(ctx, client, logger, simpleTestData)
	case "simpleHasSLSAGraph":
		for _, ingest := range simpleTestData.IsOccurrence {
			_, err := model.IngestPackage(context.Background(), client, *ingest.Pkg)

			if err != nil {
				logger.Errorf("Error in ingesting package for IsOccurence: %v\n", err)
			}

			_, err = model.IngestArtifact(context.Background(), client, *ingest.Artifact)

			if err != nil {
				logger.Errorf("Error in ingesting artifact for IsOccurence: %v\n", err)
			}

			_, err = model.IsOccurrencePkg(context.Background(), client, *ingest.Pkg, *ingest.Artifact, *ingest.IsOccurrence)

			if err != nil {
				logger.Errorf("Error in ingesting isOccurrence: %v\n", err)
			}
		}
		for _, ingest := range simpleTestData.HasSlsa {
			_, err := model.IngestBuilder(context.Background(), client, *ingest.Builder)

			if err != nil {
				logger.Errorf("Error in ingesting Builder for HasSlsa: %v\n", err)
			}

			_, err = model.IngestMaterials(context.Background(), client, ingest.Materials)

			if err != nil {
				logger.Errorf("Error in ingesting Material for HasSlsa: %v\n", err)
			}

			_, err = model.SLSAForArtifact(context.Background(), client, *ingest.Artifact, ingest.Materials, *ingest.Builder, *ingest.HasSlsa)

			if err != nil {
				logger.Errorf("Error in ingesting HasSlsa: %v\n", err)
			}
		}
	}
}

func Test_SearchSubgraphFromVuln(t *testing.T) {
	server, logger := startTestServer()
	ctx := logging.WithLogger(context.Background())

	httpClient := http.Client{}
	gqlclient := graphql.NewClient("http://localhost:9090/query", &httpClient)

	testCases := []struct {
		name           string
		startType      string
		startNamespace *string
		startName      string
		stopType       string
		stopNamespace  *string
		stopName       string
		maxDepth       int
		expectedLen    int
		expectedPkgs   []string
		graphInput     string
	}{
		//TODO: add expectedPkgs to the isDependency tests
		{
			name:           "1: test case with two dependencies at the same depth, no stopID and no limiting maxDepth",
			startType:      "deb",
			startNamespace: ptrfrom.String("ubuntu"),
			startName:      "dpkg",
			stopType:       "",
			maxDepth:       10,
			expectedLen:    5,
			graphInput:     "simpleIsDependencyGraph",
		},
		{
			name:           "2: two levels of dependencies, no stopID and no limiting maxDepth",
			startType:      "top",
			startNamespace: ptrfrom.String("topns"),
			startName:      "toppkg",
			stopType:       "",
			maxDepth:       10,
			expectedLen:    7,
			graphInput:     "simpleIsDependencyGraph",
		},

		{
			name:           "3: two levels of dependencies, a stopID at the first level and no limiting maxDepth",
			startType:      "top",
			startNamespace: ptrfrom.String("topns"),
			startName:      "toppkg",
			stopType:       "deb",
			stopNamespace:  ptrfrom.String("ubuntu"),
			stopName:       "dpkg",
			maxDepth:       10,
			expectedLen:    3,
			graphInput:     "simpleIsDependencyGraph",
		},

		{
			name:           "4: two levels of dependencies, no stopID and a limiting maxDepth at the first level",
			startType:      "top1",
			startNamespace: ptrfrom.String("topns1"),
			startName:      "toppkg1",
			stopType:       "",
			maxDepth:       1,
			expectedLen:    3,
			graphInput:     "simpleIsDependencyGraph",
		},
		{
			name:           "5: isDependency indirect dependency",
			startType:      "top2",
			startNamespace: ptrfrom.String("topns2"),
			startName:      "toppkg2",
			stopType:       "",
			maxDepth:       10,
			expectedLen:    9,
			graphInput:     "simpleIsDependencyGraph",
		},
		{
			name:           "6: isDependency range that does not include the dependency",
			startType:      "top3",
			startNamespace: ptrfrom.String("topns3"),
			startName:      "toppkg3",
			stopType:       "",
			maxDepth:       10,
			expectedLen:    1,
			graphInput:     "simpleIsDependencyGraph",
		},
		{
			name:           "7: hasSlsa simpleton case", // TODOL implement HasSLSA case in the code
			startType:      "pkgType1",
			startNamespace: ptrfrom.String("pkgNamespace1"),
			startName:      "pkgName1",
			stopType:       "",
			maxDepth:       10,
			expectedLen:    1,                    // TODO: change once implemented to two
			expectedPkgs:   []string{"pkgType1"}, // TODO: add "pkgType2" once implemented
			graphInput:     "simpleHasSLSAGraph",
		},
		{
			name:           "8: hasSlsa case with no dependent isOccurences",
			startType:      "pkgType2",
			startNamespace: ptrfrom.String("pkgNamespace2"),
			startName:      "pkgName2",
			stopType:       "",
			maxDepth:       10,
			expectedLen:    1,
			expectedPkgs:   []string{"pkgType2"},
			graphInput:     "simpleHasSLSAGraph",
		},
		{
			name:           "9: hasSlsa two levels",
			startType:      "pkgType5",
			startNamespace: ptrfrom.String("pkgNamespace5"),
			startName:      "pkgName5",
			stopType:       "",
			maxDepth:       10,
			expectedLen:    1,
			expectedPkgs:   []string{"pkgType5"}, // TODO: add pkgType2 and pkgType4 once implemented
			graphInput:     "simpleHasSLSAGraph",
		},
		{
			name:           "10: hasSlsa & isDependency combined case",
			startType:      "pkgType3",
			startNamespace: ptrfrom.String("pkgNamespace3"),
			startName:      "pkgName3",
			stopType:       "",
			maxDepth:       10,
			expectedLen:    4,
			expectedPkgs:   []string{"pkgType3"}, // TODO: add pkgType2 and pkgType1 once implemented
			graphInput:     "isDependencyAndHasSLSAGraph",
		},
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("Test case %s\n", tt.name), func(t *testing.T) {
			ingestTestData(tt.graphInput, ctx, gqlclient)
			startID, err := getPackageId(ctx, gqlclient, tt.startType, tt.startNamespace, tt.startName)

			if err != nil {
				t.Errorf("got err from getting start package ID: %v", err)
				return
			}

			var stopID string
			if tt.stopType != "" {
				stopID, err = getPackageId(ctx, gqlclient, tt.stopType, tt.stopNamespace, tt.stopName)

				if err != nil {
					t.Errorf("got err from getting stop package ID: %v", err)
					return
				}
			} else {
				stopID = ""
			}

			gotMap, err := SearchDependenciesFromStartNode(ctx, gqlclient, startID, stopID, "packageVersion", tt.maxDepth)

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

			if len(tt.expectedPkgs) > 0 {
				for _, pkg := range tt.expectedPkgs {
					nodeID, err := getPackageId(ctx, gqlclient, pkg, ptrfrom.String(""), "")

					if err != nil {
						t.Errorf("Expected node not found in graph %s", err)
					}

					if _, ok := gotMap[nodeID]; !ok {
						t.Errorf("Expected node %s not found in output map", pkg)
					}
				}
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

func getPackageId(ctx context.Context, gqlclient graphql.Client, nodeType string, nodeNamespace *string, nodeName string) (string, error) {
	var pkgFilter model.PkgSpec
	if nodeName != "" {
		pkgFilter = model.PkgSpec{
			Type:      &nodeType,
			Namespace: nodeNamespace,
			Name:      &nodeName,
		}
	} else {
		pkgFilter = model.PkgSpec{
			Type: &nodeType,
		}
	}

	pkgResponse, err := model.Packages(ctx, gqlclient, &pkgFilter)

	if err != nil {
		return "", fmt.Errorf("Error getting id for test case: %s\n", err)
	}
	return pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id, nil
}
