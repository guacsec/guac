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
	simpleGraph = assembler.IngestPredicates{

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
					Algorithm: "testArtifactAlgorithm3",
					Digest:    "testArtifactDigest3",
				},
				IsOccurrence: &model.IsOccurrenceInputSpec{
					Justification: "connect pkg4 and artifact3",
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
					Algorithm: "testArtifactAlgorithm4",
					Digest:    "testArtifactDigest4",
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
					Type:      "pkgType1",
					Namespace: ptrfrom.String("pkgNamespace1"),
					Name:      "pkgName1",
					Version:   ptrfrom.String("1.19.0"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "pkgType3",
					Namespace: ptrfrom.String("pkgNamespace3"),
					Name:      "pkgName3",
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
	shouldNotBeExplored = assembler.IngestPredicates{
		IsDependency: []assembler.IsDependencyIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgTypeA",
					Namespace: ptrfrom.String("pkgNamespaceA"),
					Name:      "pkgNameA",
					Version:   ptrfrom.String("3.0.3"),
				},
				DepPkg: &model.PkgInputSpec{
					Type:      "pkgTypeB",
					Namespace: ptrfrom.String("pkgNamespaceB"),
					Name:      "pkgNameB",
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
		},
		CertifyGood: []assembler.CertifyGoodIngest{
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgTypeB",
					Namespace: ptrfrom.String("pkgNamespaceB"),
					Name:      "pkgNameB",
					Version:   ptrfrom.String("1.19.0"),
				},
				PkgMatchFlag: model.MatchFlags{
					Pkg: model.PkgMatchTypeAllVersions,
				},
				CertifyGood: &model.CertifyGoodInputSpec{
					Justification: "good package",
				},
			},
			{
				Pkg: &model.PkgInputSpec{
					Type:      "pkgTypeA",
					Namespace: ptrfrom.String("pkgNamespaceA"),
					Name:      "pkgNameA",
					Version:   ptrfrom.String("3.0.3"),
				},
				PkgMatchFlag: model.MatchFlags{
					Pkg: model.PkgMatchTypeAllVersions,
				},
				CertifyGood: &model.CertifyGoodInputSpec{
					Justification: "good package",
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

func ingestHasSLSA(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.IsOccurrence {
		_, err := model.IngestPackage(context.Background(), client, *ingest.Pkg)

		if err != nil {
			return fmt.Errorf("Error in ingesting package for IsOccurrence: %v\n", err)
		}

		_, err = model.IngestArtifact(context.Background(), client, *ingest.Artifact)

		if err != nil {
			return fmt.Errorf("Error in ingesting artifact for IsOccurrence: %v\n", err)
		}

		_, err = model.IsOccurrencePkg(context.Background(), client, *ingest.Pkg, *ingest.Artifact, *ingest.IsOccurrence)

		if err != nil {
			return fmt.Errorf("Error in ingesting isOccurrence: %v\n", err)
		}
	}
	for _, ingest := range graph.HasSlsa {
		_, err := model.IngestBuilder(context.Background(), client, *ingest.Builder)

		if err != nil {
			return fmt.Errorf("Error in ingesting Builder for HasSlsa: %v\n", err)
		}

		_, err = model.IngestMaterials(context.Background(), client, ingest.Materials)

		if err != nil {
			return fmt.Errorf("Error in ingesting Material for HasSlsa: %v\n", err)
		}

		_, err = model.SLSAForArtifact(context.Background(), client, *ingest.Artifact, ingest.Materials, *ingest.Builder, *ingest.HasSlsa)

		if err != nil {
			return fmt.Errorf("Error in ingesting HasSlsa: %v\n", err)
		}
	}
	return nil
}

func ingestCertifyGood(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.CertifyGood {
		_, err := model.IngestPackage(context.Background(), client, *ingest.Pkg)

		if err != nil {
			return fmt.Errorf("Error in ingesting Package for CertifyGood: %v\n", err)
		}

		_, err = model.CertifyGoodPkg(context.Background(), client, *ingest.Pkg, &ingest.PkgMatchFlag, *ingest.CertifyGood)

		if err != nil {
			return fmt.Errorf("Error in ingesting CertifyGood: %v\n", err)
		}
	}
	return nil
}

func ingestTestData(ctx context.Context, client graphql.Client, graphInput string) error {
	switch graphInput {
	case "isDependencySimpleGraph":
		err := ingestIsDependency(ctx, client, simpleGraph)
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
	case "isDependencyAndHasSLSAGraph":
		err := ingestIsDependency(ctx, client, simpleGraph)
		if err != nil {
			return err
		}
		err = ingestHasSLSA(ctx, client, simpleGraph)
		if err != nil {
			return err
		}
		err = ingestIsDependency(ctx, client, isDependencyAndHasSLSAGraph)
		if err != nil {
			return err
		}
		return nil
	case "simpleHasSLSAGraph":
		err := ingestHasSLSA(ctx, client, simpleGraph)
		if err != nil {
			return err
		}
		return nil
	case "shouldNotBeExplored":
		err := ingestIsDependency(ctx, client, shouldNotBeExplored)

		if err != nil {
			return err
		}

		err = ingestCertifyGood(ctx, client, shouldNotBeExplored)

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
	gqlClient := graphql.NewClient("http://localhost:9090/query", &httpClient)

	testCases := []struct {
		name              string
		startType         string
		startNamespace    string
		startName         string
		startVersion      *string
		stopType          *string
		stopNamespace     string
		stopName          string
		stopVersion       *string
		maxDepth          int
		expectedLen       int
		expectedPkgs      []string
		expectedArtifacts []string
		graphInput        string
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
		{
			name:              "8: hasSLSA simpleton case",
			startType:         "pkgType1",
			startNamespace:    "pkgNamespace1",
			startName:         "pkgName1",
			startVersion:      ptrfrom.String("1.19.0"),
			maxDepth:          10,
			expectedLen:       6,
			expectedPkgs:      []string{"pkgType1", "pkgType2"},
			expectedArtifacts: []string{"testArtifactAlgorithm1", "testArtifactAlgorithm2"},
			graphInput:        "simpleHasSLSAGraph",
		},
		{
			name:              "9: hasSLSA case with no dependent isOccurrences",
			startType:         "pkgType2",
			startNamespace:    "pkgNamespace2",
			startName:         "pkgName2",
			startVersion:      ptrfrom.String("1.19.0"),
			maxDepth:          10,
			expectedLen:       3,
			expectedPkgs:      []string{"pkgType2"},
			expectedArtifacts: []string{"testArtifactAlgorithm2"},
			graphInput:        "simpleHasSLSAGraph",
		},
		{
			name:              "10: hasSLSA two levels",
			startType:         "pkgType5",
			startNamespace:    "pkgNamespace5",
			startName:         "pkgName5",
			startVersion:      ptrfrom.String("1.19.0"),
			maxDepth:          10,
			expectedLen:       10,
			expectedPkgs:      []string{"pkgType5", "pkgType4", "pkgType2"},
			expectedArtifacts: []string{"testArtifactAlgorithm4", "testArtifactAlgorithm3", "testArtifactAlgorithm1", "testArtifactAlgorithm2"},
			graphInput:        "simpleHasSLSAGraph",
		},
		{
			name:              "11: hasSLSA & isDependency combined case",
			startType:         "pkgType3",
			startNamespace:    "pkgNamespace3",
			startName:         "pkgName3",
			startVersion:      ptrfrom.String("1.19.0"),
			maxDepth:          10,
			expectedLen:       8,
			expectedPkgs:      []string{"pkgType3", "pkgType2", "pkgType1"},
			expectedArtifacts: []string{"testArtifactAlgorithm1", "testArtifactAlgorithm2"},
			graphInput:        "isDependencyAndHasSLSAGraph",
		},
		{
			name:           "12: should not explore certifyGood case",
			startType:      "pkgTypeB",
			startNamespace: "pkgNamespaceB",
			startName:      "pkgNameB",
			startVersion:   ptrfrom.String("1.19.0"),
			maxDepth:       10,
			expectedLen:    4,
			expectedPkgs:   []string{"pkgTypeB", "pkgTypeA"},
			graphInput:     "shouldNotBeExplored",
		},
		// TODO: add test cases for sourceName nodes
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("Test case %s\n", tt.name), func(t *testing.T) {
			err = ingestTestData(ctx, gqlClient, tt.graphInput)

			if err != nil {
				t.Errorf("Error ingesting test data: %s", err)
				return
			}

			var getPackageIDsValues []*string
			var startID string
			if tt.startVersion != nil {
				getPackageIDsValues, err = getPackageIDs(ctx, gqlClient, ptrfrom.String(tt.startType), tt.startNamespace, tt.startName, tt.startVersion, true, false)
			} else {
				getPackageIDsValues, err = getPackageIDs(ctx, gqlClient, ptrfrom.String(tt.startType), tt.startNamespace, tt.startName, nil, false, true)
			}

			if err != nil {
				t.Errorf("Error finding startNode: %s", err)
				return
			}

			if getPackageIDsValues == nil || len(getPackageIDsValues) > 1 {
				t.Errorf("Cannot locate matching startID input\n")
				return
			}

			startID = *getPackageIDsValues[0]

			var stopID *string
			if tt.stopType != nil {
				if tt.stopVersion != nil {
					getPackageIDsValues, err = getPackageIDs(ctx, gqlClient, tt.stopType, tt.stopNamespace, tt.stopName, tt.stopVersion, true, false)
				} else {
					getPackageIDsValues, err = getPackageIDs(ctx, gqlClient, tt.stopType, tt.stopNamespace, tt.stopName, nil, false, true)
				}

				if err != nil {
					t.Errorf("Error finding stopNode: %s", err)
					return
				}

				if getPackageIDsValues == nil || len(getPackageIDsValues) > 1 {
					t.Errorf("Cannot locate matching stopID input\n")
					return
				}

				stopID = getPackageIDsValues[0]
			}

			gotMap, err := SearchDependenciesFromStartNode(ctx, gqlClient, startID, stopID, tt.maxDepth)

			if err != nil {
				t.Errorf("got err from SearchDependenciesFromStartNode: %s", err)
			}

			if diff := cmp.Diff(tt.expectedLen, len(gotMap)); len(diff) > 0 {
				t.Errorf("Number of map entries (-want +got):\n%s", diff)
			}

			var expectedPkgIDs []string
			for _, pkg := range tt.expectedPkgs {
				pkgIDs, err := getPackageIDs(ctx, gqlClient, &pkg, "", "", nil, false, false)
				if err != nil {
					t.Errorf("Expected package %s not found: %s\n", pkg, err)
				}

				for _, ID := range pkgIDs {
					expectedPkgIDs = append(expectedPkgIDs, *ID)
				}
			}

			var expectedArtifactIDs []string
			for _, artifact := range tt.expectedArtifacts {
				artifactID, err := getArtifactID(ctx, gqlClient, artifact)
				if err != nil {
					t.Errorf("%s \n", err)
				}

				expectedArtifactIDs = append(expectedArtifactIDs, artifactID)
			}

			for gotID, node := range gotMap {
				if stopID == nil && tt.maxDepth == 10 {
					if !node.Expanded {
						t.Errorf("All nodes should be expanded but this node was not: node %s \n", gotID)
					}
				}

				//check that other packages are not present in return map
				inExpectedPkgs := false
				for _, expectedID := range expectedPkgIDs {
					if expectedID == gotID {
						inExpectedPkgs = true
						break
					}
				}

				inExpectedArtifacts := false
				for _, expectedID := range expectedArtifactIDs {
					if expectedID == gotID {
						inExpectedArtifacts = true
						break
					}
				}

				// if not present in expected packages or in expected artifacts
				if !(inExpectedPkgs || inExpectedArtifacts) {
					t.Errorf("This ID appears in the returned map but is not expected: %s \n", gotID)
					// return
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

// This function return matching packageName and/or packageVersion node IDs depending on if you specified to only find name nodes or version nodes
func getPackageIDs(ctx context.Context, gqlClient graphql.Client, nodeType *string, nodeNamespace string, nodeName string, nodeVersion *string, justFindVersion bool, justFindName bool) ([]*string, error) {
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
	pkgResponse, err := model.Packages(ctx, gqlClient, &pkgFilter)

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

func getArtifactID(ctx context.Context, gqlClient graphql.Client, algorithm string) (string, error) {
	artifactFilter := model.ArtifactSpec{
		Algorithm: &algorithm,
	}

	artifactResponse, err := model.Artifacts(ctx, gqlClient, &artifactFilter)

	if err != nil {
		return "", fmt.Errorf("Error filtering for expected artifact: %s\n", err)
	}

	if len(artifactResponse.Artifacts) != 1 {
		return "", fmt.Errorf("Could not find the matching artifact\n")
	}

	return artifactResponse.Artifacts[0].Id, nil
}
