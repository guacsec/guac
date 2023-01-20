//
// Copyright 2022 The GUAC Authors.
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

package cyclonedx

import (
	"context"
	"testing"

	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_cyclonedxParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name      string
		doc       *processor.Document
		wantNodes []assembler.GuacNode
		wantEdges []assembler.GuacEdge
		wantErr   bool
	}{{
		name: "valid small CycloneDX document",
		doc: &processor.Document{
			Blob:   testdata.CycloneDXDistrolessExample,
			Format: processor.FormatJSON,
			Type:   processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantNodes: testdata.CycloneDXNodes,
		wantEdges: testdata.CyloneDXEdges,
		wantErr:   false,
	}, {
		name: "valid small CycloneDX document with package dependencies",
		doc: &processor.Document{
			Blob:   testdata.CycloneDXExampleSmallDeps,
			Format: processor.FormatJSON,
			Type:   processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantNodes: testdata.CycloneDXQuarkusNodes,
		wantEdges: testdata.CyloneDXQuarkusEdges,
		wantErr:   false,
	}, {
		name: "valid CycloneDX document where dependencies are missing dependsOn properties",
		doc: &processor.Document{
			Blob:   testdata.CycloneDXDependenciesMissingDependsOn,
			Format: processor.FormatJSON,
			Type:   processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantNodes: testdata.NpmMissingDependsOnCycloneDXNodes,
		wantEdges: testdata.NpmMissingDependsOnCycloneDXEdges,
		wantErr:   false,
	},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewCycloneDXParser()
			err := s.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("cyclonedxParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if nodes := s.CreateNodes(ctx); !testdata.GuacNodeSliceEqual(nodes, tt.wantNodes) {
				t.Errorf("cyclonedxParser.CreateNodes() = %v, want %v", nodes, tt.wantNodes)
			}
			if edges := s.CreateEdges(ctx, nil); !testdata.GuacEdgeSliceEqual(edges, tt.wantEdges) {
				t.Errorf("cyclonedxParser.CreateEdges() = %v, want %v", edges, tt.wantEdges)
			}
		})
	}
}
func Test_addEdgesRecursive(t *testing.T) {
	packageA := component{curPackage: assembler.PackageNode{Name: "A"}}
	packageB := component{curPackage: assembler.PackageNode{Name: "B"}}
	packageC := component{curPackage: assembler.PackageNode{Name: "C"}}
	packageD := component{curPackage: assembler.PackageNode{Name: "D"}}

	packageA.depPackages = []*component{&packageB}
	packageB.depPackages = []*component{&packageC}
	packageC.depPackages = []*component{&packageD}
	packageD.depPackages = []*component{&packageA}
	/*
		A -> B -> C -> D -> A
		This should result in a cycle, and it shouldn't blow up the stack.
	*/
	var edges []assembler.GuacEdge
	visited := make(map[string]bool)
	addEdges(packageA, &edges, visited)

	packageE := component{curPackage: assembler.PackageNode{Name: "E"}}
	packageF := component{curPackage: assembler.PackageNode{Name: "F"}}
	packageG := component{curPackage: assembler.PackageNode{Name: "G"}}
	/*
		This test case creates seven packages: A, B, C, D, E, F, and G.
		It sets up a cycle in the dependencies such that D, E, F, and G depend on A, B and C depend on D, E, F, and G.
		Calling addEdges(packageA, &edges) should not cause the function to recursively call itself indefinitely,
		leading to a stack overflow.
	*/
	packageA.depPackages = []*component{&packageB, &packageC}
	packageB.depPackages = []*component{&packageD, &packageE}
	packageC.depPackages = []*component{&packageF, &packageG}
	packageD.depPackages = []*component{&packageA}
	packageE.depPackages = []*component{&packageA}
	packageF.depPackages = []*component{&packageA}
	packageG.depPackages = []*component{&packageA}

	var e []assembler.GuacEdge
	visited = make(map[string]bool)
	addEdges(packageA, &e, visited)
}
