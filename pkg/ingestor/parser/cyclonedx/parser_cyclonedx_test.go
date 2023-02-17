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
	"reflect"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
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
	}, {
		name: "valid CycloneDX document with no package dependencies",
		doc: &processor.Document{
			Blob:   testdata.CycloneDXExampleNoDependentComponents,
			Format: processor.FormatJSON,
			Type:   processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantNodes: testdata.CycloneDXNoDependentComponentsNodes,
		wantEdges: testdata.CyloneDXNoDependentComponentsEdges,
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

func Test_cyclonedxParser_addRootPackage(t *testing.T) {
	tests := []struct {
		name     string
		cdxBom   *cdx.BOM
		wantTag  string
		wantPurl string
	}{{
		name: "purl provided",
		cdxBom: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Name:       "gcr.io/distroless/static:nonroot",
					Type:       cdx.ComponentTypeContainer,
					Version:    "sha256:6ad5b696af3ca05a048bd29bf0f623040462638cb0b29c8d702cbb2805687388",
					PackageURL: "pkg:oci/static@sha256:6ad5b696af3ca05a048bd29bf0f623040462638cb0b29c8d702cbb2805687388?repository_url=gcr.io/distroless/static&tag=nonroot",
				},
			},
		},
		wantTag:  "container",
		wantPurl: "pkg:oci/static@sha256:6ad5b696af3ca05a048bd29bf0f623040462638cb0b29c8d702cbb2805687388?repository_url=gcr.io/distroless/static&tag=nonroot",
	}, {
		name: "gcr.io/distroless/static:nonroot - purl not provided",
		cdxBom: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Name:    "gcr.io/distroless/static:nonroot",
					Type:    cdx.ComponentTypeContainer,
					Version: "sha256:6ad5b696af3ca05a048bd29bf0f623040462638cb0b29c8d702cbb2805687388",
				},
			},
		},
		wantTag:  "container",
		wantPurl: "pkg:oci/static@sha256:6ad5b696af3ca05a048bd29bf0f623040462638cb0b29c8d702cbb2805687388?repository_url=gcr.io/distroless/static&tag=nonroot",
	}, {
		name: "gcr.io/distroless/static - purl not provided, tag not specified",
		cdxBom: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Name:    "gcr.io/distroless/static",
					Type:    cdx.ComponentTypeContainer,
					Version: "sha256:6ad5b696af3ca05a048bd29bf0f623040462638cb0b29c8d702cbb2805687388",
				},
			},
		},
		wantTag:  "container",
		wantPurl: "pkg:oci/static@sha256:6ad5b696af3ca05a048bd29bf0f623040462638cb0b29c8d702cbb2805687388?repository_url=gcr.io/distroless/static&tag=",
	}, {
		name: "gcr.io/distroless/static - purl not provided, tag not specified, version not specified",
		cdxBom: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Name: "gcr.io/distroless/static",
					Type: cdx.ComponentTypeContainer,
				},
			},
		},
		wantTag:  "container",
		wantPurl: "pkg:oci/static@?repository_url=gcr.io/distroless/static&tag=",
	}, {
		name: "library/debian:latest - purl not provided, assume docker.io",
		cdxBom: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Name:    "library/debian:latest",
					Type:    cdx.ComponentTypeContainer,
					Version: "sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870",
				},
			},
		},
		wantTag:  "container",
		wantPurl: "pkg:oci/debian@sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870?repository_url=library/debian&tag=latest",
	}, {
		name: "library/debian - purl not provided, assume docker.io, tag not specified",
		cdxBom: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Name:    "library/debian",
					Type:    cdx.ComponentTypeContainer,
					Version: "sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870",
				},
			},
		},
		wantTag:  "container",
		wantPurl: "pkg:oci/debian@sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870?repository_url=library/debian&tag=",
	}, {
		name: "file type - purl nor provided, version provided",
		cdxBom: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Name:    "/home/work/test/build/webserver/",
					Type:    cdx.ComponentTypeFile,
					Version: "sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870",
				},
			},
		},
		wantTag:  "file",
		wantPurl: "pkg:guac/file//home/work/test/build/webserver/&checksum=sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870",
	}, {
		name: "file type - purl nor provided, version not provided",
		cdxBom: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Name: "/home/work/test/build/webserver/",
					Type: cdx.ComponentTypeFile,
				},
			},
		},
		wantTag:  "file",
		wantPurl: "pkg:guac/file//home/work/test/build/webserver/&checksum=",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &cyclonedxParser{
				doc: &processor.Document{
					SourceInformation: processor.SourceInformation{
						Collector: "test",
						Source:    "test",
					},
				},
				rootComponent: component{},
				pkgMap:        map[string]*component{},
			}
			c.addRootPackage(tt.cdxBom)
			if !reflect.DeepEqual(c.rootComponent.curPackage.Purl, tt.wantPurl) {
				t.Errorf("addRootPackage failed to produce expected purl = %v, want %v", c.rootComponent.curPackage.Purl, tt.wantPurl)
			}
			if !reflect.DeepEqual(c.rootComponent.curPackage.Tags[0], tt.wantTag) {
				t.Errorf("addRootPackage failed to produce expected tag = %v, want %v", c.rootComponent.curPackage.Tags[0], tt.wantTag)
			}
		})
	}
}
