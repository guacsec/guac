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

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	asmhelpers "github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_cyclonedxParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name           string
		doc            *processor.Document
		wantPredicates *assembler.IngestPredicates
		wantErr        bool
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
		wantPredicates: &testdata.CdxIngestionPredicates,
		wantErr:        false,
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
		wantPredicates: &testdata.CdxQuarkusIngestionPredicates,
		wantErr:        false,
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
		wantPredicates: &testdata.CdxNpmIngestionPredicates,
		wantErr:        false,
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
		wantPredicates: &testdata.CdxEmptyIngestionPredicates,
		wantErr:        false,
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

			preds := s.GetPredicates(ctx)
			if d := cmp.Diff(tt.wantPredicates, preds, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
				t.Errorf("cyclondx.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}

func Test_cyclonedxParser_addRootPackage(t *testing.T) {
	tests := []struct {
		name     string
		cdxBom   *cdx.BOM
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
		wantPurl: "pkg:guac/cdx/gcr.io/distroless/static@sha256:6ad5b696af3ca05a048bd29bf0f623040462638cb0b29c8d702cbb2805687388?tag=nonroot",
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
		wantPurl: "pkg:guac/cdx/gcr.io/distroless/static@sha256:6ad5b696af3ca05a048bd29bf0f623040462638cb0b29c8d702cbb2805687388?tag=",
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
		wantPurl: "pkg:guac/cdx/gcr.io/distroless/static@?tag=",
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
		wantPurl: "pkg:guac/cdx/library/debian@sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870?tag=latest",
	}, {
		name: "library/debian - purl not provided, tag not specified",
		cdxBom: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Name:    "library/debian",
					Type:    cdx.ComponentTypeContainer,
					Version: "sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870",
				},
			},
		},
		wantPurl: "pkg:guac/cdx/library/debian@sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870?tag=",
	}, {
		name: "library - purl not provided, tag not specified",
		cdxBom: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Name:    "library",
					Type:    cdx.ComponentTypeContainer,
					Version: "sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870",
				},
			},
		},
		wantPurl: "pkg:guac/cdx/library@sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870?tag=",
	}, {
		name: "name split length too long, tag not specified",
		cdxBom: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Name:    "ghcr.io/guacsec/guac/guacsec",
					Type:    cdx.ComponentTypeContainer,
					Version: "sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870",
				},
			},
		},
		wantPurl: "pkg:guac/cdx/ghcr.io/guacsec/guac/guacsec@sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870",
	}, {
		name: "name contains local registry, tag specified",
		cdxBom: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Name:    "foo.registry.com:4443/myapp/debian:latest",
					Type:    cdx.ComponentTypeContainer,
					Version: "sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870",
				},
			},
		},
		wantPurl: "pkg:guac/cdx/foo.registry.com:4443/myapp/debian@sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870?tag=latest",
	}, {
		name: "ComponentTypeLibrary",
		cdxBom: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					Name:    "ghcr.io/guacsec/guac/guacsec",
					Type:    cdx.ComponentTypeLibrary,
					Version: "sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870",
				},
			},
		},
		wantPurl: "pkg:guac/cdx/ghcr.io/guacsec/guac/guacsec@sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870",
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
				packagePackages:   map[string][]*model.PkgInputSpec{},
				identifierStrings: &common.IdentifierStrings{},
			}
			c.cdxBom = tt.cdxBom
			if err := c.getTopLevelPackage(tt.cdxBom); err != nil {
				t.Errorf("Failed to getTopLevelPackage %s", err)
			}
			wantPackage, err := asmhelpers.PurlToPkg(tt.wantPurl)
			if err != nil {
				t.Errorf("Failed to parse purl %v %v", tt.wantPurl, err)
			}
			if d := cmp.Diff(*wantPackage, *c.packagePackages[tt.cdxBom.Metadata.Component.BOMRef][0]); len(d) != 0 {
				t.Errorf("addRootPackage failed to produce expected package for %v", tt.name)
				t.Errorf("spdx.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}
