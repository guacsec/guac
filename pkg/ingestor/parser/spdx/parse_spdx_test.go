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

package spdx

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	asmhelpers "github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func pUrlToPkgDiscardError(pUrl string) *generated.PkgInputSpec {
	pkg, _ := asmhelpers.PurlToPkg(pUrl)
	return pkg
}

func Test_spdxParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name           string
		additionalOpts []cmp.Option
		doc            *processor.Document
		wantPredicates *assembler.IngestPredicates
		wantErr        bool
	}{{
		name: "valid big SPDX document",
		doc: &processor.Document{
			Blob:   testdata.SpdxExampleAlpine,
			Format: processor.FormatJSON,
			Type:   processor.DocumentSPDX,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantPredicates: &testdata.SpdxIngestionPredicates,
		wantErr:        false,
	},
		{
			name: "SPDX with DESCRIBES relationship populates pUrl from described element",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.HasSBOMIngest{},
					"HasSBOM")},
			doc: &processor.Document{
				Blob: []byte(`
			{
			"spdxVersion": "SPDX-2.3",
			"SPDXID":"SPDXRef-DOCUMENT",
			"name":"sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
			"packages":[
				{
					"SPDXID":"SPDXRef-Package-sha256-a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
					"name":"sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
					"externalRefs":[
						{
							"referenceCategory":"PACKAGE_MANAGER",
							"referenceLocator":"pkg:oci/image@sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10?mediaType=application%2Fvnd.oci.image.manifest.v1%2Bjson",
							"referenceType":"purl"
						}
					]
				}
			],
			"relationships":[
				{
					"spdxElementId":"SPDXRef-DOCUMENT",
					"relationshipType":"DESCRIBES",
					"relatedSpdxElement":"SPDXRef-Package-sha256-a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10"
				}
			]
			}
			`),
				Format: processor.FormatJSON,
				Type:   processor.DocumentSPDX,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			wantPredicates: &assembler.IngestPredicates{
				HasSBOM: []assembler.HasSBOMIngest{
					{Pkg: pUrlToPkgDiscardError("pkg:oci/image@sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10?mediaType=application%2Fvnd.oci.image.manifest.v1%2Bjson")},
				},
			},
			wantErr: false,
		},
		{
			name: "SPDX with multiple DESCRIBES relationship populates multiple pUrls from described element",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.HasSBOMIngest{},
					"HasSBOM")},
			doc: &processor.Document{
				Blob: []byte(`
			{
			"spdxVersion": "SPDX-2.3",
			"SPDXID":"SPDXRef-DOCUMENT",
			"name":"sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
			"packages":[
				{
					"SPDXID":"SPDXRef-Package-sha256-a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
					"name":"sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
					"externalRefs":[
						{
							"referenceCategory":"PACKAGE_MANAGER",
							"referenceLocator":"pkg:oci/image@sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10?mediaType=application%2Fvnd.oci.image.manifest.v1%2Bjson",
							"referenceType":"purl"
						}
					]
				},
				{
					"SPDXID":"SPDXRef-Package-sha256-abc123",
					"name":"sha256:abc123",
					"externalRefs":[
						{
							"referenceCategory":"PACKAGE_MANAGER",
							"referenceLocator":"pkg:oci/image@sha256:abc123?mediaType=application%2Fvnd.oci.image.manifest.v1%2Bjson",
							"referenceType":"purl"
						}
					]
				}
			],
			"relationships":[
				{
					"spdxElementId":"SPDXRef-DOCUMENT",
					"relationshipType":"DESCRIBES",
					"relatedSpdxElement":"SPDXRef-Package-sha256-a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10"
				},
				{
					"spdxElementId":"SPDXRef-DOCUMENT",
					"relationshipType":"DESCRIBES",
					"relatedSpdxElement":"SPDXRef-Package-sha256-abc123"
				}
			]
			}
			`),
				Format: processor.FormatJSON,
				Type:   processor.DocumentSPDX,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			wantPredicates: &assembler.IngestPredicates{
				HasSBOM: []assembler.HasSBOMIngest{
					{Pkg: pUrlToPkgDiscardError("pkg:oci/image@sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10?mediaType=application%2Fvnd.oci.image.manifest.v1%2Bjson")},
					{Pkg: pUrlToPkgDiscardError("pkg:oci/image@sha256:abc123?mediaType=application%2Fvnd.oci.image.manifest.v1%2Bjson")},
				},
			},
			wantErr: false,
		},
		{
			name: "SPDX with DESCRIBED_BY relationship populates pUrl from described element",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.HasSBOMIngest{},
					"HasSBOM")},
			doc: &processor.Document{
				Blob: []byte(`
		{
		"spdxVersion": "SPDX-2.3",
		"SPDXID":"SPDXRef-DOCUMENT",
		"name":"sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
		"packages":[
				{
					"SPDXID":"SPDXRef-Package-sha256-a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
					"name":"sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
					"externalRefs":[
						{
							"referenceCategory":"PACKAGE_MANAGER",
							"referenceLocator":"pkg:oci/image@sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10?mediaType=application%2Fvnd.oci.image.manifest.v1%2Bjson",
							"referenceType":"purl"
						}
					]
				}
			],
		"relationships":[
			{
				"spdxElementId":"SPDXRef-Package-sha256-a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
				"relationshipType":"DESCRIBED_BY",
				"relatedSpdxElement":"SPDXRef-DOCUMENT"
			}
		]
		}
	`),
				Format: processor.FormatJSON,
				Type:   processor.DocumentSPDX,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			wantPredicates: &assembler.IngestPredicates{
				HasSBOM: []assembler.HasSBOMIngest{
					{Pkg: pUrlToPkgDiscardError("pkg:oci/image@sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10?mediaType=application%2Fvnd.oci.image.manifest.v1%2Bjson")},
				},
			},
			wantErr: false,
		},
		{
			name: "SPDX with DESCRIBED_BY relationship but no corresponding package reverts to using heuristic top level package",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.HasSBOMIngest{},
					"HasSBOM")},
			doc: &processor.Document{
				Blob: []byte(`
		{
		"spdxVersion": "SPDX-2.3",
		"SPDXID":"SPDXRef-DOCUMENT",
		"name":"sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
		"relationships":[
			{
				"spdxElementId":"SPDXRef-Package-sha256-a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
				"relationshipType":"DESCRIBED_BY",
				"relatedSpdxElement":"SPDXRef-DOCUMENT"
			}
		]
		}
	`),
				Format: processor.FormatJSON,
				Type:   processor.DocumentSPDX,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			wantPredicates: &assembler.IngestPredicates{
				HasSBOM: []assembler.HasSBOMIngest{
					{Pkg: pUrlToPkgDiscardError("pkg:guac/spdx/sbom-sha256%3Aa743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10")},
				},
			},
			wantErr: false,
		},
		{
			name: "SPDX with documentDescribes field",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.HasSBOMIngest{},
					"HasSBOM")},
			doc: &processor.Document{
				Blob: []byte(`
		{
			"SPDXID":"SPDXRef-DOCUMENT",
			"spdxVersion": "SPDX-2.2",
			"documentDescribes": [
				"SPDXRef-6dcd47a4-bfcb-47d7-8ee4-60b6dc4861a8"
			],
			"name":"sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
			"packages":[
				{
					"SPDXID": "SPDXRef-8c5bc68a-d747-48de-b737-bc9703c330e7",
					"externalRefs": [
						{
							"referenceCategory": "PACKAGE_MANAGER",
							"referenceLocator": "pkg:rpm/redhat/python3-libcomps@0.1.18-1.el9?arch=x86_64",
							"referenceType": "purl"
						}
					],
					"packageFileName": "python3-libcomps-0.1.18-1.el9.x86_64.rpm",
					"versionInfo": "python3-libcomps-0.1.18-1.el9.x86_64"
				},
				{
					"SPDXID": "SPDXRef-6dcd47a4-bfcb-47d7-8ee4-60b6dc4861a8",
					"externalRefs": [
						{
							"referenceCategory": "PACKAGE_MANAGER",
							"referenceLocator": "pkg:oci/redhat/ubi9-container@sha256:4227a4b5013999a412196237c62e40d778d09cdc751720a66ff3701fbe5a4a9d?repository_url=registry.redhat.io/ubi9&tag=9.1.0-1750",
							"referenceType": "purl"
						}
					],
					"name": "ubi9-container",
					"versionInfo": "ubi9-container-9.1.0-1750.noarch"
				}
			],
			"relationships":[
				{
					"relatedSpdxElement": "SPDXRef-6dcd47a4-bfcb-47d7-8ee4-60b6dc4861a8",
					"relationshipType": "CONTAINED_BY",
					"spdxElementId": "SPDXRef-8c5bc68a-d747-48de-b737-bc9703c330e7"
				},
				{
					"relatedSpdxElement": "SPDXRef-6dcd47a4-bfcb-47d7-8ee4-60b6dc4861a8",
					"relationshipType": "DESCRIBES",
					"spdxElementId": "SPDXRef-DOCUMENT"
				}
			]
		}
	`),
				Format: processor.FormatJSON,
				Type:   processor.DocumentSPDX,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			wantPredicates: &assembler.IngestPredicates{
				IsDependency: []assembler.IsDependencyIngest{
					{
						Pkg:             pUrlToPkgDiscardError("pkg:oci/redhat/ubi9-container@sha256:4227a4b5013999a412196237c62e40d778d09cdc751720a66ff3701fbe5a4a9d?repository_url=registry.redhat.io/ubi9&tag=9.1.0-1750"),
						DepPkg:          pUrlToPkgDiscardError("pkg:rpm/redhat/python3-libcomps@0.1.18-1.el9?arch=x86_64"),
						DepPkgMatchFlag: generated.MatchFlags{Pkg: generated.PkgMatchTypeSpecificVersion},
						IsDependency: &generated.IsDependencyInputSpec{
							DependencyType: generated.DependencyTypeUnknown,
							VersionRange:   "0.1.18-1.el9",
							Justification:  "Derived from SPDX CONTAINED_BY relationship",
						},
					},
				},
				HasSBOM: []assembler.HasSBOMIngest{
					{Pkg: pUrlToPkgDiscardError("pkg:oci/redhat/ubi9-container@sha256:4227a4b5013999a412196237c62e40d778d09cdc751720a66ff3701fbe5a4a9d?repository_url=registry.redhat.io/ubi9&tag=9.1.0-1750")},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSpdxParser()
			err := s.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("spdxParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			preds := s.GetPredicates(ctx)
			opts := append(testdata.IngestPredicatesCmpOpts, tt.additionalOpts...)
			if d := cmp.Diff(tt.wantPredicates, preds, opts...); len(d) != 0 {
				t.Errorf("spdx.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}
