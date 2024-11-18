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
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	asmhelpers "github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func pUrlToPkgDiscardError(pUrl string) *generated.PkgInputSpec {
	pkg, _ := asmhelpers.PurlToPkg(pUrl)
	return pkg
}

func Test_spdxParser(t *testing.T) {
	packageOfns := "spdx"
	packageXns := "pkg/golang.org/x"
	depPackageOfVersion := "sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10"
	packageOfEmptyString := ""
	tests := []struct {
		name           string
		additionalOpts []cmp.Option
		doc            *processor.Document
		wantPredicates *assembler.IngestPredicates
		wantErr        bool
		wantWarning    string
	}{
		{
			name: "valid big SPDX document",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(generated.HasMetadataInputSpec{},
					"Timestamp"),
			},
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
			name: "SPDX with PACKAGE_OF relationship populates pUrl from described element",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.HasSBOMIngest{},
					"HasSBOM"),
			},
			doc: &processor.Document{
				Blob: []byte(`
			{
			"spdxVersion": "SPDX-2.3",
			"SPDXID":"SPDXRef-DOCUMENT",
			"name":"sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
			"creationInfo": { "created": "2023-01-01T01:01:01.00Z" },
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
					"relationshipType":"PACKAGE_OF",
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
				IsDependency: []assembler.IsDependencyIngest{
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: &packageOfns,
							Name:      "sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
							Version:   &packageOfEmptyString,
							Subpath:   &packageOfEmptyString,
						},
						DepPkg: &generated.PkgInputSpec{
							Type:       "oci",
							Namespace:  &packageOfEmptyString,
							Name:       "image",
							Version:    &depPackageOfVersion,
							Qualifiers: []generated.PackageQualifierInputSpec{{Key: "mediatype", Value: "application/vnd.oci.image.manifest.v1+json"}},
							Subpath:    &packageOfEmptyString,
						},
						IsDependency: &generated.IsDependencyInputSpec{
							DependencyType: "UNKNOWN",
							Justification:  "top-level package GUAC heuristic connecting to each file/package",
						},
					},
				},

				HasSBOM: []assembler.HasSBOMIngest{
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: &packageOfns,
							Name:      "sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
							Version:   &packageOfEmptyString,
							Subpath:   &packageOfEmptyString,
						},
						HasSBOM: &generated.HasSBOMInputSpec{
							Uri:              "https://anchore.com/syft/image/alpine-latest-e78eca08-d9f4-49c7-97e0-6d4b9bfa99c2",
							Algorithm:        "sha256",
							Digest:           "ba096464061993bbbdfc30a26b42cd8beb1bfff301726fe6c58cb45d468c7648",
							DownloadLocation: "TestSource",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "SPDX with DESCRIBES relationship populates pUrl from described element",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.HasSBOMIngest{},
					"HasSBOM"),
			},
			doc: &processor.Document{
				Blob: []byte(`
			{
			"spdxVersion": "SPDX-2.3",
			"SPDXID":"SPDXRef-DOCUMENT",
			"name":"sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
			"creationInfo": { "created": "2023-01-01T01:01:01.00Z" },
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
					"HasSBOM"),
			},
			doc: &processor.Document{
				Blob: []byte(`
			{
			"spdxVersion": "SPDX-2.3",
			"SPDXID":"SPDXRef-DOCUMENT",
			"name":"sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
			"creationInfo": { "created": "2022-09-24T17:27:55.556104Z" },
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
					"HasSBOM"),
			},
			doc: &processor.Document{
				Blob: []byte(`
		{
		"spdxVersion": "SPDX-2.3",
		"SPDXID":"SPDXRef-DOCUMENT",
		"name":"sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
		"creationInfo": { "created": "2022-09-24T17:27:55.556104Z" },
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
					"HasSBOM"),
			},
			doc: &processor.Document{
				Blob: []byte(`
		{
		"spdxVersion": "SPDX-2.3",
		"SPDXID":"SPDXRef-DOCUMENT",
		"name":"sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
		"creationInfo": { "created": "2022-09-24T17:27:55.556104Z" },
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
					"HasSBOM"),
			},
			doc: &processor.Document{
				Blob: []byte(`
		{
			"SPDXID":"SPDXRef-DOCUMENT",
			"spdxVersion": "SPDX-2.2",
			"documentDescribes": [
				"SPDXRef-6dcd47a4-bfcb-47d7-8ee4-60b6dc4861a8"
			],
			"name":"test-sbom",
			"creationInfo": { "created": "2022-09-24T17:27:55.556104Z" },
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
						Pkg:    pUrlToPkgDiscardError("pkg:oci/redhat/ubi9-container@sha256:4227a4b5013999a412196237c62e40d778d09cdc751720a66ff3701fbe5a4a9d?repository_url=registry.redhat.io/ubi9&tag=9.1.0-1750"),
						DepPkg: pUrlToPkgDiscardError("pkg:rpm/redhat/python3-libcomps@0.1.18-1.el9?arch=x86_64"),
						IsDependency: &generated.IsDependencyInputSpec{
							DependencyType: generated.DependencyTypeUnknown,
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
		{
			name: "SPDX with files that have 0000 hash file representation",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.HasSBOMIngest{},
					"HasSBOM"),
			},
			doc: &processor.Document{
				Blob: []byte(`
		{
			"SPDXID":"SPDXRef-DOCUMENT",
			"spdxVersion": "SPDX-2.2",
			"name":"testsbom",
			"creationInfo": { "created": "2022-09-24T17:27:55.556104Z" },
			"files":[
				{
				  "fileName": "file1",
				  "SPDXID": "SPDXRef-3431c9f4f2277e36",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "SHA1",
					  "checksumValue": "0000000000000000000000000000000000000000"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
				{
				  "fileName": "file2",
				  "SPDXID": "SPDXRef-def1c9f4f2277e36",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "SHA256",
					  "checksumValue": "0000000000000000000000000000000000000000000000000000000000000000"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
				{
				  "fileName": "./include-file",
				  "SPDXID": "SPDXRef-aef1c9f4f2277e36",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "SHA1",
					  "checksumValue": "ba1c68d88439599dcca7594d610030a19eda4f63"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
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
						Pkg:    pUrlToPkgDiscardError("pkg:guac/spdx/testsbom"),
						DepPkg: pUrlToPkgDiscardError("pkg:guac/files/sha1:ba1c68d88439599dcca7594d610030a19eda4f63?filename=./include-file"),
						IsDependency: &generated.IsDependencyInputSpec{
							DependencyType: generated.DependencyTypeUnknown,
							Justification:  "top-level package GUAC heuristic connecting to each file/package",
						},
					},
				},
				IsOccurrence: []assembler.IsOccurrenceIngest{
					{
						Pkg: pUrlToPkgDiscardError("pkg:guac/files/sha1:ba1c68d88439599dcca7594d610030a19eda4f63?filename=./include-file"),
						Artifact: &generated.ArtifactInputSpec{
							Algorithm: "sha1",
							Digest:    "ba1c68d88439599dcca7594d610030a19eda4f63",
						},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx file with checksum"},
					},
				},
				HasSBOM: []assembler.HasSBOMIngest{
					{Pkg: pUrlToPkgDiscardError("pkg:guac/spdx/testsbom")},
				},
			},
			wantErr: false,
		},
		{
			name: "SPDX with files that have empty file hash representation",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.HasSBOMIngest{},
					"HasSBOM"),
			},
			doc: &processor.Document{
				Blob: []byte(`
		{
			"SPDXID":"SPDXRef-DOCUMENT",
			"spdxVersion": "SPDX-2.2",
			"name":"testsbom",
			"creationInfo": { "created": "2022-09-24T17:27:55.556104Z" },
			"files":[
				{
				  "fileName": "file1",
				  "SPDXID": "SPDXRef-3431c9f4f2277e36",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "SHA1",
					  "checksumValue": "0000000000000000000000000000000000000000"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
				{
				  "fileName": "file2",
				  "SPDXID": "SPDXRef-def1c9f4f2277e36",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "SHA256",
					  "checksumValue": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
				{
				  "fileName": "file2",
				  "SPDXID": "SPDXRef-dde3c9f4f2277e36",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "SHA512",
					  "checksumValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
				{
				  "fileName": "./include-file",
				  "SPDXID": "SPDXRef-aef1c9f4f2277e36",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "SHA1",
					  "checksumValue": "ba1c68d88439599dcca7594d610030a19eda4f63"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
				{
				  "fileName": "./include-file",
				  "SPDXID": "SPDXRef-aef1c9f4f2277e36",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "SHA224",
					  "checksumValue": "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
				{
				  "fileName": "./include-file",
				  "SPDXID": "SPDXRef-aef1c9f4f2277e36",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "SHA384",
					  "checksumValue": "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
				{
				  "fileName": "./include-file",
				  "SPDXID": "SPDXRef-aef1c9f4f2277e36",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "SHA3-256",
					  "checksumValue": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
								{
				  "fileName": "./include-file",
				  "SPDXID": "SPDXRef-aef1c9f4f2277e37",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "MD5",
					  "checksumValue": "d41d8cd98f00b204e9800998ecf8427e"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				}
				,
				{
				  "fileName": "./include-file",
				  "SPDXID": "SPDXRef-aef1c9f4f2277e38",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "adler",
					  "checksumValue": "00000001"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
				{
				  "fileName": "./include-file",
				  "SPDXID": "SPDXRef-aef1c9f4f2277e39",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "SHA3-384",
					  "checksumValue": "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
				{
				  "fileName": "./include-file",
				  "SPDXID": "SPDXRef-aef1c9f4f2277e39",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "SHA3-512",
					  "checksumValue": "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
				{
				  "fileName": "./include-file",
				  "SPDXID": "SPDXRef-aef1c9f4f2277e39",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "BLAKE2b-256",
					  "checksumValue": "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
				{
				  "fileName": "./include-file",
				  "SPDXID": "SPDXRef-aef1c9f4f2277e39",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "BLAKE2b-384",
					  "checksumValue": "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
				},
				{
				  "fileName": "./include-file",
				  "SPDXID": "SPDXRef-aef1c9f4f2277e39",
				  "fileTypes": [
					"TEXT"
				  ],
				  "checksums": [
					{
					  "algorithm": "BLAKE2b-512",
					  "checksumValue": "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
					}
				  ],
				  "licenseConcluded": "NOASSERTION",
				  "copyrightText": ""
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
						Pkg:    pUrlToPkgDiscardError("pkg:guac/spdx/testsbom"),
						DepPkg: pUrlToPkgDiscardError("pkg:guac/files/sha1:ba1c68d88439599dcca7594d610030a19eda4f63?filename=./include-file"),
						IsDependency: &generated.IsDependencyInputSpec{
							DependencyType: generated.DependencyTypeUnknown,
							Justification:  "top-level package GUAC heuristic connecting to each file/package",
						},
					},
				},
				IsOccurrence: []assembler.IsOccurrenceIngest{
					{
						Pkg: pUrlToPkgDiscardError("pkg:guac/files/sha1:ba1c68d88439599dcca7594d610030a19eda4f63?filename=./include-file"),
						Artifact: &generated.ArtifactInputSpec{
							Algorithm: "sha1",
							Digest:    "ba1c68d88439599dcca7594d610030a19eda4f63",
						},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx file with checksum"},
					},
				},
				HasSBOM: []assembler.HasSBOMIngest{
					{Pkg: pUrlToPkgDiscardError("pkg:guac/spdx/testsbom")},
				},
			},
			wantErr: false,
		},
		{
			name: "SPDX with complex license expression",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.IngestPredicates{},
					"HasSBOM", "IsDependency", "IsOccurrence"),
			},
			doc: &processor.Document{
				Blob: []byte(`
{
  "SPDXID":"SPDXRef-DOCUMENT",
  "spdxVersion": "SPDX-2.2",
  "name":"testsbom",
  "creationInfo": {
    "created": "2022-09-24T17:27:55.556104Z",
    "licenseListVersion": "1.2.3"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-35085779bdf473bb",
      "name": "mypackage",
      "licenseConcluded": "NOASSERTION",
      "description": "Alpine base dir structure and init scripts",
      "downloadLocation": "https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout",
      "filesAnalyzed": false,
      "licenseDeclared": "(BSD-3-Clause OR BSD-2-Clause) AND Apache-2.0",
      "copyrightText": "Copyright (c) 2022 Authors of MyPackage",
      "originator": "Person: Natanael Copa <ncopa@alpinelinux.org>",
      "sourceInfo": "acquired package info from APK DB: /lib/apk/db/installed",
      "versionInfo": "3.2.0-r22"
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
				CertifyLegal: []assembler.CertifyLegalIngest{
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "mypackage",
							Version:   ptrfrom.String("3.2.0-r22"),
							Subpath:   ptrfrom.String(""),
						},
						Declared: []generated.LicenseInputSpec{
							{
								Name:        "BSD-3-Clause",
								ListVersion: ptrfrom.String("1.2.3"),
							},
							{
								Name:        "BSD-2-Clause",
								ListVersion: ptrfrom.String("1.2.3"),
							},
							{
								Name:        "Apache-2.0",
								ListVersion: ptrfrom.String("1.2.3"),
							},
						},
						Discovered: []generated.LicenseInputSpec{
							{
								Name:        "NOASSERTION",
								ListVersion: ptrfrom.String("1.2.3"),
							},
						},
						CertifyLegal: &generated.CertifyLegalInputSpec{
							DeclaredLicense:   "(BSD-3-Clause OR BSD-2-Clause) AND Apache-2.0",
							DiscoveredLicense: "NOASSERTION",
							Attribution:       "Copyright (c) 2022 Authors of MyPackage",
							Justification:     "Found in SPDX document.",
							TimeScanned:       parseRfc3339("2022-09-24T17:27:55.556104Z"),
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "SPDX with differing licenses",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.IngestPredicates{},
					"HasSBOM", "IsDependency", "IsOccurrence"),
			},
			doc: &processor.Document{
				Blob: []byte(`
{
  "SPDXID":"SPDXRef-DOCUMENT",
  "spdxVersion": "SPDX-2.2",
  "name":"testsbom",
  "creationInfo": {
    "created": "2022-09-24T17:27:55.556104Z",
    "licenseListVersion": "1.2.3"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-35085779bdf473bb",
      "name": "mypackage",
      "licenseConcluded": "MIT AND GPL-2.0-only",
      "description": "Alpine base dir structure and init scripts",
      "downloadLocation": "https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout",
      "filesAnalyzed": false,
      "licenseDeclared": "MIT",
      "copyrightText": "Copyright (c) 2022 Authors of MyPackage",
      "originator": "Person: Natanael Copa <ncopa@alpinelinux.org>",
      "sourceInfo": "acquired package info from APK DB: /lib/apk/db/installed",
      "versionInfo": "3.2.0-r22",
      "licenseComments": "Scanned with ScanCode"
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
				CertifyLegal: []assembler.CertifyLegalIngest{
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "mypackage",
							Version:   ptrfrom.String("3.2.0-r22"),
							Subpath:   ptrfrom.String(""),
						},
						Declared: []generated.LicenseInputSpec{
							{
								Name:        "MIT",
								ListVersion: ptrfrom.String("1.2.3"),
							},
						},
						Discovered: []generated.LicenseInputSpec{
							{
								Name:        "MIT",
								ListVersion: ptrfrom.String("1.2.3"),
							},
							{
								Name:        "GPL-2.0-only",
								ListVersion: ptrfrom.String("1.2.3"),
							},
						},
						CertifyLegal: &generated.CertifyLegalInputSpec{
							DeclaredLicense:   "MIT",
							DiscoveredLicense: "MIT AND GPL-2.0-only",
							Attribution:       "Copyright (c) 2022 Authors of MyPackage",
							Justification:     "Found in SPDX document. : Scanned with ScanCode",
							TimeScanned:       parseRfc3339("2022-09-24T17:27:55.556104Z"),
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "SPDX with custom licenses",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.IngestPredicates{},
					"HasSBOM", "IsDependency", "IsOccurrence"),
			},
			doc: &processor.Document{
				Blob: []byte(`
{
  "SPDXID":"SPDXRef-DOCUMENT",
  "spdxVersion": "SPDX-2.2",
  "name":"testsbom",
  "creationInfo": {
    "created": "2022-09-24T17:27:55.556104Z",
    "licenseListVersion": "1.2.3"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-35085779bdf473bb",
      "name": "mypackage",
      "description": "Alpine base dir structure and init scripts",
      "downloadLocation": "https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout",
      "filesAnalyzed": false,
      "licenseDeclared": "LicenseRef-Custom",
      "copyrightText": "Copyright (c) 2022 Authors of MyPackage",
      "originator": "Person: Natanael Copa <ncopa@alpinelinux.org>",
      "sourceInfo": "acquired package info from APK DB: /lib/apk/db/installed",
      "versionInfo": "3.2.0-r22"
    }
  ],
  "hasExtractedLicensingInfos": [
    {
      "licenseId": "LicenseRef-Custom",
      "extractedText": "Redistribution and use of the this code or any derivative works are permitted provided that the following conditions are met...",
      "name": "Custom License"
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
				CertifyLegal: []assembler.CertifyLegalIngest{
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "mypackage",
							Version:   ptrfrom.String("3.2.0-r22"),
							Subpath:   ptrfrom.String(""),
						},
						Declared: []generated.LicenseInputSpec{
							{
								Name:   "LicenseRef-2ba8ded3",
								Inline: ptrfrom.String("Redistribution and use of the this code or any derivative works are permitted provided that the following conditions are met..."),
							},
						},
						CertifyLegal: &generated.CertifyLegalInputSpec{
							DeclaredLicense: "LicenseRef-2ba8ded3",
							Attribution:     "Copyright (c) 2022 Authors of MyPackage",
							Justification:   "Found in SPDX document.",
							TimeScanned:     parseRfc3339("2022-09-24T17:27:55.556104Z"),
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "SPDX v2.2 with an empty relationship value (see https://github.com/guacsec/guac/issues/1821)",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(generated.HasSBOMInputSpec{},
					"KnownSince"),
			}, doc: &processor.Document{
				Blob: []byte(`
				{
					"spdxVersion": "SPDX-2.2",
					"dataLicense": "CC0-1.0",
					"SPDXID": "SPDXRef-DOCUMENT",
					"creationInfo": {
					  "created": "2020-11-24T01:12:27Z"
					},
					"name": "empty-relationship.spdx.json",
					"documentNamespace": "https://example.com/for-testing",
					"documentDescribes": [
					  "SPDXRef-go-module-golang.org/x/text"
					],
					"packages": [
					  {
						"name": "golang.org/x/text",
						"SPDXID": "SPDXRef-go-module-golang.org/x/text",
						"downloadLocation": "go://golang.org/x/text@v0.0.0-20170915032832-14c0d48ead0c",
						"filesAnalyzed": false,
						"packageLicenseConcluded": "NOASSERTION",
						"packageLicenseDeclared": "NOASSERTION",
						"packageCopyrightText": "NOASSERTION"
					  }
					],
					"relationships": [
						{}
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
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: &packageXns,
							Name:      "text",
							Version:   &packageOfEmptyString,
							Subpath:   &packageOfEmptyString,
						},
						HasSBOM: &generated.HasSBOMInputSpec{
							Uri:              "https://example.com/for-testing",
							Algorithm:        "sha256",
							Digest:           "f0b160c3bc9001b17b1bdc0e398bd75b80cbe8ab8df48bc7a545ec5d9802c66d",
							DownloadLocation: "TestSource",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "SPDX v2.3 with package with a checksum described by the SBOM",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(generated.HasSBOMInputSpec{},
					"KnownSince"),
			}, doc: &processor.Document{
				Blob: []byte(`
				{
					"spdxVersion": "SPDX-2.3",
					"dataLicense": "CC0-1.0",
					"SPDXID": "SPDXRef-DOCUMENT",
					"creationInfo": {
					  "created": "2024-04-30T01:12:27Z"
					},
					"name": "for-testing-a-pkg-with-checksum",
					"documentNamespace": "https://example.com/for-testing-a-pkg-with-checksum",
					"packages": [
					  {
						"name": "for-testing-a-pkg-with-checksum-pkg",
						"SPDXID": "SPDXRef-Package-for-testing-a-pkg-with-checksum-pkg",
						"downloadLocation": "https://example.com/for-testing-a-pkg-with-checksum-pkg",
						"checksums": [
							{
								"algorithm": "SHA1",
								"checksumValue": "pkgsha1"
							},
							{
								"algorithm": "SHA3-384",
								"checksumValue": "pkgsha3-384"
							}
						]
					}
					],
					"relationships": [
						{
							"spdxElementId": "SPDXRef-DOCUMENT",
							"relationshipType": "DESCRIBES",
							"relatedSpdxElement": "SPDXRef-Package-for-testing-a-pkg-with-checksum-pkg"
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
					{
						Artifact: &generated.ArtifactInputSpec{Algorithm: "sha1", Digest: "pkgsha1"},
						HasSBOM: &generated.HasSBOMInputSpec{
							Uri:              "https://example.com/for-testing-a-pkg-with-checksum",
							Algorithm:        "sha256",
							Digest:           "1a8c41553b593172ff06e036ca8dc411aa228ab4c266d162640df69f7414e2c1",
							DownloadLocation: "TestSource",
						},
					},
					{
						Artifact: &generated.ArtifactInputSpec{Algorithm: "sha3-384", Digest: "pkgsha3-384"},
						HasSBOM: &generated.HasSBOMInputSpec{
							Uri:              "https://example.com/for-testing-a-pkg-with-checksum",
							Algorithm:        "sha256",
							Digest:           "1a8c41553b593172ff06e036ca8dc411aa228ab4c266d162640df69f7414e2c1",
							DownloadLocation: "TestSource",
						},
					},
				},
				IsOccurrence: []assembler.IsOccurrenceIngest{
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "for-testing-a-pkg-with-checksum-pkg",
							Version:   &packageOfEmptyString,
							Subpath:   &packageOfEmptyString,
						},
						Artifact:     &generated.ArtifactInputSpec{Algorithm: "sha1", Digest: "pkgsha1"},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx package with checksum"},
					},
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "for-testing-a-pkg-with-checksum-pkg",
							Version:   &packageOfEmptyString,
							Subpath:   &packageOfEmptyString,
						},
						Artifact:     &generated.ArtifactInputSpec{Algorithm: "sha3-384", Digest: "pkgsha3-384"},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx package with checksum"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "SPDX v2.3 with a file with a checksum described by the SBOM",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(generated.HasSBOMInputSpec{},
					"KnownSince"),
			}, doc: &processor.Document{
				Blob: []byte(`
				{
					"spdxVersion": "SPDX-2.3",
					"dataLicense": "CC0-1.0",
					"SPDXID": "SPDXRef-DOCUMENT",
					"creationInfo": {
					  "created": "2024-04-30T01:12:27Z"
					},
					"name": "for-testing-an-art-with-checksum",
					"documentNamespace": "https://example.com/for-testing-an-art-with-checksum",
					"files": [
					  {
						"filename": "for-testing-an-art-with-checksum-file",
						"SPDXID": "SPDXRef-File-for-testing-an-art-with-checksum",
						"downloadLocation": "https://example.com/for-testing-an-art-with-checksum-file",
						"checksums": [
							{
								"algorithm": "SHA1",
								"checksumValue": "filesha1"
							},
							{
								"algorithm": "SHA3-384",
								"checksumValue": "filesha3-384"
							}
						]
					}
					],
					"relationships": [
						{
							"spdxElementId": "SPDXRef-DOCUMENT",
							"relationshipType": "DESCRIBES",
							"relatedSpdxElement": "SPDXRef-File-for-testing-an-art-with-checksum"
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
					{
						Artifact: &generated.ArtifactInputSpec{Algorithm: "sha1", Digest: "filesha1"},
						HasSBOM: &generated.HasSBOMInputSpec{
							Uri:              "https://example.com/for-testing-an-art-with-checksum",
							Algorithm:        "sha256",
							Digest:           "7c809829c97c7f0b2941830013233ccf14b2ada200cdf77c54b95021961a0aa3",
							DownloadLocation: "TestSource",
						},
					},
					{
						Artifact: &generated.ArtifactInputSpec{Algorithm: "sha3-384", Digest: "filesha3-384"},
						HasSBOM: &generated.HasSBOMInputSpec{
							Uri:              "https://example.com/for-testing-an-art-with-checksum",
							Algorithm:        "sha256",
							Digest:           "7c809829c97c7f0b2941830013233ccf14b2ada200cdf77c54b95021961a0aa3",
							DownloadLocation: "TestSource",
						},
					},
				},
				IsOccurrence: []assembler.IsOccurrenceIngest{
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("files"),
							Name:      "sha1:filesha1",
							Version:   &packageOfEmptyString,
							Qualifiers: []generated.PackageQualifierInputSpec{
								{
									Key:   "filename",
									Value: "for-testing-an-art-with-checksum-file",
								},
							},
							Subpath: &packageOfEmptyString,
						},
						Artifact:     &generated.ArtifactInputSpec{Algorithm: "sha1", Digest: "filesha1"},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx file with checksum"},
					},
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("files"),
							Name:      "sha1:filesha1",
							Version:   &packageOfEmptyString,
							Qualifiers: []generated.PackageQualifierInputSpec{
								{
									Key:   "filename",
									Value: "for-testing-an-art-with-checksum-file",
								},
							},
							Subpath: &packageOfEmptyString,
						},
						Artifact:     &generated.ArtifactInputSpec{Algorithm: "sha3-384", Digest: "filesha3-384"},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx file with checksum"},
					},
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("files"),
							Name:      "sha3-384:filesha3-384",
							Version:   &packageOfEmptyString,
							Qualifiers: []generated.PackageQualifierInputSpec{
								{
									Key:   "filename",
									Value: "for-testing-an-art-with-checksum-file",
								},
							},
							Subpath: &packageOfEmptyString,
						},
						Artifact:     &generated.ArtifactInputSpec{Algorithm: "sha1", Digest: "filesha1"},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx file with checksum"},
					},
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("files"),
							Name:      "sha3-384:filesha3-384",
							Version:   &packageOfEmptyString,
							Qualifiers: []generated.PackageQualifierInputSpec{
								{
									Key:   "filename",
									Value: "for-testing-an-art-with-checksum-file",
								},
							},
							Subpath: &packageOfEmptyString,
						},
						Artifact:     &generated.ArtifactInputSpec{Algorithm: "sha3-384", Digest: "filesha3-384"},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx file with checksum"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "SPDX v2.3 with package with a checksum described by the SBOM, and a package is DESCRIBED_BY the doc, but has no checksum",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(generated.HasSBOMInputSpec{},
					"KnownSince"),
			}, doc: &processor.Document{
				Blob: []byte(`
				{
					"spdxVersion": "SPDX-2.3",
					"dataLicense": "CC0-1.0",
					"SPDXID": "SPDXRef-DOCUMENT",
					"creationInfo": {
					  "created": "2024-04-30T01:12:27Z"
					},
					"name": "for-testing-with-checksum",
					"documentNamespace": "https://example.com/for-testing-with-checksum",
					"packages": [
					  {
						"name": "for-testing-with-checksum-pkg",
						"SPDXID": "SPDXRef-Package-for-testing-with-checksum-pkg",
						"downloadLocation": "https://example.com/for-testing-with-checksum-pkg",
						"checksums": [
							{
								"algorithm": "SHA1",
								"checksumValue": "pkgsha1"
							},
							{
								"algorithm": "SHA3-384",
								"checksumValue": "pkgsha3-384"
							}
						]
					},
					{
						"name": "for-testing-without-checksum-pkg",
						"SPDXID": "SPDXRef-Package-for-testing-without-checksum-pkg",
						"downloadLocation": "https://example.com/for-testing-without-checksum-pkg"
					}
					],
					"relationships": [
						{
							"spdxElementId": "SPDXRef-DOCUMENT",
							"relationshipType": "DESCRIBES",
							"relatedSpdxElement": "SPDXRef-Package-for-testing-with-checksum-pkg"
						},
						{
							"spdxElementId": "SPDXRef-Package-for-testing-with-checksum-pkg",
							"relationshipType": "DESCRIBED_BY",
							"relatedSpdxElement": "SPDXRef-DOCUMENT"
						},
						{
							"spdxElementId": "SPDXRef-Package-for-testing-without-checksum-pkg",
							"relationshipType": "DESCRIBED_BY",
							"relatedSpdxElement": "SPDXRef-DOCUMENT"
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
					{
						Artifact: &generated.ArtifactInputSpec{Algorithm: "sha1", Digest: "pkgsha1"},
						HasSBOM: &generated.HasSBOMInputSpec{
							Uri:              "https://example.com/for-testing-with-checksum",
							Algorithm:        "sha256",
							Digest:           "a9d161aa15f725b2a4ff31c940b8662a2444bae9cc8705dedc911dfee6e5b680",
							DownloadLocation: "TestSource",
						},
					},
					{
						Artifact: &generated.ArtifactInputSpec{Algorithm: "sha3-384", Digest: "pkgsha3-384"},
						HasSBOM: &generated.HasSBOMInputSpec{
							Uri:              "https://example.com/for-testing-with-checksum",
							Algorithm:        "sha256",
							Digest:           "a9d161aa15f725b2a4ff31c940b8662a2444bae9cc8705dedc911dfee6e5b680",
							DownloadLocation: "TestSource",
						},
					},
				},
				IsOccurrence: []assembler.IsOccurrenceIngest{
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "for-testing-with-checksum-pkg",
							Version:   &packageOfEmptyString,
							Subpath:   &packageOfEmptyString,
						},
						Artifact:     &generated.ArtifactInputSpec{Algorithm: "sha1", Digest: "pkgsha1"},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx package with checksum"},
					},
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "for-testing-with-checksum-pkg",
							Version:   &packageOfEmptyString,
							Subpath:   &packageOfEmptyString,
						},
						Artifact:     &generated.ArtifactInputSpec{Algorithm: "sha3-384", Digest: "pkgsha3-384"},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx package with checksum"},
					},
				},
			},
			wantErr:     false,
			wantWarning: "Top-level unique artifact count (1) and top-level package count (2) are mismatched. SBOM ingestion may not be as expected.",
		},
		{
			name: "SPDX with multiple referenceType=purl for a single package",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.HasSBOMIngest{},
					"HasSBOM"),
			},
			doc: &processor.Document{
				Blob: []byte(`
			{
			"spdxVersion": "SPDX-2.3",
			"SPDXID":"SPDXRef-DOCUMENT",
			"name":"openssl-3.0.7-18.el9_2",
			"creationInfo": { "created": "2023-01-01T01:01:01.00Z" },
			"packages":[
				{
					"SPDXID":"SPDXRef-SRPM",
					"name":"openssl",
					"versionInfo": "3.0.7-18.el9_2",
					"packageFileName": "openssl-3.0.7-18.el9_2.src.rpm",
					"externalRefs":[
						{
							"referenceCategory":"PACKAGE_MANAGER",
							"referenceLocator":"pkg:rpm/redhat/openssl@3.0.7-18.el9_2?repository_id=rhel-9-baseos-eus",
							"referenceType":"purl"
						},
						{
							"referenceCategory":"PACKAGE_MANAGER",
							"referenceLocator":"pkg:rpm/redhat/openssl@3.0.7-18.el9_2?repository_id=rhel-9-baseos-tus",
							"referenceType":"purl"
						}
					]
				}
			],
			"relationships":[
				{
					"spdxElementId":"SPDXRef-DOCUMENT",
					"relationshipType":"PACKAGE_OF",
					"relatedSpdxElement":"SPDXRef-SRPM"
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
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: &packageOfns,
							Name:      "openssl-3.0.7-18.el9_2",
							Version:   &packageOfEmptyString,
							Subpath:   &packageOfEmptyString,
						},
						DepPkg: &generated.PkgInputSpec{
							Type:      "rpm",
							Namespace: ptrfrom.String("redhat"),
							Name:      "openssl",
							Version:   ptrfrom.String("3.0.7-18.el9_2"),
							Qualifiers: []generated.PackageQualifierInputSpec{
								{Key: "repository_id", Value: "rhel-9-baseos-eus"},
							},
							Subpath: &packageOfEmptyString,
						},
						IsDependency: &generated.IsDependencyInputSpec{
							DependencyType: "UNKNOWN",
							Justification:  "top-level package GUAC heuristic connecting to each file/package",
						},
					},
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: &packageOfns,
							Name:      "openssl-3.0.7-18.el9_2",
							Version:   &packageOfEmptyString,
							Subpath:   &packageOfEmptyString,
						},
						DepPkg: &generated.PkgInputSpec{
							Type:      "rpm",
							Namespace: ptrfrom.String("redhat"),
							Name:      "openssl",
							Version:   ptrfrom.String("3.0.7-18.el9_2"),
							Qualifiers: []generated.PackageQualifierInputSpec{
								{Key: "repository_id", Value: "rhel-9-baseos-tus"},
							},
							Subpath: &packageOfEmptyString,
						},
						IsDependency: &generated.IsDependencyInputSpec{
							DependencyType: "UNKNOWN",
							Justification:  "top-level package GUAC heuristic connecting to each file/package",
						},
					},
				},

				HasSBOM: []assembler.HasSBOMIngest{
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: &packageOfns,
							Name:      "openssl-3.0.7-18.el9_2",
							Version:   &packageOfEmptyString,
							Subpath:   &packageOfEmptyString,
						},
						HasSBOM: &generated.HasSBOMInputSpec{
							Uri:              "https://anchore.com/syft/image/alpine-latest-e78eca08-d9f4-49c7-97e0-6d4b9bfa99c2",
							Algorithm:        "sha256",
							Digest:           "ba096464061993bbbdfc30a26b42cd8beb1bfff301726fe6c58cb45d468c7648",
							DownloadLocation: "TestSource",
						},
					},
				},
			},
			wantErr: false,
		}, {
			name: "SPDX with GENERATED_FROM relationship",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.HasSBOMIngest{},
					"HasSBOM"),
			},
			doc: &processor.Document{
				Blob: []byte(`
		{
		"spdxVersion": "SPDX-2.3",
		"SPDXID":"SPDXRef-DOCUMENT",
		"name":"sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
		"creationInfo": { "created": "2022-09-24T17:27:55.556104Z" },
		"packages":[
			{
			  "SPDXID": "SPDXRef-SRPM",
			  "name": "openssl",
			  "versionInfo": "3.0.7-18.el9_2",
			  "downloadLocation": "NOASSERTION",
			  "packageFileName": "openssl-3.0.7-18.el9_2.src.rpm",
			  "checksums": [
				{
				  "algorithm": "SHA256",
				  "checksumValue": "31b5079268339cff7ba65a0aee77930560c5adef4b1b3f8f5927a43ee46a56d9"
				}
			  ]
			},
			{
			  "SPDXID": "SPDXRef-aarch64-openssl-perl",
			  "name": "openssl-perl",
			  "versionInfo": "3.0.7-18.el9_2",
			  "downloadLocation": "NOASSERTION",
			  "packageFileName": "openssl-perl-3.0.7-18.el9_2.aarch64.rpm",
			  "checksums": [
				{
				  "algorithm": "SHA256",
				  "checksumValue": "96e53b2da90ce5ad109ba659ce3ed1b5a819b108c95fc493f84847429898b2ed"
				}
			  ]
			}
		],
		"relationships":[
			{
			  "spdxElementId": "SPDXRef-DOCUMENT",
			  "relationshipType": "DESCRIBES",
			  "relatedSpdxElement": "SPDXRef-SRPM"
			},
			{
			  "spdxElementId": "SPDXRef-aarch64-openssl-perl",
			  "relationshipType": "GENERATED_FROM",
			  "relatedSpdxElement": "SPDXRef-SRPM"
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
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "openssl-perl",
							Version:   ptrfrom.String("3.0.7-18.el9_2"),
							Subpath:   &packageOfEmptyString,
						},
						DepPkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "openssl",
							Version:   ptrfrom.String("3.0.7-18.el9_2"),
							Subpath:   &packageOfEmptyString,
						},
						IsDependency: &generated.IsDependencyInputSpec{
							DependencyType: "UNKNOWN",
							Justification:  "Derived from SPDX GENERATED_FROM relationship",
						},
					},
				},
				IsOccurrence: []assembler.IsOccurrenceIngest{
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "openssl",
							Version:   ptrfrom.String("3.0.7-18.el9_2"),
							Subpath:   &packageOfEmptyString,
						},
						Artifact: &generated.ArtifactInputSpec{
							Algorithm: "sha256",
							Digest:    "31b5079268339cff7ba65a0aee77930560c5adef4b1b3f8f5927a43ee46a56d9",
						},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx package with checksum"},
					},
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "openssl-perl",
							Version:   ptrfrom.String("3.0.7-18.el9_2"),
							Subpath:   &packageOfEmptyString,
						},
						Artifact: &generated.ArtifactInputSpec{
							Algorithm: "sha256",
							Digest:    "96e53b2da90ce5ad109ba659ce3ed1b5a819b108c95fc493f84847429898b2ed",
						},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx package with checksum"},
					},
				},
				HasSBOM: []assembler.HasSBOMIngest{
					{
						Artifact: &generated.ArtifactInputSpec{
							Algorithm: "sha256",
							Digest:    "31b5079268339cff7ba65a0aee77930560c5adef4b1b3f8f5927a43ee46a56d9",
						},
					},
				},
			},
			wantErr: false,
		}, {
			name: "SPDX with GENERATES relationship",
			additionalOpts: []cmp.Option{
				cmpopts.IgnoreFields(assembler.HasSBOMIngest{},
					"HasSBOM"),
			},
			doc: &processor.Document{
				Blob: []byte(`
		{
		"spdxVersion": "SPDX-2.3",
		"SPDXID":"SPDXRef-DOCUMENT",
		"name":"sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
		"creationInfo": { "created": "2022-09-24T17:27:55.556104Z" },
		"packages":[
			{
			  "SPDXID": "SPDXRef-SRPM",
			  "name": "openssl",
			  "versionInfo": "3.0.7-18.el9_2",
			  "downloadLocation": "NOASSERTION",
			  "packageFileName": "openssl-3.0.7-18.el9_2.src.rpm",
			  "checksums": [
				{
				  "algorithm": "SHA256",
				  "checksumValue": "31b5079268339cff7ba65a0aee77930560c5adef4b1b3f8f5927a43ee46a56d9"
				}
			  ]
			},
			{
			  "SPDXID": "SPDXRef-aarch64-openssl-perl",
			  "name": "openssl-perl",
			  "versionInfo": "3.0.7-18.el9_2",
			  "downloadLocation": "NOASSERTION",
			  "packageFileName": "openssl-perl-3.0.7-18.el9_2.aarch64.rpm",
			  "checksums": [
				{
				  "algorithm": "SHA256",
				  "checksumValue": "96e53b2da90ce5ad109ba659ce3ed1b5a819b108c95fc493f84847429898b2ed"
				}
			  ]
			}
		],
		"relationships":[
			{
			  "spdxElementId": "SPDXRef-DOCUMENT",
			  "relationshipType": "DESCRIBES",
			  "relatedSpdxElement": "SPDXRef-SRPM"
			},
			{
			  "spdxElementId": "SPDXRef-SRPM",
			  "relationshipType": "GENERATES",
			  "relatedSpdxElement": "SPDXRef-aarch64-openssl-perl"
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
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "openssl-perl",
							Version:   ptrfrom.String("3.0.7-18.el9_2"),
							Subpath:   &packageOfEmptyString,
						},
						DepPkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "openssl",
							Version:   ptrfrom.String("3.0.7-18.el9_2"),
							Subpath:   &packageOfEmptyString,
						},
						IsDependency: &generated.IsDependencyInputSpec{
							DependencyType: "UNKNOWN",
							Justification:  "Derived from SPDX GENERATES relationship",
						},
					},
				},
				IsOccurrence: []assembler.IsOccurrenceIngest{
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "openssl",
							Version:   ptrfrom.String("3.0.7-18.el9_2"),
							Subpath:   &packageOfEmptyString,
						},
						Artifact: &generated.ArtifactInputSpec{
							Algorithm: "sha256",
							Digest:    "31b5079268339cff7ba65a0aee77930560c5adef4b1b3f8f5927a43ee46a56d9",
						},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx package with checksum"},
					},
					{
						Pkg: &generated.PkgInputSpec{
							Type:      "guac",
							Namespace: ptrfrom.String("pkg"),
							Name:      "openssl-perl",
							Version:   ptrfrom.String("3.0.7-18.el9_2"),
							Subpath:   &packageOfEmptyString,
						},
						Artifact: &generated.ArtifactInputSpec{
							Algorithm: "sha256",
							Digest:    "96e53b2da90ce5ad109ba659ce3ed1b5a819b108c95fc493f84847429898b2ed",
						},
						IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "spdx package with checksum"},
					},
				},
				HasSBOM: []assembler.HasSBOMIngest{
					{
						Artifact: &generated.ArtifactInputSpec{
							Algorithm: "sha256",
							Digest:    "31b5079268339cff7ba65a0aee77930560c5adef4b1b3f8f5927a43ee46a56d9",
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logger zapcore.Core
			var logs *observer.ObservedLogs
			logging.InitLogger(logging.Debug)
			if tt.wantWarning != "" {
				logger, logs = observer.New(zap.DebugLevel)
				l := zap.New(logger).Sugar()
				logging.SetLogger(t, l)
			}
			ctx := logging.WithLogger(context.Background())

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
				t.Errorf("spdx.GetPredicates() mismatch values (+got, -expected): %s", d)
			}

			if tt.wantWarning != "" {
				if !slices.ContainsFunc(logs.All(), func(e observer.LoggedEntry) bool {
					return e.Message == tt.wantWarning
				}) {
					t.Errorf("spdx.GetPredicates() did not log the expected warning (wanted '%s')", tt.wantWarning)
				}
			}
		})
	}
}

func parseRfc3339(s string) time.Time {
	time, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return time
}
