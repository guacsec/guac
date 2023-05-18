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
			"SPDXID":"SPDXRef-DOCUMENT",
			"name":"sbom-sha256:a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10",
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
					{Pkg: pUrlToPkgDiscardError("pkg:guac/spdx/Package-sha256-a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10")},
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
					{Pkg: pUrlToPkgDiscardError("pkg:guac/spdx/Package-sha256-a743268cd3c56f921f3fb706cc0425c8ab78119fd433e38bb7c5dcd5635b0d10")},
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
