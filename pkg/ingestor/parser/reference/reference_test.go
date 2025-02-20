//
// Copyright 2025 The GUAC Authors.
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

package reference

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func TestReferenceParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tm, _ := time.Parse(time.RFC3339, "2025-01-23T12:00:00Z")

	tests := []struct {
		name       string
		doc        *processor.Document
		wantHasMet []assembler.HasMetadataIngest
		wantErr    bool
	}{
		{
			name: "valid reference data with single reference",
			doc: &processor.Document{
				Blob:   testdata.ITE6ReferenceSingle,
				Format: processor.FormatJSON,
				Type:   processor.DocumentITE6Reference,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			wantHasMet: []assembler.HasMetadataIngest{
				{
					Pkg: &generated.PkgInputSpec{
						Type:      "npm",
						Name:      "example-pkg",
						Version:   ptrfrom.String("1.0.0"),
						Namespace: ptrfrom.String(""),
						Subpath:   ptrfrom.String(""),
					},
					PkgMatchFlag: generated.MatchFlags{Pkg: generated.PkgMatchTypeSpecificVersion},
					HasMetadata: &generated.HasMetadataInputSpec{
						Key:           "reference",
						Value:         "attester:attester-123,ref#0,downloadLocation:https://example.com/downloads/pkg.tar.gz,digest:sha256=abcd1234...,mediaType:application/x-tar",
						Timestamp:     tm,
						Justification: "Retrieved from reference predicate",
						Origin:        "GUAC Reference Certifier",
						Collector:     "GUAC",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid reference data with multiple references",
			doc: &processor.Document{
				Blob:   testdata.ITE6ReferenceMultiple,
				Format: processor.FormatJSON,
				Type:   processor.DocumentITE6Reference,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			wantHasMet: []assembler.HasMetadataIngest{
				{
					Pkg: &generated.PkgInputSpec{
						Type:      "pypi",
						Name:      "example-python",
						Version:   ptrfrom.String("3.9.0"),
						Namespace: ptrfrom.String(""),
						Subpath:   ptrfrom.String(""),
					},
					PkgMatchFlag: generated.MatchFlags{Pkg: generated.PkgMatchTypeSpecificVersion},
					HasMetadata: &generated.HasMetadataInputSpec{
						Key:           "reference",
						Value:         "attester:attester-xyz,ref#0,downloadLocation:https://example.com/artifacts/python-ref1.tgz,digest:sha256=aa1111111111111111111111111111111111111111111111111111111111111111,mediaType:application/octet-stream",
						Timestamp:     tm,
						Justification: "Retrieved from reference predicate",
						Origin:        "GUAC Reference Certifier",
						Collector:     "GUAC",
					},
				},
				{
					Pkg: &generated.PkgInputSpec{
						Type:      "pypi",
						Name:      "example-python",
						Version:   ptrfrom.String("3.9.0"),
						Namespace: ptrfrom.String(""),
						Subpath:   ptrfrom.String(""),
					},
					PkgMatchFlag: generated.MatchFlags{Pkg: generated.PkgMatchTypeSpecificVersion},
					HasMetadata: &generated.HasMetadataInputSpec{
						Key:           "reference",
						Value:         "attester:attester-xyz,ref#1,downloadLocation:https://example.com/artifacts/python-ref2.whl,digest:sha256=bb2222222222222222222222222222222222222222222222222222222222222222,mediaType:application/zip",
						Timestamp:     tm,
						Justification: "Retrieved from reference predicate",
						Origin:        "GUAC Reference Certifier",
						Collector:     "GUAC",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "no subject found",
			doc: &processor.Document{
				Blob:   testdata.ITE6ReferenceNoSubject,
				Format: processor.FormatJSON,
				Type:   processor.DocumentITE6Reference,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			wantHasMet: nil,
			wantErr:    true,
		},
	}

	var ignoreHMTimestamp = cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".Timestamp", p[len(p)-1].String()) == 0
	}, cmp.Ignore())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewReferenceParser()
			err := p.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			ip := p.GetPredicates(ctx)
			if diff := cmp.Diff(tt.wantHasMet, ip.HasMetadata, ignoreHMTimestamp); diff != "" {
				t.Errorf("unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
