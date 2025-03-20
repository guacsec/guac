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

	tests := []struct {
		name      string
		doc       *processor.Document
		wantOccur []assembler.IsOccurrenceIngest
		wantErr   bool
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
			wantOccur: []assembler.IsOccurrenceIngest{
				{
					Pkg: &generated.PkgInputSpec{
						Type:      "npm",
						Name:      "example-pkg",
						Version:   ptrfrom.String("1.0.0"),
						Namespace: ptrfrom.String(""),
						Subpath:   ptrfrom.String(""),
					},
					Artifact: &generated.ArtifactInputSpec{
						Algorithm: "sha256",
						Digest:    "abcd1234...",
					},
					IsOccurrence: &generated.IsOccurrenceInputSpec{
						Justification: "Retrieved from reference predicate",
						Collector:     "GUAC",
						Origin:        "GUAC Reference",
						DocumentRef:   "https://example.com/downloads/pkg.tar.gz",
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
			wantOccur: []assembler.IsOccurrenceIngest{
				{
					Pkg: &generated.PkgInputSpec{
						Type:      "pypi",
						Name:      "example-python",
						Version:   ptrfrom.String("3.9.0"),
						Namespace: ptrfrom.String(""),
						Subpath:   ptrfrom.String(""),
					},
					Artifact: &generated.ArtifactInputSpec{
						Algorithm: "sha256",
						Digest:    "aa1111111111111111111111111111111111111111111111111111111111111111",
					},
					IsOccurrence: &generated.IsOccurrenceInputSpec{
						Justification: "Retrieved from reference predicate",
						Collector:     "GUAC",
						Origin:        "GUAC Reference",
						DocumentRef:   "https://example.com/artifacts/python-ref1.tgz",
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
					Artifact: &generated.ArtifactInputSpec{
						Algorithm: "sha256",
						Digest:    "bb2222222222222222222222222222222222222222222222222222222222222222",
					},
					IsOccurrence: &generated.IsOccurrenceInputSpec{
						Justification: "Retrieved from reference predicate",
						Collector:     "GUAC",
						Origin:        "GUAC Reference",
						DocumentRef:   "https://example.com/artifacts/python-ref2.whl",
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
			wantOccur: nil,
			wantErr:   true,
		},
	}

	var ignoreUnused = cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Contains(p.String(), "timeScanned")
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
			if diff := cmp.Diff(tt.wantOccur, ip.IsOccurrence, ignoreUnused); diff != "" {
				t.Errorf("unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
