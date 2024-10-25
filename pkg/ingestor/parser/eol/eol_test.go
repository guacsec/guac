//
// Copyright 2024 The GUAC Authors.
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

package eol

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

func TestParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tm, _ := time.Parse(time.RFC3339, "2024-03-15T12:00:00Z")
	tests := []struct {
		name    string
		doc     *processor.Document
		wantHM  []assembler.HasMetadataIngest
		wantErr bool
	}{
		{
			name: "valid EOL data for Node.js",
			doc: &processor.Document{
				Blob:   testdata.ITE6EOLNodejs,
				Format: processor.FormatJSON,
				Type:   processor.DocumentITE6EOL,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			wantHM: []assembler.HasMetadataIngest{
				{
					Pkg: &generated.PkgInputSpec{
						Type:      "npm",
						Name:      "nodejs",
						Version:   ptrfrom.String("14.17.0"),
						Namespace: ptrfrom.String(""),
						Subpath:   ptrfrom.String(""),
					},
					PkgMatchFlag: generated.MatchFlags{Pkg: generated.PkgMatchTypeSpecificVersion},
					HasMetadata: &generated.HasMetadataInputSpec{
						Key:           "endoflife",
						Value:         "product:nodejs,cycle:14,version:14.17.0,isEOL:true,eolDate:2023-04-30,lts:true,latest:14.21.3,releaseDate:2021-05-11",
						Timestamp:     tm,
						Justification: "Retrieved from endoflife.date",
						Origin:        "GUAC EOL Certifier",
						Collector:     "GUAC",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid EOL data for Python",
			doc: &processor.Document{
				Blob:   testdata.ITE6EOLPython,
				Format: processor.FormatJSON,
				Type:   processor.DocumentITE6EOL,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			wantHM: []assembler.HasMetadataIngest{
				{
					Pkg: &generated.PkgInputSpec{
						Type:      "pypi",
						Name:      "python",
						Version:   ptrfrom.String("3.9.5"),
						Namespace: ptrfrom.String(""),
						Subpath:   ptrfrom.String(""),
					},
					PkgMatchFlag: generated.MatchFlags{Pkg: generated.PkgMatchTypeSpecificVersion},
					HasMetadata: &generated.HasMetadataInputSpec{
						Key:           "endoflife",
						Value:         "product:python,cycle:3.9,version:3.9.5,isEOL:false,eolDate:2025-10-05,lts:false,latest:3.9.16,releaseDate:2021-05-03",
						Timestamp:     tm,
						Justification: "Retrieved from endoflife.date",
						Origin:        "GUAC EOL Certifier",
						Collector:     "GUAC",
					},
				},
			},
			wantErr: false,
		},
	}

	var ignoreHMTimestamp = cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".Timestamp", p[len(p)-1].String()) == 0
	}, cmp.Ignore())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewEOLCertificationParser()
			err := s.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parser.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			ip := s.GetPredicates(ctx)
			if diff := cmp.Diff(tt.wantHM, ip.HasMetadata, ignoreHMTimestamp); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
