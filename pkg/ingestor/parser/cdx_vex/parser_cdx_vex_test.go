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

package cdx_vex

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

// Test and assert predicates
func Test_CdxVexParser(t *testing.T) {
	t.Parallel()
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name           string
		doc            *processor.Document
		wantPredicates *assembler.IngestPredicates
	}{
		{
			name: "successfully parsed a cdx_vex document containing unaffected package",
			doc: &processor.Document{
				Blob: testdata.CycloneDXVEXUnAffected,
			},
			wantPredicates: &assembler.IngestPredicates{
				Vex:          testdata.CycloneDXUnAffectedVexIngest,
				VulnMetadata: testdata.CycloneDXUnAffectedVulnMetadata,
			},
		},
		{
			name: "successfully parsed a cdx_vex document containing affected package",
			doc: &processor.Document{
				Blob: testdata.CycloneDXVEXAffected,
			},
			wantPredicates: &assembler.IngestPredicates{
				Vex:          testdata.CycloneDXAffectedVexIngest,
				VulnMetadata: testdata.CycloneDXAffectedVulnMetadata,
				CertifyVuln:  testdata.CycloneDXAffectedCertifyVuln,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCdxVexParser()
			if err := c.Parse(ctx, tt.doc); err != nil {
				t.Errorf("CdxVexParser.Parse() error = %v", err)
				return
			}

			preds := c.GetPredicates(ctx)
			if d := cmp.Diff(tt.wantPredicates, preds, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
				t.Errorf("csaf.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}
