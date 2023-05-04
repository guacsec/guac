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

package slsa

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_slsaParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name           string
		doc            *processor.Document
		wantPredicates *assembler.IngestPredicates
		wantErr        bool
	}{
		{
			name:           "testing v0.2",
			doc:            &testdata.Ite6SLSADoc,
			wantPredicates: &testdata.SlsaPreds,
			wantErr:        false,
		},
		{
			name:           "testing v0.1",
			doc:            &testdata.Ite6SLSA1Doc,
			wantPredicates: &testdata.SlsaPreds1,
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSLSAParser()
			err := s.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("slsa.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			preds := s.GetPredicates(ctx)
			//fmt.Println(preds.HasSlsa[0].HasSlsa.SlsaPredicate)
			if d := cmp.Diff(tt.wantPredicates, preds, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
				t.Errorf("slsa.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}
