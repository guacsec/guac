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

package csaf

import (
	"context"
	"reflect"
	"testing"

	"github.com/openvex/go-vex/pkg/csaf"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_csafParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name           string
		doc            *processor.Document
		wantPredicates *assembler.IngestPredicates
		wantErr        bool
	}{{
		name: "valid big CSAF document",
		doc: &processor.Document{
			Blob:   testdata.CsafExampleRedHat,
			Format: processor.FormatJSON,
			Type:   processor.DocumentCsaf,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantPredicates: &assembler.IngestPredicates{
			Vex:         testdata.CsafVexIngest,
			CertifyVuln: testdata.CsafCertifyVulnIngest,
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewCsafParser()
			err := s.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("csafParse.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			preds := s.GetPredicates(ctx)
			if d := cmp.Diff(tt.wantPredicates, preds, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
				t.Errorf("csaf.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}

func Test_findPurl(t *testing.T) {
	defaultTestTree := csaf.ProductBranch{
		Name: "node1",
		Branches: []csaf.ProductBranch{
			{
				Name: "node2",
				Product: csaf.Product{
					IdentificationHelper: map[string]string{
						"purl": "test 2",
					},
				},
			},
		},
	}

	returnedPurl := defaultTestTree.Branches[0].Product.IdentificationHelper["purl"]
	type args struct {
		ctx         context.Context
		tree        csaf.ProductBranch
		product_ref string
	}
	tests := []struct {
		name          string
		args          args
		stackOverflow bool
		want          *string
	}{
		{
			name: "default",
			args: args{
				ctx:         context.Background(),
				tree:        defaultTestTree,
				product_ref: "node2",
			},
			want: &returnedPurl,
		},
		{
			name: "can stack overflow",
			args: args{
				ctx: context.Background(),
				tree: csaf.ProductBranch{
					Name: "node1",
				},
				product_ref: "not equal to any tree nodes",
			},
			stackOverflow: true,
			want:          nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.stackOverflow {
				test.args.tree.Branches = append(test.args.tree.Branches, csaf.ProductBranch{
					Name: "node2",
				})
				test.args.tree.Branches[0].Branches = append(test.args.tree.Branches[0].Branches, test.args.tree)
			}

			if got := findPurl(test.args.ctx, test.args.tree, test.args.product_ref, make(map[string]bool)); !reflect.DeepEqual(got, test.want) {
				t.Errorf("findPurl() = %v, want %v", got, test.want)
			}
		})
	}
}
