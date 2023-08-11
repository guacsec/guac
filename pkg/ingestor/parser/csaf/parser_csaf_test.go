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
	"github.com/openvex/go-vex/pkg/csaf"
	"reflect"
	"testing"

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

func Test_findProductRef(t *testing.T) {
	defaultTestTree := csaf.ProductBranch{
		Name: "node1",
		Branches: []csaf.ProductBranch{
			{
				Name: "node2",
				Relationships: []csaf.Relationship{
					{
						FullProductName: csaf.Product{
							ID: "relationshipProductID2",
						},
						ProductRef: "relationshipProductRef2",
					},
				},
			},
		},
	}
	defaultReturnProductRef := &defaultTestTree.Branches[0].Relationships[0].ProductRef

	type args struct {
		ctx        context.Context
		tree       csaf.ProductBranch
		product_id string
	}
	tests := []struct {
		name          string
		args          args
		want          *string
		stackOverflow bool
	}{
		{
			name: "default",
			args: args{
				ctx:        context.Background(),
				tree:       defaultTestTree,
				product_id: defaultTestTree.Branches[0].Relationships[0].FullProductName.ID,
			},
			want: defaultReturnProductRef,
		},
		{
			name: "can stack overflow",
			args: args{
				ctx: context.Background(),
				tree: csaf.ProductBranch{
					Name: "node1",
					Product: csaf.Product{
						Name: "productName1",
						ID:   "productID1",
					},
					Category: "category1",

					Branches: []csaf.ProductBranch{
						{ // create a child branch which will then point back to the parent branch
							Name: "node2",
							Product: csaf.Product{
								Name: "productName2",
								ID:   "productID2",
							},
							Category: "category2",
						},
					},
				},
				product_id: "not equal to any tree nodes",
			},
			stackOverflow: true,
			want:          nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.stackOverflow {
				// create a circular reference
				// the child branch points back to the parent branch
				test.args.tree.Branches[0].Branches = append(test.args.tree.Branches[0].Branches, test.args.tree)
			}

			if got := findProductRef(test.args.ctx, test.args.tree, test.args.product_id); !reflect.DeepEqual(got, test.want) {
				t.Errorf("findProductRef() = %v, want %v", got, test.want)
			}
		})
	}
}
