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

	"github.com/guacsec/guac/pkg/ingestor/parser/common"

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

	// creating the tree outside the test loop and then making the child point back to the parent because
	// the child can only point back to the parent if the tree is already created
	// The child is pointing back to the parent outside the loop so that this test doesn't need a stackoverflow flag
	stackoverflowTestTree := csaf.ProductBranch{
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
	}

	// The child branch is pointing back to the parent branch to create a loop
	stackoverflowTestTree.Branches[0].Branches = append(stackoverflowTestTree.Branches[0].Branches, stackoverflowTestTree)

	type args struct {
		ctx        context.Context
		tree       csaf.ProductBranch
		product_id string
	}
	tests := []struct {
		name string
		args args
		want *string
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
				ctx:        context.Background(),
				tree:       stackoverflowTestTree,
				product_id: "not equal to any tree nodes",
			},
			want: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := findProductRef(test.args.ctx, test.args.tree, test.args.product_id); !reflect.DeepEqual(got, test.want) {
				t.Errorf("findProductRef() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_findPurl(t *testing.T) {
	// The tree for the default test case
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

	defaultReturnedPurl := defaultTestTree.Branches[0].Product.IdentificationHelper["purl"]

	// The tree for the stack overflow test case

	stackOverflowTree := csaf.ProductBranch{
		Name: "node1",
		Branches: []csaf.ProductBranch{
			{
				Name: "node2",
			},
		},
	}

	stackOverflowTree.Branches[0].Branches = append(stackOverflowTree.Branches[0].Branches, stackOverflowTree)

	type args struct {
		ctx         context.Context
		tree        csaf.ProductBranch
		product_ref string
	}
	tests := []struct {
		name string
		args args
		want *string
	}{
		{
			name: "default",
			args: args{
				ctx:         context.Background(),
				tree:        defaultTestTree,
				product_ref: "node2",
			},
			want: &defaultReturnedPurl,
		},
		{
			name: "can stack overflow",
			args: args{
				ctx:         context.Background(),
				tree:        stackOverflowTree,
				product_ref: "not equal to any tree nodes",
			},
			want: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := findPurl(test.args.ctx, test.args.tree, test.args.product_ref); !reflect.DeepEqual(got, test.want) {
				t.Errorf("findPurl() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_csafParser_GetIdentifiers(t *testing.T) {
	type fields struct {
		doc               *processor.Document
		identifierStrings *common.IdentifierStrings
	}
	test := struct {
		name    string
		fields  fields
		ctx     context.Context
		want    *common.IdentifierStrings
		wantErr bool
	}{
		name: "default test",
		fields: fields{
			doc: &processor.Document{
				Blob:   testdata.CsafExampleRedHat,
				Format: processor.FormatJSON,
				Type:   processor.DocumentCsaf,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			identifierStrings: &common.IdentifierStrings{},
		},
		ctx: context.Background(),
		want: &common.IdentifierStrings{
			PurlStrings: []string{
				"BaseOS-8.6.0.Z.EUS:openssl-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-1:1.1.1k-8.el8_6.src",
				"BaseOS-8.6.0.Z.EUS:openssl-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-debuginfo-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-debuginfo-1:1.1.1k-8.el8_6.i686",
				"BaseOS-8.6.0.Z.EUS:openssl-debuginfo-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-debuginfo-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-debuginfo-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-debugsource-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-debugsource-1:1.1.1k-8.el8_6.i686",
				"BaseOS-8.6.0.Z.EUS:openssl-debugsource-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-debugsource-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-debugsource-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-devel-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-devel-1:1.1.1k-8.el8_6.i686",
				"BaseOS-8.6.0.Z.EUS:openssl-devel-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-devel-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-devel-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-1:1.1.1k-8.el8_6.i686",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-debuginfo-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-debuginfo-1:1.1.1k-8.el8_6.i686",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-debuginfo-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-debuginfo-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-libs-debuginfo-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-perl-1:1.1.1k-8.el8_6.aarch64",
				"BaseOS-8.6.0.Z.EUS:openssl-perl-1:1.1.1k-8.el8_6.ppc64le",
				"BaseOS-8.6.0.Z.EUS:openssl-perl-1:1.1.1k-8.el8_6.s390x",
				"BaseOS-8.6.0.Z.EUS:openssl-perl-1:1.1.1k-8.el8_6.x86_64",
				"BaseOS-8.6.0.Z.EUS:openssl-1:1.1.1k-7.el8_6.x86_64",
			},
		},
	}

	c := NewCsafParser()

	err := c.Parse(test.ctx, test.fields.doc)
	if err != nil {
		t.Errorf("Parse() error = %v", err)
		return
	}

	_ = c.GetPredicates(test.ctx)

	got, err := c.GetIdentifiers(test.ctx)
	if (err != nil) != test.wantErr {
		t.Errorf("GetIdentifiers() error = %v, wantErr %v", err, test.wantErr)
		return
	}
	if d := cmp.Diff(test.want, got, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
		t.Errorf("csaf.GetPredicate mismatch values (+got, -expected): %s", d)
	}
}
