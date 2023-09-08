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

package resolvers_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/guacsec/guac/internal/testing/mocks"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

func TestIngestPkgEquals(t *testing.T) {
	type call struct {
		P1 []*model.PkgInputSpec
		P2 []*model.PkgInputSpec
		PE []*model.PkgEqualInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest with different number of artifacts",
			Calls: []call{
				{
					P1: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					P2: []*model.PkgInputSpec{testdata.P2},
					PE: []*model.PkgEqualInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest with different number of HashEqual",
			Calls: []call{
				{
					P1: []*model.PkgInputSpec{testdata.P1},
					P2: []*model.PkgInputSpec{testdata.P2},
					PE: []*model.PkgEqualInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "another justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "HappyPath",
			Calls: []call{
				{
					P1: []*model.PkgInputSpec{testdata.P1},
					P2: []*model.PkgInputSpec{testdata.P2},
					PE: []*model.PkgEqualInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: false,
		},
	}
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b := mocks.NewMockBackend(ctrl)
			r := resolvers.Resolver{Backend: b}
			for _, o := range test.Calls {
				times := 1
				if test.ExpIngestErr {
					times = 0
				}
				b.
					EXPECT().
					IngestPkgEquals(ctx, o.P1, o.P2, o.PE).
					Return([]string{}, nil).
					Times(times)
				_, err := r.Mutation().IngestPkgEquals(ctx, o.P1, o.P2, o.PE)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
		})
	}
}

func TestPkgEqual(t *testing.T) {
	tests := []struct {
		Name        string
		Query       *model.PkgEqualSpec
		ExpQueryErr bool
	}{
		{
			Name: "Query three",
			Query: &model.PkgEqualSpec{
				Packages: []*model.PkgSpec{
					{
						Name: ptrfrom.String("somename"),
					},
					{
						Version: ptrfrom.String("1.2.3"),
					},
					{
						Type: ptrfrom.String("asdf"),
					},
				},
			},
			ExpQueryErr: true,
		},
		{
			Name: "Happy path",
			Query: &model.PkgEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpQueryErr: false,
		},
	}
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b := mocks.NewMockBackend(ctrl)
			r := resolvers.Resolver{Backend: b}
			times := 1
			if test.ExpQueryErr {
				times = 0
			}
			b.
				EXPECT().
				PkgEqual(ctx, test.Query).
				Times(times)
			_, err := r.Query().PkgEqual(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}
