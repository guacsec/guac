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
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

func TestIngestDependencies(t *testing.T) {
	type call struct {
		P1s []*model.PkgInputSpec
		P2s []*model.PkgInputSpec
		MF  model.MatchFlags
		IDs []*model.IsDependencyInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest two packages and one dependent package",
			Calls: []call{
				{
					P1s: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					P2s: []*model.PkgInputSpec{testdata.P4},
					MF:  testdata.MAll,
					IDs: []*model.IsDependencyInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest one package and two dependency notes",
			Calls: []call{
				{
					P1s: []*model.PkgInputSpec{testdata.P1},
					P2s: []*model.PkgInputSpec{testdata.P4},
					MF:  testdata.MAll,
					IDs: []*model.IsDependencyInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "HappyPath",
			Calls: []call{{
				P1s: []*model.PkgInputSpec{testdata.P1, testdata.P2},
				P2s: []*model.PkgInputSpec{testdata.P2, testdata.P4},
				MF:  testdata.MAll,
				IDs: []*model.IsDependencyInputSpec{
					{
						Justification: "test justification",
					},
					{
						Justification: "test justification",
					},
				},
			}},
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
					IngestDependencies(ctx, o.P1s, o.P2s, o.MF, o.IDs).
					Return([]*model.IsDependency{{ID: "a"}}, nil).
					Times(times)
				_, err := r.Mutation().IngestDependencies(ctx, o.P1s, o.P2s, o.MF, o.IDs)
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
