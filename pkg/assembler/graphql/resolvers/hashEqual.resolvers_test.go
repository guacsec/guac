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

func TestIngestHashEquals(t *testing.T) {
	type call struct {
		A1 []*model.IDorArtifactInput
		A2 []*model.IDorArtifactInput
		HE []*model.HashEqualInputSpec
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
					A1: []*model.IDorArtifactInput{{ArtifactInput: testdata.A1}, {ArtifactInput: testdata.A2}},
					A2: []*model.IDorArtifactInput{{ArtifactInput: testdata.A2}},
					HE: []*model.HashEqualInputSpec{
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
					A1: []*model.IDorArtifactInput{{ArtifactInput: testdata.A1}},
					A2: []*model.IDorArtifactInput{{ArtifactInput: testdata.A2}},
					HE: []*model.HashEqualInputSpec{
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
					A1: []*model.IDorArtifactInput{{ArtifactInput: testdata.A1}},
					A2: []*model.IDorArtifactInput{{ArtifactInput: testdata.A2}},
					HE: []*model.HashEqualInputSpec{
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
					IngestHashEquals(ctx, o.A1, o.A2, o.HE).
					Return(nil, nil).
					Times(times)
				_, err := r.Mutation().IngestHashEquals(ctx, o.A1, o.A2, o.HE)
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

func TestHashEqual(t *testing.T) {
	tests := []struct {
		Name        string
		Query       *model.HashEqualSpec
		ExpQueryErr bool
	}{
		{
			Name: "Query three",
			Query: &model.HashEqualSpec{
				Artifacts: []*model.ArtifactSpec{
					{
						Algorithm: ptrfrom.String("gitHash"),
					},
					{
						Digest: ptrfrom.String("6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"),
					},
					{
						Digest: ptrfrom.String("asdf"),
					},
				},
			},
			ExpQueryErr: true,
		},
		{
			Name: "Happy path",
			Query: &model.HashEqualSpec{
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
				HashEqual(ctx, test.Query).
				Times(times)
			_, err := r.Query().HashEqual(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}
