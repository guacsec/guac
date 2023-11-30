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
	"time"

	"github.com/golang/mock/gomock"
	"github.com/guacsec/guac/internal/testing/mocks"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

func TestIngestHasSLSA(t *testing.T) {
	testTime := time.Unix(1e9+5, 0)
	type call struct {
		Sub  *model.ArtifactInputSpec
		BF   []*model.ArtifactInputSpec
		BB   *model.BuilderInputSpec
		SLSA *model.SLSAInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest with no builtFrom",
			Calls: []call{
				{
					Sub: testdata.A1,
					BF:  []*model.ArtifactInputSpec{},
					BB:  testdata.B1,
					SLSA: &model.SLSAInputSpec{
						StartedOn: &testTime,
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Happy path",
			Calls: []call{
				{
					Sub: testdata.A1,
					BF:  []*model.ArtifactInputSpec{testdata.A2},
					BB:  testdata.B1,
					SLSA: &model.SLSAInputSpec{
						BuildType: "test type",
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
					IngestSLSA(ctx, *o.Sub, o.BF, *o.BB, *o.SLSA).
					Return("", nil).
					Times(times)
				_, err := r.Mutation().IngestSlsa(ctx, *o.Sub, o.BF, *o.BB, *o.SLSA)
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

func TestIngestHasSLSAs(t *testing.T) {
	type call struct {
		Sub  []*model.ArtifactInputSpec
		BF   [][]*model.ArtifactInputSpec
		BB   []*model.BuilderInputSpec
		SLSA []*model.SLSAInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest without slsaList",
			Calls: []call{
				{
					Sub:  []*model.ArtifactInputSpec{testdata.A1},
					BF:   [][]*model.ArtifactInputSpec{{testdata.A2}},
					BB:   []*model.BuilderInputSpec{testdata.B1},
					SLSA: []*model.SLSAInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest without builtFrom",
			Calls: []call{
				{
					Sub: []*model.ArtifactInputSpec{testdata.A1},
					BF:  [][]*model.ArtifactInputSpec{},
					BB:  []*model.BuilderInputSpec{testdata.B1},
					SLSA: []*model.SLSAInputSpec{
						{
							BuildType: "test type",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest without builtByList",
			Calls: []call{
				{
					Sub: []*model.ArtifactInputSpec{testdata.A1},
					BF:  [][]*model.ArtifactInputSpec{{testdata.A2}},
					BB:  []*model.BuilderInputSpec{},
					SLSA: []*model.SLSAInputSpec{
						{
							BuildType: "test type",
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
					Sub: []*model.ArtifactInputSpec{testdata.A1},
					BF:  [][]*model.ArtifactInputSpec{{testdata.A2}},
					BB:  []*model.BuilderInputSpec{testdata.B1},
					SLSA: []*model.SLSAInputSpec{
						{
							BuildType: "test type",
						},
					},
				},
			},
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
					IngestSLSAs(ctx, o.Sub, o.BF, o.BB, o.SLSA).
					Return(nil, nil).
					Times(times)
				_, err := r.Mutation().IngestSLSAs(ctx, o.Sub, o.BF, o.BB, o.SLSA)
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
