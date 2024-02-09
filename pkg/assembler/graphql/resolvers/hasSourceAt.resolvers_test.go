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

func TestIngestHasSourceAts(t *testing.T) {
	type call struct {
		Pkgs       []*model.IDorPkgInput
		Match      model.MatchFlags
		Sources    []*model.IDorSourceInput
		HasSources []*model.HasSourceAtInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest without source",
			Calls: []call{
				{
					Pkgs: []*model.IDorPkgInput{{PackageInput: testdata.P2}},
					Match: model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					Sources:    []*model.IDorSourceInput{},
					HasSources: []*model.HasSourceAtInputSpec{{}},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest missing pkg",
			Calls: []call{
				{
					Pkgs: []*model.IDorPkgInput{},
					Match: model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					Sources:    []*model.IDorSourceInput{{SourceInput: testdata.S1}},
					HasSources: []*model.HasSourceAtInputSpec{{}},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest without hasSource",
			Calls: []call{
				{
					Pkgs: []*model.IDorPkgInput{{PackageInput: testdata.P2}},
					Match: model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					Sources:    []*model.IDorSourceInput{{SourceInput: testdata.S1}},
					HasSources: []*model.HasSourceAtInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Happy path",
			Calls: []call{
				{
					Pkgs: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
					Match: model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					Sources: []*model.IDorSourceInput{{SourceInput: testdata.S1}, {SourceInput: testdata.S2}},
					HasSources: []*model.HasSourceAtInputSpec{
						{
							Justification: "test",
						},
						{
							Justification: "test",
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
					IngestHasSourceAts(ctx, o.Pkgs, gomock.Any(), gomock.Any(), o.HasSources).
					Return([]string{}, nil).
					Times(times)
				_, err := r.Mutation().IngestHasSourceAts(ctx, o.Pkgs, o.Match, o.Sources, o.HasSources)
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
