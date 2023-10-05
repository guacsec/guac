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
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

func TestIngestLicense(t *testing.T) {
	tests := []struct {
		Name         string
		Call         *model.LicenseInputSpec
		ExpIngestErr bool
	}{
		{
			Name: "Happy ID",
			Call: &model.LicenseInputSpec{
				Name:        "LIC-ID",
				ListVersion: ptrfrom.String("1.2.3"),
			},
			ExpIngestErr: false,
		},
		{
			Name: "Happy Inline",
			Call: &model.LicenseInputSpec{
				Name:   "LicenseRef-123",
				Inline: ptrfrom.String("text"),
			},
			ExpIngestErr: false,
		},
		{
			Name: "No list",
			Call: &model.LicenseInputSpec{
				Name: "LIC-ID",
			},
			ExpIngestErr: true,
		},
		{
			Name: "Empty list",
			Call: &model.LicenseInputSpec{
				Name:        "LIC-ID",
				ListVersion: ptrfrom.String(""),
			},
			ExpIngestErr: true,
		},
		{
			Name: "ID with Inline",
			Call: &model.LicenseInputSpec{
				Name:   "LIC-ID",
				Inline: ptrfrom.String("asdf"),
			},
			ExpIngestErr: true,
		},
		{
			Name: "ID with Both",
			Call: &model.LicenseInputSpec{
				Name:        "LIC-ID",
				ListVersion: ptrfrom.String("1.2.3"),
				Inline:      ptrfrom.String("asdf"),
			},
			ExpIngestErr: true,
		},
		{
			Name: "No inline",
			Call: &model.LicenseInputSpec{
				Name: "LicenseRef-123",
			},
			ExpIngestErr: true,
		},
		{
			Name: "Empty inline",
			Call: &model.LicenseInputSpec{
				Name:   "LicenseRef-123",
				Inline: ptrfrom.String(""),
			},
			ExpIngestErr: true,
		},
		{
			Name: "LicenseRef with List",
			Call: &model.LicenseInputSpec{
				Name:        "LicenseRef-123",
				ListVersion: ptrfrom.String("1.2.3"),
			},
			ExpIngestErr: true,
		},
		{
			Name: "LicenseRef with Both",
			Call: &model.LicenseInputSpec{
				Name:        "LicenseRef-123",
				ListVersion: ptrfrom.String("1.2.3"),
				Inline:      ptrfrom.String("asdf"),
			},
			ExpIngestErr: true,
		},
	}
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b := mocks.NewMockBackend(ctrl)
			r := resolvers.Resolver{Backend: b}
			times := 1
			if test.ExpIngestErr {
				times = 0
			}
			b.
				EXPECT().
				IngestLicense(ctx, test.Call).
				Return(&model.License{ID: "a"}, nil).
				Times(times)
			_, err := r.Mutation().IngestLicense(ctx, test.Call)
			if (err != nil) != test.ExpIngestErr {
				t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}

func TestIngestBulkLicense(t *testing.T) {
	tests := []struct {
		Name         string
		Call         []*model.LicenseInputSpec
		ExpIngestErr bool
	}{
		{
			Name: "All Good",
			Call: []*model.LicenseInputSpec{
				{
					Name:        "LIC-ID",
					ListVersion: ptrfrom.String("1.2.3"),
				},
				{
					Name:   "LicenseRef-123",
					Inline: ptrfrom.String("text"),
				},
			},
			ExpIngestErr: false,
		},
		{
			Name: "One Bad",
			Call: []*model.LicenseInputSpec{
				{
					Name:        "LIC-ID",
					ListVersion: ptrfrom.String("1.2.3"),
				},
				{
					Name:        "LIC-ID",
					ListVersion: ptrfrom.String("1.2.3"),
					Inline:      ptrfrom.String("asdf"),
				},
				{
					Name:   "LicenseRef-123",
					Inline: ptrfrom.String("text"),
				},
			},
			ExpIngestErr: true,
		},
	}
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b := mocks.NewMockBackend(ctrl)
			r := resolvers.Resolver{Backend: b}
			times := 1
			if test.ExpIngestErr {
				times = 0
			}
			b.
				EXPECT().
				IngestLicenses(ctx, test.Call).
				Return([]*model.License{}, nil).
				Times(times)
			_, err := r.Mutation().IngestLicenses(ctx, test.Call)
			if (err != nil) != test.ExpIngestErr {
				t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}
