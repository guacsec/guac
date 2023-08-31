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

func TestVulnEqual(t *testing.T) {
	tests := []struct {
		Name        string
		Query       *model.VulnEqualSpec
		ExpQueryErr bool
	}{
		{
			Name: "Query with three vulnerabilities",
			Query: &model.VulnEqualSpec{
				Vulnerabilities: []*model.VulnerabilitySpec{
					{
						VulnerabilityID: ptrfrom.String("CVE-2022-26499"),
					},
					{
						VulnerabilityID: ptrfrom.String("CVE-2021-26499"),
					},
					{
						VulnerabilityID: ptrfrom.String("CVE-2020-26499"),
					},
				},
				Justification: ptrfrom.String("test justification"),
			},
			ExpQueryErr: true,
		},
		{
			Name: "Happy path with vulnerabilities",
			Query: &model.VulnEqualSpec{
				Vulnerabilities: []*model.VulnerabilitySpec{
					{
						Type:            ptrfrom.String("cve"),
						VulnerabilityID: ptrfrom.String("CVE-2022-26499"),
					},
					{
						Type:            ptrfrom.String("osv"),
						VulnerabilityID: ptrfrom.String("CVE-2021-26499"),
					},
				},
				Justification: ptrfrom.String("test justification"),
			},
			ExpQueryErr: false,
		},
		{
			Name: "Happy path",
			Query: &model.VulnEqualSpec{
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
				VulnEqual(ctx, gomock.Any()).
				Times(times)
			_, err := r.Query().VulnEqual(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}
