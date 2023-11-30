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
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

func TestIngestVEXStatement(t *testing.T) {
	type call struct {
		Sub  model.PackageOrArtifactInput
		Vuln *model.VulnerabilityInputSpec
		In   *model.VexStatementInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest double sub",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package:  testdata.P1,
						Artifact: testdata.A1,
					},
					Vuln: testdata.V1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest status-not_affected justification-not_provided statement-empty",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					Vuln: testdata.V1,
					In: &model.VexStatementInputSpec{
						Status:           model.VexStatusNotAffected,
						VexJustification: model.VexJustificationNotProvided,
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest status-affected justification-not_provided statement-empty",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					Vuln: testdata.V1,
					In: &model.VexStatementInputSpec{
						Status:           model.VexStatusAffected,
						VexJustification: model.VexJustificationNotProvided,
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest vulnerability NoVuln",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					Vuln: &model.VulnerabilityInputSpec{
						Type: "NoVuln",
					},
					In: &model.VexStatementInputSpec{
						Status:           model.VexStatusAffected,
						VexJustification: "test justification",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest vulnerability cve with novulnID",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					Vuln: &model.VulnerabilityInputSpec{
						Type:            "cve",
						VulnerabilityID: "",
					},
					In: &model.VexStatementInputSpec{
						Status:           model.VexStatusAffected,
						VexJustification: "test justification",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Happy path",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					Vuln: testdata.V1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
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
					IngestVEXStatement(ctx, o.Sub, gomock.Any(), *o.In).
					Return("", nil).
					Times(times)
				_, err := r.Mutation().IngestVEXStatement(ctx, o.Sub, *o.Vuln, *o.In)
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

func TestCertifyVEXStatement(t *testing.T) {
	tests := []struct {
		Name        string
		Query       *model.CertifyVEXStatementSpec
		ExpQueryErr bool
	}{
		{
			Name: "Query double sub",
			Query: &model.CertifyVEXStatementSpec{
				Subject: &model.PackageOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String(""),
					},
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha256"),
					},
				},
			},
			ExpQueryErr: true,
		},
		{
			Name: "Happy path",
			Query: &model.CertifyVEXStatementSpec{
				Subject: &model.PackageOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha256"),
					},
				},
			},
			ExpQueryErr: false,
		},
		{
			Name: "Happy path with Vulnerability",
			Query: &model.CertifyVEXStatementSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type:            ptrfrom.String("CVE"),
					VulnerabilityID: ptrfrom.String("CVE-2014-8140"),
				},
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
				CertifyVEXStatement(ctx, gomock.Any()).
				Times(times)
			_, err := r.Query().CertifyVEXStatement(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
		})
	}
}
