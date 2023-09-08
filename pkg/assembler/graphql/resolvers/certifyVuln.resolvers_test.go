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

var t1, _ = time.Parse(time.RFC3339, "2023-01-01T00:00:00Z")

func TestIngestCertifyVulns(t *testing.T) {
	type call struct {
		Pkgs         []*model.PkgInputSpec
		Vulns        []*model.VulnerabilityInputSpec
		CertifyVulns []*model.ScanMetadataInput
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest without vuln",
			Calls: []call{
				{
					Pkgs:         []*model.PkgInputSpec{testdata.P2},
					Vulns:        []*model.VulnerabilityInputSpec{},
					CertifyVulns: []*model.ScanMetadataInput{{}},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest missing pkg",
			Calls: []call{
				{
					Pkgs:         []*model.PkgInputSpec{},
					Vulns:        []*model.VulnerabilityInputSpec{},
					CertifyVulns: []*model.ScanMetadataInput{{}},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest vulnerability cve with novulnID",
			Calls: []call{
				{
					Pkgs: []*model.PkgInputSpec{testdata.P2},
					Vulns: []*model.VulnerabilityInputSpec{
						{
							Type:            "cve",
							VulnerabilityID: "",
						},
					},
					CertifyVulns: []*model.ScanMetadataInput{{}},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Happy path",
			Calls: []call{
				{
					Pkgs:  []*model.PkgInputSpec{testdata.P2, testdata.P1},
					Vulns: []*model.VulnerabilityInputSpec{testdata.C1, testdata.C2},
					CertifyVulns: []*model.ScanMetadataInput{
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
						},
						{
							Collector:      "test collector",
							Origin:         "test origin",
							ScannerVersion: "v1.0.0",
							ScannerURI:     "test scanner uri",
							DbVersion:      "2023.01.01",
							DbURI:          "test db uri",
							TimeScanned:    t1,
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
					IngestCertifyVulns(ctx, o.Pkgs, gomock.Any(), o.CertifyVulns).
					//Return([]*model.CertifyScorecard{testdata.SC1out}, nil).
					Times(times)
				_, err := r.Mutation().IngestCertifyVulns(ctx, o.Pkgs, o.Vulns, o.CertifyVulns)
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
