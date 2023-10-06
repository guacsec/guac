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

//go:build integration

package backend

import (
	"strconv"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) TestVEX() {
	testTime := time.Unix(1e9+5, 0)
	type call struct {
		Sub  model.PackageOrArtifactInput
		Vuln *model.VulnerabilityInputSpec
		In   *model.VexStatementInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InArt        []*model.ArtifactInputSpec
		InVuln       []*model.VulnerabilityInputSpec
		Calls        []call
		Query        *model.CertifyVEXStatementSpec
		ExpVEX       []*model.CertifyVEXStatement
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "HappyPath",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				VexJustification: (*model.VexJustification)(ptrfrom.String("test justification")),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Ingest same twice",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				VexJustification: (*model.VexJustification)(ptrfrom.String("test justification")),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Justification",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification 2",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				VexJustification: (*model.VexJustification)(ptrfrom.String("test justification 2")),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification 2",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Package",
			InPkg:  []*model.PkgInputSpec{p1, p2},
			InArt:  []*model.ArtifactInputSpec{a1},
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p2,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: a1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				Subject: &model.PackageOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String(""),
					},
				},
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Artifact",
			InPkg:  []*model.PkgInputSpec{p1},
			InArt:  []*model.ArtifactInputSpec{a1, a2},
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: a1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: a2,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				Subject: &model.PackageOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha256"),
					},
				},
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: a1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Vuln",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1, o2, c1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o2,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: c1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type:            ptrfrom.String("osv"),
					VulnerabilityID: ptrfrom.String("cve-2014-8140"),
				},
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Status",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{c1, o1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: c1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
						Status:           "status one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
						Status:           "status two",
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				Status: (*model.VexStatus)(ptrfrom.String("status one")),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
					Status:           "status one",
				},
			},
		},
		{
			Name:   "Query on Statement",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
						Statement:        "statement one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
						Statement:        "statement two",
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				Statement: ptrfrom.String("statement two"),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
					Statement:        "statement two",
				},
			},
		},
		{
			Name:   "Query on KnownSince",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       testTime,
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				KnownSince: &testTime,
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification",
					KnownSince:       testTime,
				},
			},
		},
		{
			Name:   "Query on ID",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1, o2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o2,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				ID: ptrfrom.String("0"),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query None",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1, o2, c1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o2,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: c1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: ptrfrom.String("asdf"),
				},
			},
			ExpVEX: nil,
		},
		{
			Name:   "Query multiple",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1, o2, c1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o2,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification two",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: c1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification two",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				VexJustification: (*model.VexJustification)(ptrfrom.String("test justification two")),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o2out},
					},
					VexJustification: "test justification two",
					KnownSince:       time.Unix(1e9, 0),
				},
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					VexJustification: "test justification two",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Ingest without sub",
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest without vuln",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:   "Query bad id",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Vuln: o1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: true,
		},
	}
	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.Name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %a", err)
				}
			}
			for _, v := range test.InVuln {
				if _, err := b.IngestVulnerability(ctx, *v); err != nil {
					t.Fatalf("Could not ingest vulnerability: %v", err)
				}
			}
			ids := make([]string, len(test.Calls))
			for i, o := range test.Calls {
				v, err := b.IngestVEXStatement(ctx, o.Sub, *o.Vuln, *o.In)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				ids[i] = v.ID
			}

			if test.Query.ID != nil {
				idIdx, err := strconv.Atoi(*test.Query.ID)
				if err == nil {
					if idIdx < 0 || idIdx >= len(ids) {
						s.T().Fatalf("ID index out of range, want: %d, got: %d. So ID %d will be directly used to query", len(ids), idIdx, idIdx)
					}
					test.Query.ID = ptrfrom.String(ids[idIdx])
				}
			}

			got, err := b.CertifyVEXStatement(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpVEX, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *Suite) TestVEXBulkIngest() {
	type call struct {
		Subs  model.PackageOrArtifactInputs
		Vulns []*model.VulnerabilityInputSpec
		Vexs  []*model.VexStatementInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InArt        []*model.ArtifactInputSpec
		InVuln       []*model.VulnerabilityInputSpec
		Calls        []call
		Query        *model.CertifyVEXStatementSpec
		ExpVEX       []*model.CertifyVEXStatement
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "HappyPath",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1},
					},
					Vulns: []*model.VulnerabilityInputSpec{o1},
					Vexs: []*model.VexStatementInputSpec{
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
						},
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				VexJustification: (*model.VexJustification)(ptrfrom.String("test justification")),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Ingest same twice",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1, p1},
					},
					Vulns: []*model.VulnerabilityInputSpec{o1, o1},
					Vexs: []*model.VexStatementInputSpec{
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
						},
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
						},
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				VexJustification: (*model.VexJustification)(ptrfrom.String("test justification")),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Package",
			InPkg:  []*model.PkgInputSpec{p1, p2},
			InArt:  []*model.ArtifactInputSpec{a1},
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1, p2},
					},
					Vulns: []*model.VulnerabilityInputSpec{o1, o1},
					Vexs: []*model.VexStatementInputSpec{
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
						},
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
						},
					},
				},
				{
					Subs: model.PackageOrArtifactInputs{
						Artifacts: []*model.ArtifactInputSpec{a1},
					},
					Vulns: []*model.VulnerabilityInputSpec{o1},
					Vexs: []*model.VexStatementInputSpec{
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
						},
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				Subject: &model.PackageOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String(""),
					},
				},
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Artifact",
			InArt:  []*model.ArtifactInputSpec{a1, a2},
			InVuln: []*model.VulnerabilityInputSpec{o1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Artifacts: []*model.ArtifactInputSpec{a1, a2},
					},
					Vulns: []*model.VulnerabilityInputSpec{o1, o1},
					Vexs: []*model.VexStatementInputSpec{
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
						},
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
						},
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				Subject: &model.PackageOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha256"),
					},
				},
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: a1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Vuln",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1, o2, c1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1, p1, p1},
					},
					Vulns: []*model.VulnerabilityInputSpec{o1, o2, c1},
					Vexs: []*model.VexStatementInputSpec{
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
						},
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
						},
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
						},
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				Vulnerability: &model.VulnerabilitySpec{
					Type:            ptrfrom.String("osv"),
					VulnerabilityID: ptrfrom.String("cve-2014-8140"),
				},
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Status",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{c1, o1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1, p1},
					},
					Vulns: []*model.VulnerabilityInputSpec{c1, o1},
					Vexs: []*model.VexStatementInputSpec{
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
							Status:           "status one",
						},
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
						},
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				Status: (*model.VexStatus)(ptrfrom.String("status one")),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
					Status:           "status one",
				},
			},
		},
		{
			Name:   "Query multiple",
			InPkg:  []*model.PkgInputSpec{p1},
			InVuln: []*model.VulnerabilityInputSpec{o1, o2, c1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1, p1, p1},
					},
					Vulns: []*model.VulnerabilityInputSpec{o1, o2, c1},
					Vexs: []*model.VexStatementInputSpec{
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
						},
						{
							VexJustification: "test justification two",
							KnownSince:       time.Unix(1e9, 0),
						},
						{
							VexJustification: "test justification two",
							KnownSince:       time.Unix(1e9, 0),
						},
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				VexJustification: (*model.VexJustification)(ptrfrom.String("test justification two")),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{o2out},
					},
					VexJustification: "test justification two",
					KnownSince:       time.Unix(1e9, 0),
				},
				{
					Subject: p1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{c1out},
					},
					VexJustification: "test justification two",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
	}
	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.Name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}

			if _, err := b.IngestPackages(ctx, test.InPkg); err != nil {
				t.Fatalf("Could not ingest package: %v", err)
			}

			if _, err := b.IngestArtifacts(ctx, test.InArt); err != nil {
				t.Fatalf("Could not ingest artifact: %a", err)
			}

			if _, err := b.IngestVulnerabilities(ctx, test.InVuln); err != nil {
				t.Fatalf("Could not ingest vulnerability: %v", err)
			}
			for _, o := range test.Calls {
				_, err := b.IngestVEXStatements(ctx, o.Subs, o.Vulns, o.Vexs)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.CertifyVEXStatement(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpVEX, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
