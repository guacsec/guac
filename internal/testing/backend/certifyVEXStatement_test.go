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

package backend_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestVEX(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
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
		QueryID      bool
		QueryPkgID   bool
		QueryArtID   bool
		QueryVulnID  bool
		ExpVEX       []*model.CertifyVEXStatement
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:   "HappyPath",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Ingest same twice",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Justification",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification 2",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Package",
			InPkg:  []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InArt:  []*model.ArtifactInputSpec{testdata.A1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P2},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					},
					Vuln: testdata.O1,
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification 2",
					KnownSince:       time.Unix(1e9, 0),
				},
				{
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Package ID",
			InPkg:  []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InArt:  []*model.ArtifactInputSpec{testdata.A1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P2},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			QueryPkgID: true,
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Artifact",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InArt:  []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
					},
					Vuln: testdata.O1,
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
					Subject: testdata.A1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Artifact ID",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InArt:  []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			QueryArtID: true,
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: testdata.A2out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Vuln",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2, testdata.C1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O2,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.C1,
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
				{
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification 2",
					KnownSince:       time.Unix(1e9, 0),
				},
				{
					Subject: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
				{
					Subject: testdata.A1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
				{
					Subject: testdata.A2out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Vulnerability ID",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2, testdata.C1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O2,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.C1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			QueryVulnID: true,
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Status",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.C1, testdata.O1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.C1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
						Status:           "status one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
					Status:           "status one",
				},
			},
		},
		{
			Name:   "Query on Status Notes",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.C1, testdata.O1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.C1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
						StatusNotes:      "status one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
						StatusNotes:      "status two",
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				StatusNotes: ptrfrom.String("status one"),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
					StatusNotes:      "status one",
				},
			},
		},
		{
			Name:   "Query on Statement",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
						Statement:        "statement one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
					Statement:        "statement two",
				},
			},
		},
		{
			Name:   "Query on KnownSince",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       testTime,
				},
			},
		},
		{
			Name:   "Query on ID",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O2,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
			},
			QueryID: true,
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query None",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2, testdata.C1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O2,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.C1,
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
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2, testdata.C1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O2,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification two",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.C1,
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
					},
					VexJustification: "test justification two",
					KnownSince:       time.Unix(1e9, 0),
				},
				{
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					VexJustification: "test justification two",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		}, {
			Name:   "docref",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
						DocumentRef:      "test",
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				DocumentRef: ptrfrom.String("test"),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
					DocumentRef:      "test",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if pkgIDs, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: p}); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				} else {
					if test.QueryPkgID {
						test.Query = &model.CertifyVEXStatementSpec{
							Subject: &model.PackageOrArtifactSpec{
								Package: &model.PkgSpec{
									ID: ptrfrom.String(pkgIDs.PackageVersionID),
								},
							},
						}
					}
				}
			}
			for _, a := range test.InArt {
				if artID, err := b.IngestArtifact(ctx, &model.IDorArtifactInput{ArtifactInput: a}); err != nil {
					t.Fatalf("Could not ingest artifact: %a", err)
				} else {
					if test.QueryArtID {
						test.Query = &model.CertifyVEXStatementSpec{
							Subject: &model.PackageOrArtifactSpec{
								Artifact: &model.ArtifactSpec{
									ID: ptrfrom.String(artID),
								},
							},
						}
					}
				}
			}
			for _, v := range test.InVuln {
				if vulnIDs, err := b.IngestVulnerability(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: v}); err != nil {
					t.Fatalf("Could not ingest vulnerability: %v", err)
				} else {
					if test.QueryVulnID {
						test.Query = &model.CertifyVEXStatementSpec{
							Vulnerability: &model.VulnerabilitySpec{
								ID: ptrfrom.String(vulnIDs.VulnerabilityNodeID),
							},
						}
					}
				}
			}
			for _, o := range test.Calls {
				vexID, err := b.IngestVEXStatement(ctx, o.Sub, model.IDorVulnerabilityInput{VulnerabilityInput: o.Vuln}, *o.In)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.CertifyVEXStatementSpec{
						ID: ptrfrom.String(vexID),
					}
				}
			}
			got, err := b.CertifyVEXStatementList(ctx, *test.Query, nil, nil)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			var returnedObjects []*model.CertifyVEXStatement
			if got != nil {
				for _, obj := range got.Edges {
					returnedObjects = append(returnedObjects, obj.Node)
				}
			}
			if diff := cmp.Diff(test.ExpVEX, returnedObjects, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestVEXBulkIngest(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		Subs  model.PackageOrArtifactInputs
		Vulns []*model.IDorVulnerabilityInput
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
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
					},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.O1}},
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Ingest same twice",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P1}},
					},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.O1}, {VulnerabilityInput: testdata.O1}},
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Package",
			InPkg:  []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InArt:  []*model.ArtifactInputSpec{testdata.A1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
					},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.O1}, {VulnerabilityInput: testdata.O1}},
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
						Artifacts: []*model.IDorArtifactInput{{ArtifactInput: testdata.A1}},
					},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.O1}},
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Artifact",
			InArt:  []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Artifacts: []*model.IDorArtifactInput{{ArtifactInput: testdata.A1}, {ArtifactInput: testdata.A2}},
					},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.O1}, {VulnerabilityInput: testdata.O1}},
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
					Subject: testdata.A1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Vuln",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2, testdata.C1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P1}, {PackageInput: testdata.P1}},
					},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.O1}, {VulnerabilityInput: testdata.O2}, {VulnerabilityInput: testdata.C1}},
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
				{
					Subject: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
				{
					Subject: testdata.A1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
				{
					Subject: testdata.A2out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		},
		{
			Name:   "Query on Status",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.C1, testdata.O1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P1}},
					},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.C1}, {VulnerabilityInput: testdata.O1}},
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
					Status:           "status one",
				},
			},
		},
		{
			Name:   "Query multiple",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2, testdata.C1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P1}, {PackageInput: testdata.P1}},
					},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.O1}, {VulnerabilityInput: testdata.O2}, {VulnerabilityInput: testdata.C1}},
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
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
					},
					VexJustification: "test justification two",
					KnownSince:       time.Unix(1e9, 0),
				},
				{
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "cve",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
					},
					VexJustification: "test justification two",
					KnownSince:       time.Unix(1e9, 0),
				},
			},
		}, {
			Name:   "docref",
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
					},
					Vulns: []*model.IDorVulnerabilityInput{{VulnerabilityInput: testdata.O1}},
					Vexs: []*model.VexStatementInputSpec{
						{
							VexJustification: "test justification",
							KnownSince:       time.Unix(1e9, 0),
							DocumentRef:      "test",
						},
					},
				},
			},
			Query: &model.CertifyVEXStatementSpec{
				DocumentRef: ptrfrom.String("test"),
			},
			ExpVEX: []*model.CertifyVEXStatement{
				{
					Subject: testdata.P1out,
					Vulnerability: &model.Vulnerability{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					VexJustification: "test justification",
					KnownSince:       time.Unix(1e9, 0),
					DocumentRef:      "test",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: p}); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, &model.IDorArtifactInput{ArtifactInput: a}); err != nil {
					t.Fatalf("Could not ingest artifact: %a", err)
				}
			}
			for _, v := range test.InVuln {
				if _, err := b.IngestVulnerability(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: v}); err != nil {
					t.Fatalf("Could not ingest vulnerability: %v", err)
				}
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
			got, err := b.CertifyVEXStatementList(ctx, *test.Query, nil, nil)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			var returnedObjects []*model.CertifyVEXStatement
			if got != nil {
				for _, obj := range got.Edges {
					returnedObjects = append(returnedObjects, obj.Node)
				}
			}
			if diff := cmp.Diff(test.ExpVEX, returnedObjects, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
