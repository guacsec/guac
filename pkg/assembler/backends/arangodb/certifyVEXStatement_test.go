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

package arangodb

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestVEX(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
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
						Package: testdata.P1,
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
						Package: testdata.P1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
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
						Package: testdata.P1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
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
						Package: testdata.P1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P2,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A1,
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
						Package: testdata.P1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P2,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A1,
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
						Package: testdata.P1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A2,
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
						Package: testdata.P1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A2,
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
						Package: testdata.P1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					Vuln: testdata.O2,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
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
						Package: testdata.P1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					Vuln: testdata.O2,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
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
						Package: testdata.P1,
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
						Package: testdata.P1,
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
						Package: testdata.P1,
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
						Package: testdata.P1,
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
						Package: testdata.P1,
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
						Package: testdata.P1,
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
						Package: testdata.P1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
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
						Package: testdata.P1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
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
						Package: testdata.P1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					Vuln: testdata.O2,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
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
						Package: testdata.P1,
					},
					Vuln: testdata.O1,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					Vuln: testdata.O2,
					In: &model.VexStatementInputSpec{
						VexJustification: "test justification two",
						KnownSince:       time.Unix(1e9, 0),
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
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
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
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
			for _, o := range test.Calls {
				found, err := b.IngestVEXStatement(ctx, o.Sub, *o.Vuln, *o.In)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.CertifyVEXStatementSpec{
						ID: ptrfrom.String(found.ID),
					}
				}
				if test.QueryPkgID {
					if _, ok := found.Subject.(*model.Package); ok {
						test.Query = &model.CertifyVEXStatementSpec{
							Subject: &model.PackageOrArtifactSpec{
								Package: &model.PkgSpec{
									ID: ptrfrom.String(found.Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID),
								},
							},
						}
					}
				}
				if test.QueryArtID {
					if _, ok := found.Subject.(*model.Artifact); ok {
						test.Query = &model.CertifyVEXStatementSpec{
							Subject: &model.PackageOrArtifactSpec{
								Artifact: &model.ArtifactSpec{
									ID: ptrfrom.String(found.Subject.(*model.Artifact).ID),
								},
							},
						}
					}
				}
				if test.QueryVulnID {
					test.Query = &model.CertifyVEXStatementSpec{
						Vulnerability: &model.VulnerabilitySpec{
							ID: ptrfrom.String(found.Vulnerability.ID),
						},
					}
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

func TestVEXBulkIngest(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
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
			InPkg:  []*model.PkgInputSpec{testdata.P1},
			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
			Calls: []call{
				{
					Subs: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1},
					},
					Vulns: []*model.VulnerabilityInputSpec{testdata.O1},
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
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P1},
					},
					Vulns: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O1},
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
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					},
					Vulns: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O1},
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
						Artifacts: []*model.ArtifactInputSpec{testdata.A1},
					},
					Vulns: []*model.VulnerabilityInputSpec{testdata.O1},
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
						Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
					},
					Vulns: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O1},
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
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P1, testdata.P1},
					},
					Vulns: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2, testdata.C1},
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
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P1},
					},
					Vulns: []*model.VulnerabilityInputSpec{testdata.C1, testdata.O1},
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
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P1, testdata.P1},
					},
					Vulns: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2, testdata.C1},
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
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
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

// TODO (pxp928): add tests back in when implemented

// func TestVEXNeighbors(t *testing.T) {
// 	type call struct {
// 		Sub  model.PackageOrArtifactInput
// 		Vuln *model.VulnerabilityInputSpec
// 		In   *model.VexStatementInputSpec
// 	}
// 	tests := []struct {
// 		Name         string
// 		InPkg        []*model.PkgInputSpec
// 		InArt        []*model.ArtifactInputSpec
// 		InVuln       []*model.VulnerabilityInputSpec
// 		Calls        []call
// 		ExpNeighbors map[string][]string
// 	}{
// 		{
// 			Name:   "HappyPath",
// 			InPkg:  []*model.PkgInputSpec{testdata.P1},
// 			InVuln: []*model.VulnerabilityInputSpec{testdata.O1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					Vuln: testdata.O1,
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"4": []string{"1", "7"}, // pkg version -> pkg name, vex
// 				"6": []string{"5", "7"}, // vuln -> vuln type, vex
// 				"7": []string{"1", "5"}, // Vex -> pkg version, vuln
// 			},
// 		},
// 		{
// 			Name:   "Two vex on same package",
// 			InPkg:  []*model.PkgInputSpec{testdata.P1},
// 			InVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.O2},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					Vuln: testdata.O1,
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					Vuln: testdata.O2,
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"4": []string{"1", "8", "9"}, // pkg version -> pkg name, vex1, vex2
// 				"6": []string{"5", "8"},      // Vuln1 -> vulnType, vex1
// 				"7": []string{"5", "9"},      // Vuln2 -> vulnType, vex2
// 				"8": []string{"1", "5"},      // Vex1 -> pkg version, vuln1
// 				"9": []string{"1", "5"},      // Vex2 -> pkg version, vuln2
// 			},
// 		},
// 	}
// 	ctx := context.Background()
// 	for _, test := range tests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			b, err := inmem.getBackend(nil)
// 			if err != nil {
// 				t.Fatalf("Could not instantiate testing backend: %v", err)
// 			}
// 			for _, p := range test.InPkg {
// 				if _, err := b.IngestPackage(ctx, *p); err != nil {
// 					t.Fatalf("Could not ingest package: %v", err)
// 				}
// 			}
// 			for _, a := range test.InArt {
// 				if _, err := b.IngestArtifact(ctx, a); err != nil {
// 					t.Fatalf("Could not ingest artifact: %a", err)
// 				}
// 			}
// 			for _, v := range test.InVuln {
// 				if _, err := b.IngestVulnerability(ctx, *v); err != nil {
// 					t.Fatalf("Could not ingest vulnerability: %v", err)
// 				}
// 			}
// 			for _, o := range test.Calls {
// 				if _, err := b.IngestVEXStatement(ctx, o.Sub, *o.Vuln, *o.In); err != nil {
// 					t.Fatalf("Could not ingest VEXStatement")
// 				}
// 			}
// 			for q, r := range test.ExpNeighbors {
// 				got, err := b.Neighbors(ctx, q, nil)
// 				if err != nil {
// 					t.Fatalf("Could not query neighbors: %s", err)
// 				}
// 				gotIDs := convNodes(got)
// 				slices.Sort(r)
// 				slices.Sort(gotIDs)
// 				if diff := cmp.Diff(r, gotIDs); diff != "" {
// 					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
// 				}
// 			}
// 		})
// 	}
// }
