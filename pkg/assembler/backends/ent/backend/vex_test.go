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

// func (s *Suite) TestVEX() {
// 	testTime := time.Unix(1e9+5, 0)
// 	type call struct {
// 		Sub  model.PackageOrArtifactInput
// 		Vuln model.VulnerabilityInputSpec
// 		In   *model.VexStatementInputSpec
// 	}
// 	tests := []struct {
// 		Name         string
// 		InPkg        []*model.PkgInputSpec
// 		InArt        []*model.ArtifactInputSpec
// 		InOsv        []*model.OSVInputSpec
// 		InCve        []*model.CVEInputSpec
// 		InGhsa       []*model.GHSAInputSpec
// 		Calls        []call
// 		Query        *model.CertifyVEXStatementSpec
// 		ExpVEX       []*model.CertifyVEXStatement
// 		ExpIngestErr bool
// 		ExpQueryErr  bool
// 	}{
// 		{
// 			Name:  "HappyPath",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				VexJustification: (*model.VexJustification)(ptrfrom.String("test justification")),
// 			},
// 			ExpVEX: []*model.CertifyVEXStatement{
// 				&model.CertifyVEXStatement{
// 					Subject:          p1out,
// 					Vulnerability:    o1out,
// 					VexJustification: "test justification",
// 					KnownSince:       time.Unix(1e9, 0),
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Ingest same twice",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				VexJustification: (*model.VexJustification)(ptrfrom.String("test justification")),
// 			},
// 			ExpVEX: []*model.CertifyVEXStatement{
// 				&model.CertifyVEXStatement{
// 					Subject:          p1out,
// 					Vulnerability:    o1out,
// 					VexJustification: "test justification",
// 					KnownSince:       time.Unix(1e9, 0),
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Justification",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification 2",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				VexJustification: (*model.VexJustification)(ptrfrom.String("test justification 2")),
// 			},
// 			ExpVEX: []*model.CertifyVEXStatement{
// 				&model.CertifyVEXStatement{
// 					Subject:          p1out,
// 					Vulnerability:    o1out,
// 					VexJustification: "test justification 2",
// 					KnownSince:       time.Unix(1e9, 0),
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Package",
// 			InPkg: []*model.PkgInputSpec{p1, p2},
// 			InArt: []*model.ArtifactInputSpec{a1},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p2,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Artifact: a1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				Subject: &model.PackageOrArtifactSpec{
// 					Package: &model.PkgSpec{
// 						Version: ptrfrom.String(""),
// 					},
// 				},
// 			},
// 			ExpVEX: []*model.CertifyVEXStatement{
// 				&model.CertifyVEXStatement{
// 					Subject:          p1out,
// 					Vulnerability:    o1out,
// 					VexJustification: "test justification",
// 					KnownSince:       time.Unix(1e9, 0),
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Artifact",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InArt: []*model.ArtifactInputSpec{a1, a2},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Artifact: a1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Artifact: a2,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				Subject: &model.PackageOrArtifactSpec{
// 					Artifact: &model.ArtifactSpec{
// 						Algorithm: ptrfrom.String("sha256"),
// 					},
// 				},
// 			},
// 			ExpVEX: []*model.CertifyVEXStatement{
// 				&model.CertifyVEXStatement{
// 					Subject:          a1out,
// 					Vulnerability:    o1out,
// 					VexJustification: "test justification",
// 					KnownSince:       time.Unix(1e9, 0),
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Vuln",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1, o2},
// 			InCve: []*model.CVEInputSpec{c1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o2,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Cve: c1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				Vulnerability: &model.VulnerabilitySpec{
// 					Osv: &model.OSVSpec{
// 						OsvID: ptrfrom.String("CVE-2014-8140"),
// 					},
// 				},
// 			},
// 			ExpVEX: []*model.CertifyVEXStatement{
// 				&model.CertifyVEXStatement{
// 					Subject:          p1out,
// 					Vulnerability:    o1out,
// 					VexJustification: "test justification",
// 					KnownSince:       time.Unix(1e9, 0),
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Status",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 						Status:           "status one",
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 						Status:           "status two",
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				Status: (*model.VexStatus)(ptrfrom.String("status one")),
// 			},
// 			ExpVEX: []*model.CertifyVEXStatement{
// 				&model.CertifyVEXStatement{
// 					Subject:          p1out,
// 					Vulnerability:    o1out,
// 					VexJustification: "test justification",
// 					KnownSince:       time.Unix(1e9, 0),
// 					Status:           "status one",
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on Statement",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 						Statement:        "statement one",
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 						Statement:        "statement two",
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				Statement: ptrfrom.String("statement two"),
// 			},
// 			ExpVEX: []*model.CertifyVEXStatement{
// 				&model.CertifyVEXStatement{
// 					Subject:          p1out,
// 					Vulnerability:    o1out,
// 					VexJustification: "test justification",
// 					KnownSince:       time.Unix(1e9, 0),
// 					Statement:        "statement two",
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on KnownSince",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       testTime,
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				KnownSince: &testTime,
// 			},
// 			ExpVEX: []*model.CertifyVEXStatement{
// 				&model.CertifyVEXStatement{
// 					Subject:          p1out,
// 					Vulnerability:    o1out,
// 					VexJustification: "test justification",
// 					KnownSince:       testTime,
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query on ID",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1, o2},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o2,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				//ID: ptrfrom.String("17179869184"),
// 				ID: ptrfrom.String("0"),
// 			},
// 			ExpVEX: []*model.CertifyVEXStatement{
// 				&model.CertifyVEXStatement{
// 					Subject:          p1out,
// 					Vulnerability:    o1out,
// 					VexJustification: "test justification",
// 					KnownSince:       time.Unix(1e9, 0),
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Query None",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1, o2},
// 			InCve: []*model.CVEInputSpec{c1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o2,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Cve: c1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				Vulnerability: &model.VulnerabilitySpec{
// 					Osv: &model.OSVSpec{
// 						OsvID: ptrfrom.String("asdf"),
// 					},
// 				},
// 			},
// 			ExpVEX: nil,
// 		},
// 		{
// 			Name:  "Query multiple",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1, o2},
// 			InCve: []*model.CVEInputSpec{c1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o2,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification two",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Cve: c1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification two",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				VexJustification: (*model.VexJustification)(ptrfrom.String("test justification two")),
// 			},
// 			ExpVEX: []*model.CertifyVEXStatement{
// 				&model.CertifyVEXStatement{
// 					Subject:          p1out,
// 					Vulnerability:    o2out,
// 					VexJustification: "test justification two",
// 					KnownSince:       time.Unix(1e9, 0),
// 				},
// 				&model.CertifyVEXStatement{
// 					Subject:          p1out,
// 					Vulnerability:    c1out,
// 					VexJustification: "test justification two",
// 					KnownSince:       time.Unix(1e9, 0),
// 				},
// 			},
// 		},
// 		{
// 			Name:  "Ingest noVuln",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						NoVuln: ptrfrom.Bool(true),
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			ExpIngestErr: true,
// 		},
// 		{
// 			Name:  "Ingest without sub",
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			ExpIngestErr: true,
// 		},
// 		{
// 			Name:  "Ingest without vuln",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			ExpIngestErr: true,
// 		},
// 		{
// 			Name:  "Ingest double sub",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InArt: []*model.ArtifactInputSpec{a1},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package:  p1,
// 						Artifact: a1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			ExpIngestErr: true,
// 		},
// 		{
// 			Name:  "Ingest double vuln",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			InCve: []*model.CVEInputSpec{c1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 						Cve: c1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			ExpIngestErr: true,
// 		},
// 		{
// 			Name:  "Query double sub",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				Subject: &model.PackageOrArtifactSpec{
// 					Package: &model.PkgSpec{
// 						Version: ptrfrom.String(""),
// 					},
// 					Artifact: &model.ArtifactSpec{
// 						Algorithm: ptrfrom.String("sha256"),
// 					},
// 				},
// 			},
// 			ExpQueryErr: true,
// 		},
// 		{
// 			Name:  "Query double vuln",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				Vulnerability: &model.VulnerabilitySpec{
// 					Osv: &model.OSVSpec{
// 						OsvID: ptrfrom.String("asdf"),
// 					},
// 					Cve: &model.CVESpec{
// 						CveID: ptrfrom.String("asdf"),
// 					},
// 				},
// 			},
// 			ExpQueryErr: true,
// 		},
// 		{
// 			Name:  "Query no vuln",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				Vulnerability: &model.VulnerabilitySpec{
// 					NoVuln: ptrfrom.Bool(true),
// 				},
// 			},
// 			ExpQueryErr: true,
// 		},
// 		{
// 			Name:  "Query bad id",
// 			InPkg: []*model.PkgInputSpec{p1},
// 			InOsv: []*model.OSVInputSpec{o1},
// 			Calls: []call{
// 				call{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: p1,
// 					},
// 					Vuln: model.VulnerabilityInput{
// 						Osv: o1,
// 					},
// 					In: &model.VexStatementInputSpec{
// 						VexJustification: "test justification",
// 						KnownSince:       time.Unix(1e9, 0),
// 					},
// 				},
// 			},
// 			Query: &model.CertifyVEXStatementSpec{
// 				ID: ptrfrom.String("asdf"),
// 			},
// 			ExpQueryErr: true,
// 		},
// 	}
// 	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
// 		return strings.Compare(".ID", p[len(p)-1].String()) == 0
// 	}, cmp.Ignore())
// 	ctx := s.Ctx
// 	for _, test := range tests {
// 		s.Run(test.Name, func() {
// 			t := s.T()
// 			b, err := GetBackend(s.Client)
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
// 			for _, o := range test.InOsv {
// 				if _, err := b.IngestOsv(ctx, o); err != nil {
// 					t.Fatalf("Could not ingest osv: %v", err)
// 				}
// 			}
// 			for _, c := range test.InCve {
// 				if _, err := b.IngestCve(ctx, c); err != nil {
// 					t.Fatalf("Could not ingest cve: %v", err)
// 				}
// 			}
// 			for _, g := range test.InGhsa {
// 				if _, err := b.IngestGhsa(ctx, g); err != nil {
// 					t.Fatalf("Could not ingest ghsa: %a", err)
// 				}
// 			}
// 			ids := make([]string, len(test.Calls))
// 			for i, o := range test.Calls {
// 				v, err := b.IngestVEXStatement(ctx, o.Sub, o.Vuln, *o.In)
// 				if (err != nil) != test.ExpIngestErr {
// 					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
// 				}
// 				if err != nil {
// 					return
// 				}
// 				ids[i] = v.ID
// 			}

// 			if test.Query.ID != nil {
// 				idIdx, err := strconv.Atoi(*test.Query.ID)
// 				if err == nil {
// 					if idIdx >= len(ids) {
// 						s.T().Fatalf("ID index out of range, want: %d, got: %d", len(ids), idIdx)
// 					}
// 					test.Query.ID = ptrfrom.String(ids[idIdx])
// 				}
// 			}

// 			got, err := b.CertifyVEXStatement(ctx, test.Query)
// 			if (err != nil) != test.ExpQueryErr {
// 				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
// 			}
// 			if err != nil {
// 				return
// 			}
// 			if diff := cmp.Diff(test.ExpVEX, got, ignoreID); diff != "" {
// 				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
// 			}
// 		})
// 	}
// }

//func (s *Suite) TestVEXNeighbors() {
//	type call struct {
//		Sub  model.PackageOrArtifactInput
//		Vuln model.VulnerabilityInput
//		In   *model.VexStatementInputSpec
//	}
//	tests := []struct {
//		Name         string
//		InPkg        []*model.PkgInputSpec
//		InArt        []*model.ArtifactInputSpec
//		InOsv        []*model.OSVInputSpec
//		InCve        []*model.CVEInputSpec
//		InGhsa       []*model.GHSAInputSpec
//		Calls        []call
//		ExpNeighbors map[string][]string
//	}{
//		{
//			Name:  "HappyPath",
//			InPkg: []*model.PkgInputSpec{p1},
//			InOsv: []*model.OSVInputSpec{o1},
//			Calls: []call{
//				call{
//					Sub: model.PackageOrArtifactInput{
//						Package: p1,
//					},
//					Vuln: model.VulnerabilityInput{
//						Osv: o1,
//					},
//					In: &model.VexStatementInputSpec{
//						VexJustification: "test justification",
//						KnownSince:       time.Unix(1e9, 0),
//					},
//				},
//			},
//			ExpNeighbors: map[string][]string{
//				"5": []string{"2", "7"}, // pkg version -> pkg name, vex
//				"6": []string{"7"},      // Vuln -> vex
//				"7": []string{"2", "6"}, // Vex -> pkg version, vuln
//			},
//		},
//		{
//			Name:  "Two vex on same package",
//			InPkg: []*model.PkgInputSpec{p1},
//			InOsv: []*model.OSVInputSpec{o1, o2},
//			Calls: []call{
//				call{
//					Sub: model.PackageOrArtifactInput{
//						Package: p1,
//					},
//					Vuln: model.VulnerabilityInput{
//						Osv: o1,
//					},
//					In: &model.VexStatementInputSpec{
//						VexJustification: "test justification",
//						KnownSince:       time.Unix(1e9, 0),
//					},
//				},
//				call{
//					Sub: model.PackageOrArtifactInput{
//						Package: p1,
//					},
//					Vuln: model.VulnerabilityInput{
//						Osv: o2,
//					},
//					In: &model.VexStatementInputSpec{
//						VexJustification: "test justification",
//						KnownSince:       time.Unix(1e9, 0),
//					},
//				},
//			},
//			ExpNeighbors: map[string][]string{
//				"5": []string{"2", "8", "9"}, // pkg version -> pkg name, vex1, vex2
//				"6": []string{"8"},           // Vuln1 -> vex1
//				"7": []string{"9"},           // Vuln2 -> vex2
//				"8": []string{"2", "6"},      // Vex1 -> pkg version, vuln1
//				"9": []string{"2", "7"},      // Vex2 -> pkg version, vuln2
//			},
//		},
//	}
//	ctx := s.Ctx
//	for _, test := range tests {
//		s.Run(test.Name, func() {
//			t := s.T()
//			b, err := GetBackend(s.Client)
//			if err != nil {
//				t.Fatalf("Could not instantiate testing backend: %v", err)
//			}
//			for _, p := range test.InPkg {
//				if _, err := b.IngestPackage(ctx, *p); err != nil {
//					t.Fatalf("Could not ingest package: %v", err)
//				}
//			}
//			for _, a := range test.InArt {
//				if _, err := b.IngestArtifact(ctx, a); err != nil {
//					t.Fatalf("Could not ingest artifact: %a", err)
//				}
//			}
//			for _, o := range test.InOsv {
//				if _, err := b.IngestOsv(ctx, o); err != nil {
//					t.Fatalf("Could not ingest osv: %v", err)
//				}
//			}
//			for _, c := range test.InCve {
//				if _, err := b.IngestCve(ctx, c); err != nil {
//					t.Fatalf("Could not ingest cve: %v", err)
//				}
//			}
//			for _, g := range test.InGhsa {
//				if _, err := b.IngestGhsa(ctx, g); err != nil {
//					t.Fatalf("Could not ingest ghsa: %a", err)
//				}
//			}
//			for _, o := range test.Calls {
//				if _, err := b.IngestVEXStatement(ctx, o.Sub, o.Vuln, *o.In); err != nil {
//					t.Fatalf("Could not ingest VEXStatement")
//				}
//			}
//			for q, r := range test.ExpNeighbors {
//				got, err := b.Neighbors(ctx, q, nil)
//				if err != nil {
//					t.Fatalf("Could not query neighbors: %s", err)
//				}
//				gotIDs := convNodes(got)
//				slices.Sort(r)
//				slices.Sort(gotIDs)
//				if diff := cmp.Diff(r, gotIDs); diff != "" {
//					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
//				}
//			}
//		})
//	}
//}
