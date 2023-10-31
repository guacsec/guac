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
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func Test_Path(t *testing.T) {
	ctx := context.Background()
	arangoArg := getArangoConfig()
	err := deleteDatabase(ctx, arangoArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangoArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	type certifyVulnCall struct {
		Pkg         *model.PkgInputSpec
		Vuln        *model.VulnerabilityInputSpec
		CertifyVuln *model.ScanMetadataInput
	}
	type isDepCall struct {
		P1 *model.PkgInputSpec
		P2 *model.PkgInputSpec
		MF model.MatchFlags
		ID *model.IsDependencyInputSpec
	}
	tests := []struct {
		name                   string
		pkgInput               *model.PkgInputSpec
		vulnInput              *model.VulnerabilityInputSpec
		inPkg                  []*model.PkgInputSpec
		inVuln                 []*model.VulnerabilityInputSpec
		certifyVulnCall        *certifyVulnCall
		certifyVulnTwoPkgsCall *certifyVulnCall
		isDepCall              *isDepCall
		edges                  []model.Edge
		want                   []model.Node
		wantErr                bool
	}{
		{
			name:   "certifyVuln - edges not provided",
			inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			inPkg:  []*model.PkgInputSpec{testdata.P2},
			edges:  []model.Edge{},
			certifyVulnCall: &certifyVulnCall{
				Pkg:  testdata.P2,
				Vuln: testdata.G1,
				CertifyVuln: &model.ScanMetadataInput{
					Collector:      "test collector",
					Origin:         "test origin",
					ScannerVersion: "v1.0.0",
					ScannerURI:     "test scanner uri",
					DbVersion:      "2023.01.01",
					DbURI:          "test db uri",
					TimeScanned:    testdata.T1,
				},
			},
			want: []model.Node{
				testdata.P2out,
				&model.CertifyVuln{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
				&model.Vulnerability{
					Type:             "ghsa",
					VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
				},
			},
		},
		{
			name:   "certifyVuln - edges not provided",
			inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			inPkg:  []*model.PkgInputSpec{testdata.P2},
			edges:  []model.Edge{model.EdgePackageCertifyVuln, model.EdgeVulnerabilityCertifyVuln},
			certifyVulnCall: &certifyVulnCall{
				Pkg:  testdata.P2,
				Vuln: testdata.G1,
				CertifyVuln: &model.ScanMetadataInput{
					Collector:      "test collector",
					Origin:         "test origin",
					ScannerVersion: "v1.0.0",
					ScannerURI:     "test scanner uri",
					DbVersion:      "2023.01.01",
					DbURI:          "test db uri",
					TimeScanned:    testdata.T1,
				},
			},
			want: []model.Node{
				testdata.P2out,
				&model.CertifyVuln{
					Package: testdata.P2out,
					Vulnerability: &model.Vulnerability{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
					Metadata: vmd1,
				},
				&model.Vulnerability{
					Type:             "ghsa",
					VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
				},
			},
		},
		{
			name:   "certifyVuln - two packages (one vulnerable)",
			inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			inPkg:  []*model.PkgInputSpec{testdata.P2, testdata.P3},
			edges:  []model.Edge{model.EdgePackageCertifyVuln, model.EdgeVulnerabilityCertifyVuln},
			certifyVulnTwoPkgsCall: &certifyVulnCall{
				Pkg:  testdata.P2,
				Vuln: testdata.G1,
				CertifyVuln: &model.ScanMetadataInput{
					Collector:      "test collector",
					Origin:         "test origin",
					ScannerVersion: "v1.0.0",
					ScannerURI:     "test scanner uri",
					DbVersion:      "2023.01.01",
					DbURI:          "test db uri",
					TimeScanned:    testdata.T1,
				},
			},
			want: nil,
		},
		{
			name:  "isDependency",
			inPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			edges: []model.Edge{model.EdgePackageIsDependency, model.EdgeIsDependencyPackage},
			isDepCall: &isDepCall{
				P1: testdata.P1,
				P2: testdata.P2,
				MF: mAll,
				ID: &model.IsDependencyInputSpec{},
			},
			want: []model.Node{
				testdata.P1out,
				&model.IsDependency{
					Package:           testdata.P1out,
					DependencyPackage: testdata.P2outName,
				},
				testdata.P2outName,
			},
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var startID string
			var stopID string
			for _, g := range tt.inVuln {
				if _, err := b.IngestVulnerability(ctx, *g); err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				}
			}
			if tt.certifyVulnTwoPkgsCall != nil {
				var nonVulnPkgID string
				for _, p := range tt.inPkg {
					pkg, err := b.IngestPackage(ctx, *p)
					if err != nil {
						t.Fatalf("Could not ingest package: %v", err)
					}
					nonVulnPkgID = pkg.Namespaces[0].Names[0].Versions[0].ID
				}
				found, err := b.IngestCertifyVuln(ctx, *tt.certifyVulnTwoPkgsCall.Pkg, *tt.certifyVulnTwoPkgsCall.Vuln, *tt.certifyVulnTwoPkgsCall.CertifyVuln)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				startID = found.ID
				stopID = nonVulnPkgID
			}
			if tt.certifyVulnCall != nil {
				for _, p := range tt.inPkg {
					if _, err := b.IngestPackage(ctx, *p); err != nil {
						t.Fatalf("Could not ingest package: %v", err)
					}
				}
				found, err := b.IngestCertifyVuln(ctx, *tt.certifyVulnCall.Pkg, *tt.certifyVulnCall.Vuln, *tt.certifyVulnCall.CertifyVuln)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				startID = found.Package.Namespaces[0].Names[0].Versions[0].ID
				stopID = found.Vulnerability.VulnerabilityIDs[0].ID
			}
			if tt.isDepCall != nil {
				for _, p := range tt.inPkg {
					if _, err := b.IngestPackage(ctx, *p); err != nil {
						t.Fatalf("Could not ingest package: %v", err)
					}
				}
				found, err := b.IngestDependency(ctx, *tt.isDepCall.P1, *tt.isDepCall.P2, tt.isDepCall.MF, *tt.isDepCall.ID)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				startID = found.Package.Namespaces[0].Names[0].Versions[0].ID
				stopID = found.DependencyPackage.Namespaces[0].Names[0].ID
			}
			got, err := b.Path(ctx, startID, stopID, 5, tt.edges)
			if (err != nil) != tt.wantErr {
				t.Errorf("node query error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_Nodes(t *testing.T) {
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
	type certifyBadCall struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		CB    *model.CertifyBadInputSpec
	}
	type certifyGoodCall struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		CG    *model.CertifyGoodInputSpec
	}
	type certifyLegalCall struct {
		PkgSrc model.PackageOrSourceInput
		Dec    []*model.LicenseInputSpec
		Dis    []*model.LicenseInputSpec
		Legal  *model.CertifyLegalInputSpec
	}
	type scorecardCall struct {
		Src *model.SourceInputSpec
		SC  *model.ScorecardInputSpec
	}
	type vexCall struct {
		Sub  model.PackageOrArtifactInput
		Vuln *model.VulnerabilityInputSpec
		In   *model.VexStatementInputSpec
	}
	type certifyVulnCall struct {
		Pkg         *model.PkgInputSpec
		Vuln        *model.VulnerabilityInputSpec
		CertifyVuln *model.ScanMetadataInput
	}
	type hashEqualCall struct {
		A1 *model.ArtifactInputSpec
		A2 *model.ArtifactInputSpec
		HE *model.HashEqualInputSpec
	}
	type hasMetadataCall struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		HM    *model.HasMetadataInputSpec
	}
	type hasSBOMCall struct {
		Sub model.PackageOrArtifactInput
		HS  *model.HasSBOMInputSpec
	}
	type hasSlsaCall struct {
		Sub  *model.ArtifactInputSpec
		BF   []*model.ArtifactInputSpec
		BB   *model.BuilderInputSpec
		SLSA *model.SLSAInputSpec
	}
	type hasSourceAtCall struct {
		Pkg   *model.PkgInputSpec
		Src   *model.SourceInputSpec
		Match *model.MatchFlags
		HSA   *model.HasSourceAtInputSpec
	}
	type isDepCall struct {
		P1 *model.PkgInputSpec
		P2 *model.PkgInputSpec
		MF model.MatchFlags
		ID *model.IsDependencyInputSpec
	}
	type isOcurCall struct {
		PkgSrc     model.PackageOrSourceInput
		Artifact   *model.ArtifactInputSpec
		Occurrence *model.IsOccurrenceInputSpec
	}
	type pkgEqualCall struct {
		P1 *model.PkgInputSpec
		P2 *model.PkgInputSpec
		HE *model.PkgEqualInputSpec
	}
	type pointOfContactCall struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		POC   *model.PointOfContactInputSpec
	}
	type vulnEqualCall struct {
		Vuln      *model.VulnerabilityInputSpec
		OtherVuln *model.VulnerabilityInputSpec
		In        *model.VulnEqualInputSpec
	}
	type vulnMetadataCall struct {
		Vuln         *model.VulnerabilityInputSpec
		VulnMetadata *model.VulnerabilityMetadataInputSpec
	}
	tests := []struct {
		name               string
		pkgInput           *model.PkgInputSpec
		artifactInput      *model.ArtifactInputSpec
		builderInput       *model.BuilderInputSpec
		srcInput           *model.SourceInputSpec
		vulnInput          *model.VulnerabilityInputSpec
		licenseInput       *model.LicenseInputSpec
		inPkg              []*model.PkgInputSpec
		inSrc              []*model.SourceInputSpec
		inArt              []*model.ArtifactInputSpec
		inVuln             []*model.VulnerabilityInputSpec
		inBld              []*model.BuilderInputSpec
		inLic              []*model.LicenseInputSpec
		certifyBadCall     *certifyBadCall
		certifyGoodCall    *certifyGoodCall
		certifyLegalCall   *certifyLegalCall
		scorecardCall      *scorecardCall
		vexCall            *vexCall
		certifyVulnCall    *certifyVulnCall
		hashEqualCall      *hashEqualCall
		hasMetadataCall    *hasMetadataCall
		hasSBOMCall        *hasSBOMCall
		hasSlsaCall        *hasSlsaCall
		hasSourceAtCall    *hasSourceAtCall
		isDepCall          *isDepCall
		isOcurCall         *isOcurCall
		pkgEqualCall       *pkgEqualCall
		pointOfContactCall *pointOfContactCall
		vulnEqualCall      *vulnEqualCall
		vulnMetadataCall   *vulnMetadataCall
		want               []model.Node
		wantErr            bool
	}{{
		name:     "package",
		pkgInput: testdata.P1,
		want:     []model.Node{testdata.P1out},
		wantErr:  false,
	}, {
		name: "artifact",
		artifactInput: &model.ArtifactInputSpec{
			Algorithm: "sha256",
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
		},
		want: []model.Node{&model.Artifact{
			Algorithm: "sha256",
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
		}},
		wantErr: false,
	}, {
		name: "builder",
		builderInput: &model.BuilderInputSpec{
			URI: "https://github.com/CreateFork/HubHostedActions@v1",
		},
		want: []model.Node{&model.Builder{
			URI: "https://github.com/CreateFork/HubHostedActions@v1",
		}},
		wantErr: false,
	}, {
		name:     "source",
		srcInput: testdata.S1,
		want:     []model.Node{testdata.S1out},
		wantErr:  false,
	}, {
		name:      "vulnerability",
		vulnInput: testdata.C1,
		want: []model.Node{&model.Vulnerability{
			Type:             "cve",
			VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
		}},
	}, {
		name:         "license",
		licenseInput: testdata.L1,
		want:         []model.Node{testdata.L1out},
	}, {
		name:  "certifyBad",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		certifyBadCall: &certifyBadCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P1,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CB: &model.CertifyBadInputSpec{
				Justification: "test justification",
			},
		},
		want: []model.Node{&model.CertifyBad{
			Subject:       testdata.P1out,
			Justification: "test justification",
		}},
	}, {
		name:  "certifyGood",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		certifyGoodCall: &certifyGoodCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P1,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CG: &model.CertifyGoodInputSpec{
				Justification: "test justification",
			},
		},
		want: []model.Node{&model.CertifyGood{
			Subject:       testdata.P1out,
			Justification: "test justification",
		}},
	}, {
		name:  "certifyLegal",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		inLic: []*model.LicenseInputSpec{testdata.L1},
		certifyLegalCall: &certifyLegalCall{
			PkgSrc: model.PackageOrSourceInput{
				Package: testdata.P1,
			},
			Dec: []*model.LicenseInputSpec{testdata.L1},
			Legal: &model.CertifyLegalInputSpec{
				Justification: "test justification 2",
			},
		},
		want: []model.Node{&model.CertifyLegal{
			Subject:          testdata.P1out,
			DeclaredLicenses: []*model.License{testdata.L1out},
			Justification:    "test justification 2",
		}},
	}, {
		name:  "scorecard",
		inSrc: []*model.SourceInputSpec{testdata.S2},
		scorecardCall: &scorecardCall{
			Src: testdata.S2,
			SC: &model.ScorecardInputSpec{
				Origin: "test origin",
			},
		},
		want: []model.Node{&model.CertifyScorecard{
			Source: testdata.S2out,
			Scorecard: &model.Scorecard{
				Checks: []*model.ScorecardCheck{},
				Origin: "test origin",
			},
		}},
	}, {
		name:   "vex",
		inPkg:  []*model.PkgInputSpec{testdata.P1},
		inVuln: []*model.VulnerabilityInputSpec{testdata.O2},
		vexCall: &vexCall{
			Sub: model.PackageOrArtifactInput{
				Package: testdata.P1,
			},
			Vuln: testdata.O2,
			In: &model.VexStatementInputSpec{
				VexJustification: "test justification",
				KnownSince:       time.Unix(1e9, 0),
			},
		},
		want: []model.Node{&model.CertifyVEXStatement{
			Subject: testdata.P1out,
			Vulnerability: &model.Vulnerability{
				Type:             "osv",
				VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
			},
			VexJustification: "test justification",
			KnownSince:       time.Unix(1e9, 0),
		}},
	}, {
		name:   "certifyVuln",
		inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
		inPkg:  []*model.PkgInputSpec{testdata.P2},
		certifyVulnCall: &certifyVulnCall{
			Pkg:  testdata.P2,
			Vuln: testdata.G1,
			CertifyVuln: &model.ScanMetadataInput{
				Collector:      "test collector",
				Origin:         "test origin",
				ScannerVersion: "v1.0.0",
				ScannerURI:     "test scanner uri",
				DbVersion:      "2023.01.01",
				DbURI:          "test db uri",
				TimeScanned:    testdata.T1,
			},
		},
		want: []model.Node{&model.CertifyVuln{
			Package: testdata.P2out,
			Vulnerability: &model.Vulnerability{
				Type:             "ghsa",
				VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
			},
			Metadata: vmd1,
		}},
	}, {
		name:  "hashEqual",
		inArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3},
		hashEqualCall: &hashEqualCall{
			A1: testdata.A1,
			A2: testdata.A3,
			HE: &model.HashEqualInputSpec{},
		},
		want: []model.Node{&model.HashEqual{
			Artifacts: []*model.Artifact{testdata.A3out, testdata.A1out},
		}},
	}, {
		name:  "hasMetadata",
		inArt: []*model.ArtifactInputSpec{testdata.A2},
		hasMetadataCall: &hasMetadataCall{
			Sub: model.PackageSourceOrArtifactInput{
				Artifact: testdata.A2,
			},
			HM: &model.HasMetadataInputSpec{
				Justification: "test justification",
			},
		},
		want: []model.Node{&model.HasMetadata{
			Subject:       testdata.A2out,
			Justification: "test justification",
		}},
	}, {
		name:  "hasSBOM",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		hasSBOMCall: &hasSBOMCall{

			Sub: model.PackageOrArtifactInput{
				Package: testdata.P1,
			},
			HS: &model.HasSBOMInputSpec{
				DownloadLocation: "location two",
			},
		},
		want: []model.Node{&model.HasSbom{
			Subject:          testdata.P1out,
			DownloadLocation: "location two",
		}},
	}, {
		name:  "hasSLSA",
		inArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
		inBld: []*model.BuilderInputSpec{testdata.B1, testdata.B2},
		hasSlsaCall: &hasSlsaCall{
			Sub:  testdata.A1,
			BF:   []*model.ArtifactInputSpec{testdata.A2},
			BB:   testdata.B2,
			SLSA: &model.SLSAInputSpec{},
		},
		want: []model.Node{&model.HasSlsa{
			Subject: testdata.A1out,
			Slsa: &model.Slsa{
				BuiltBy:   testdata.B2out,
				BuiltFrom: []*model.Artifact{testdata.A2out},
			},
		}},
	}, {
		name:  "hasSourceAt",
		inPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
		inSrc: []*model.SourceInputSpec{testdata.S1},
		hasSourceAtCall: &hasSourceAtCall{
			Pkg: testdata.P2,
			Src: testdata.S1,
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			HSA: &model.HasSourceAtInputSpec{},
		},
		want: []model.Node{&model.HasSourceAt{
			Package: testdata.P2out,
			Source:  testdata.S1out,
		}},
	}, {
		name:  "isDependency",
		inPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
		isDepCall: &isDepCall{
			P1: testdata.P1,
			P2: testdata.P2,
			MF: mAll,
			ID: &model.IsDependencyInputSpec{},
		},
		want: []model.Node{&model.IsDependency{
			Package:           testdata.P1out,
			DependencyPackage: testdata.P2outName,
		}},
	}, {
		name:  "isOccurrence",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		inArt: []*model.ArtifactInputSpec{testdata.A1},
		isOcurCall: &isOcurCall{
			PkgSrc: model.PackageOrSourceInput{
				Package: testdata.P1,
			},
			Artifact: testdata.A1,
			Occurrence: &model.IsOccurrenceInputSpec{
				Justification: "test justification",
			},
		},
		want: []model.Node{&model.IsOccurrence{
			Subject:       testdata.P1out,
			Artifact:      testdata.A1out,
			Justification: "test justification",
		}},
	}, {
		name:  "pkgEqual",
		inPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
		pkgEqualCall: &pkgEqualCall{
			P1: testdata.P1,
			P2: testdata.P2,
			HE: &model.PkgEqualInputSpec{
				Justification: "test justification two",
			},
		},
		want: []model.Node{&model.PkgEqual{

			Packages:      []*model.Package{testdata.P1out, testdata.P2out},
			Justification: "test justification two",
		}},
	}, {
		name:  "pointOfContact",
		inArt: []*model.ArtifactInputSpec{testdata.A2},
		pointOfContactCall: &pointOfContactCall{
			Sub: model.PackageSourceOrArtifactInput{
				Artifact: testdata.A2,
			},
			POC: &model.PointOfContactInputSpec{
				Justification: "test justification",
			},
		},
		want: []model.Node{&model.PointOfContact{
			Subject:       testdata.A2out,
			Justification: "test justification",
		}},
	}, {
		name:   "vulnEqual",
		inVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.G1},
		vulnEqualCall: &vulnEqualCall{
			Vuln:      testdata.O1,
			OtherVuln: testdata.G1,
			In: &model.VulnEqualInputSpec{
				Justification: "test justification",
			},
		},
		want: []model.Node{&model.VulnEqual{
			Vulnerabilities: []*model.Vulnerability{
				{
					Type:             "osv",
					VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
				},
				{
					Type:             "ghsa",
					VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
				},
			},
			Justification: "test justification",
		}},
	}, {
		name:   "vulnMetadata",
		inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
		vulnMetadataCall: &vulnMetadataCall{
			Vuln: testdata.G1,
			VulnMetadata: &model.VulnerabilityMetadataInputSpec{
				ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
				ScoreValue: 8.9,
				Timestamp:  testdata.T1,
				Collector:  "test collector",
				Origin:     "test origin",
			},
		},
		want: []model.Node{&model.VulnerabilityMetadata{
			Vulnerability: &model.Vulnerability{
				Type:             "ghsa",
				VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
			},
			ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
			ScoreValue: 8.9,
			Timestamp:  testdata.T1,
			Collector:  "test collector",
			Origin:     "test origin",
		}},
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nodeID string
			for _, p := range tt.inPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range tt.inSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range tt.inArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, bld := range tt.inBld {
				if _, err := b.IngestBuilder(ctx, bld); err != nil {
					t.Fatalf("Could not ingest builder: %v", err)
				}
			}
			for _, a := range tt.inLic {
				if _, err := b.IngestLicense(ctx, a); err != nil {
					t.Fatalf("Could not ingest license: %v", err)
				}
			}
			for _, g := range tt.inVuln {
				if _, err := b.IngestVulnerability(ctx, *g); err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				}
			}
			if tt.pkgInput != nil {
				ingestedPkg, err := b.IngestPackage(ctx, *tt.pkgInput)
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedPkg.Namespaces[0].Names[0].Versions[0].ID
			}
			if tt.artifactInput != nil {
				ingestedArt, err := b.IngestArtifact(ctx, tt.artifactInput)
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestArtifact() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedArt.ID
			}
			if tt.builderInput != nil {
				ingestedBuilder, err := b.IngestBuilder(ctx, tt.builderInput)
				if (err != nil) != tt.wantErr {
					t.Errorf("demoClient.IngestBuilder() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedBuilder.ID
			}
			if tt.srcInput != nil {
				ingestedSrc, err := b.IngestSource(ctx, *tt.srcInput)
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestSource() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedSrc.Namespaces[0].Names[0].ID
			}
			if tt.vulnInput != nil {
				ingestVuln, err := b.IngestVulnerability(ctx, *tt.vulnInput)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.want, err)
				}
				nodeID = ingestVuln.VulnerabilityIDs[0].ID
			}
			if tt.licenseInput != nil {
				ingestedLicense, err := b.IngestLicense(ctx, tt.licenseInput)
				if (err != nil) != tt.wantErr {
					t.Errorf("demoClient.IngestLicense() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedLicense.ID
			}
			if tt.certifyBadCall != nil {
				found, err := b.IngestCertifyBad(ctx, tt.certifyBadCall.Sub, tt.certifyBadCall.Match, *tt.certifyBadCall.CB)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.certifyGoodCall != nil {
				found, err := b.IngestCertifyGood(ctx, tt.certifyGoodCall.Sub, tt.certifyGoodCall.Match, *tt.certifyGoodCall.CG)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.certifyLegalCall != nil {
				found, err := b.IngestCertifyLegal(ctx, tt.certifyLegalCall.PkgSrc, tt.certifyLegalCall.Dec, tt.certifyLegalCall.Dis, tt.certifyLegalCall.Legal)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.scorecardCall != nil {
				found, err := b.IngestScorecard(ctx, *tt.scorecardCall.Src, *tt.scorecardCall.SC)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.vexCall != nil {
				found, err := b.IngestVEXStatement(ctx, tt.vexCall.Sub, *tt.vexCall.Vuln, *tt.vexCall.In)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.certifyVulnCall != nil {
				found, err := b.IngestCertifyVuln(ctx, *tt.certifyVulnCall.Pkg, *tt.certifyVulnCall.Vuln, *tt.certifyVulnCall.CertifyVuln)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.hashEqualCall != nil {
				found, err := b.IngestHashEqual(ctx, *tt.hashEqualCall.A1, *tt.hashEqualCall.A2, *tt.hashEqualCall.HE)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.hasMetadataCall != nil {
				found, err := b.IngestHasMetadata(ctx, tt.hasMetadataCall.Sub, tt.hasMetadataCall.Match, *tt.hasMetadataCall.HM)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.hasSBOMCall != nil {
				// TODO (knrc) handle includes
				found, err := b.IngestHasSbom(ctx, tt.hasSBOMCall.Sub, *tt.hasSBOMCall.HS, model.HasSBOMIncludesInputSpec{})
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.hasSlsaCall != nil {
				found, err := b.IngestSLSA(ctx, *tt.hasSlsaCall.Sub, tt.hasSlsaCall.BF, *tt.hasSlsaCall.BB, *tt.hasSlsaCall.SLSA)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.hasSourceAtCall != nil {
				found, err := b.IngestHasSourceAt(ctx, *tt.hasSourceAtCall.Pkg, *tt.hasSourceAtCall.Match, *tt.hasSourceAtCall.Src, *tt.hasSourceAtCall.HSA)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.isDepCall != nil {
				found, err := b.IngestDependency(ctx, *tt.isDepCall.P1, *tt.isDepCall.P2, tt.isDepCall.MF, *tt.isDepCall.ID)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.isOcurCall != nil {
				found, err := b.IngestOccurrence(ctx, tt.isOcurCall.PkgSrc, *tt.isOcurCall.Artifact, *tt.isOcurCall.Occurrence)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.pkgEqualCall != nil {
				found, err := b.IngestPkgEqual(ctx, *tt.pkgEqualCall.P1, *tt.pkgEqualCall.P2, *tt.pkgEqualCall.HE)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.pointOfContactCall != nil {
				found, err := b.IngestPointOfContact(ctx, tt.pointOfContactCall.Sub, tt.pointOfContactCall.Match, *tt.pointOfContactCall.POC)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.vulnEqualCall != nil {
				found, err := b.IngestVulnEqual(ctx, *tt.vulnEqualCall.Vuln, *tt.vulnEqualCall.OtherVuln, *tt.vulnEqualCall.In)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found.ID
			}
			if tt.vulnMetadataCall != nil {
				found, err := b.IngestVulnerabilityMetadata(ctx, *tt.vulnMetadataCall.Vuln, *tt.vulnMetadataCall.VulnMetadata)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = found
			}
			got, err := b.Nodes(ctx, []string{nodeID})
			if (err != nil) != tt.wantErr {
				t.Errorf("node query error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_Neighbors(t *testing.T) {
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
	type certifyBadCall struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		CB    *model.CertifyBadInputSpec
	}
	type certifyGoodCall struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		CG    *model.CertifyGoodInputSpec
	}
	type certifyLegalCall struct {
		PkgSrc model.PackageOrSourceInput
		Dec    []*model.LicenseInputSpec
		Dis    []*model.LicenseInputSpec
		Legal  *model.CertifyLegalInputSpec
	}
	type scorecardCall struct {
		Src *model.SourceInputSpec
		SC  *model.ScorecardInputSpec
	}
	type vexCall struct {
		Sub  model.PackageOrArtifactInput
		Vuln *model.VulnerabilityInputSpec
		In   *model.VexStatementInputSpec
	}
	type certifyVulnCall struct {
		Pkg         *model.PkgInputSpec
		Vuln        *model.VulnerabilityInputSpec
		CertifyVuln *model.ScanMetadataInput
	}
	type hashEqualCall struct {
		A1 *model.ArtifactInputSpec
		A2 *model.ArtifactInputSpec
		HE *model.HashEqualInputSpec
	}
	type hasMetadataCall struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		HM    *model.HasMetadataInputSpec
	}
	type hasSBOMCall struct {
		Sub model.PackageOrArtifactInput
		HS  *model.HasSBOMInputSpec
	}
	type hasSlsaCall struct {
		Sub  *model.ArtifactInputSpec
		BF   []*model.ArtifactInputSpec
		BB   *model.BuilderInputSpec
		SLSA *model.SLSAInputSpec
	}
	type hasSourceAtCall struct {
		Pkg   *model.PkgInputSpec
		Src   *model.SourceInputSpec
		Match *model.MatchFlags
		HSA   *model.HasSourceAtInputSpec
	}
	type isDepCall struct {
		P1 *model.PkgInputSpec
		P2 *model.PkgInputSpec
		MF model.MatchFlags
		ID *model.IsDependencyInputSpec
	}
	type isOcurCall struct {
		PkgSrc     model.PackageOrSourceInput
		Artifact   *model.ArtifactInputSpec
		Occurrence *model.IsOccurrenceInputSpec
	}
	type pkgEqualCall struct {
		P1 *model.PkgInputSpec
		P2 *model.PkgInputSpec
		HE *model.PkgEqualInputSpec
	}
	type pointOfContactCall struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		POC   *model.PointOfContactInputSpec
	}
	type vulnEqualCall struct {
		Vuln      *model.VulnerabilityInputSpec
		OtherVuln *model.VulnerabilityInputSpec
		In        *model.VulnEqualInputSpec
	}
	type vulnMetadataCall struct {
		Vuln         *model.VulnerabilityInputSpec
		VulnMetadata *model.VulnerabilityMetadataInputSpec
	}
	tests := []struct {
		name                     string
		pkgInput                 *model.PkgInputSpec
		srcInput                 *model.SourceInputSpec
		vulnInput                *model.VulnerabilityInputSpec
		licenseInput             *model.LicenseInputSpec
		inPkg                    []*model.PkgInputSpec
		inSrc                    []*model.SourceInputSpec
		inArt                    []*model.ArtifactInputSpec
		inVuln                   []*model.VulnerabilityInputSpec
		inBld                    []*model.BuilderInputSpec
		inLic                    []*model.LicenseInputSpec
		queryArtifactID          bool
		queryEqualArtifactID     bool
		queryBuilderID           bool
		queryPkgTypeID           bool
		queryPkgNamespaceID      bool
		queryPkgNameID           bool
		queryPkgVersionID        bool
		queryEqualPkgID          bool
		querySrcTypeID           bool
		querySrcNamespaceID      bool
		querySrcNameID           bool
		queryVulnTypeID          bool
		queryVulnID              bool
		queryEqualVulnID         bool
		queryDeclaredLicenseID   bool
		queryDiscoveredLicenseID bool
		queryCertifyBadID        bool
		queryCertifyGoodID       bool
		queryCertifyLegalID      bool
		queryScorecardID         bool
		queryCertifyVexID        bool
		queryCertifyVulnID       bool
		queryHashEqualID         bool
		queryHasMetadataID       bool
		queryHasSbomID           bool
		queryHasSlsaID           bool
		queryHasSourceAtID       bool
		queryIsDependencyID      bool
		queryIsOccurrenceID      bool
		queryPkgEqualID          bool
		queryPointOfContactID    bool
		queryVulnEqualID         bool
		queryVulnMetadataID      bool
		certifyBadCall           *certifyBadCall
		certifyGoodCall          *certifyGoodCall
		certifyLegalCall         *certifyLegalCall
		scorecardCall            *scorecardCall
		vexCall                  *vexCall
		certifyVulnCall          *certifyVulnCall
		hashEqualCall            *hashEqualCall
		hasMetadataCall          *hasMetadataCall
		hasSBOMCall              *hasSBOMCall
		hasSlsaCall              *hasSlsaCall
		hasSourceAtCall          *hasSourceAtCall
		isDepCall                *isDepCall
		isOcurCall               *isOcurCall
		pkgEqualCall             *pkgEqualCall
		pointOfContactCall       *pointOfContactCall
		vulnEqualCall            *vulnEqualCall
		vulnMetadataCall         *vulnMetadataCall
		usingOnly                []model.Edge
		want                     []model.Node
		wantErr                  bool
	}{{
		name:           "package - pkgType",
		pkgInput:       testdata.P1,
		queryPkgTypeID: true,
		want: []model.Node{&model.Package{
			Type: "pypi",
			Namespaces: []*model.PackageNamespace{{
				Names: []*model.PackageName{},
			}}}},
		wantErr: false,
	}, {
		name:                "package - pkgNamespace",
		pkgInput:            testdata.P1,
		queryPkgNamespaceID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}}},
			&model.Package{
				Type:       "pypi",
				Namespaces: []*model.PackageNamespace{},
			}},
		wantErr: false,
	}, {
		name:           "package - pkgName",
		pkgInput:       testdata.P1,
		queryPkgNameID: true,
		want: []model.Node{
			testdata.P1out,
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{},
				}}}},
		wantErr: false,
	}, {
		name:              "package - pkgVersion",
		pkgInput:          testdata.P1,
		queryPkgVersionID: true,
		want: []model.Node{&model.Package{
			Type: "pypi",
			Namespaces: []*model.PackageNamespace{{
				Names: []*model.PackageName{{
					Name:     "tensorflow",
					Versions: []*model.PackageVersion{},
				}},
			}}}},
		wantErr: false,
	}, {
		name:           "source - srcType",
		srcInput:       testdata.S1,
		querySrcTypeID: true,
		want: []model.Node{&model.Source{
			Type: "git",
			Namespaces: []*model.SourceNamespace{{
				Namespace: "github.com/jeff",
				Names:     []*model.SourceName{},
			}},
		}},
		wantErr: false,
	}, {
		name:                "source - srcNamespace",
		srcInput:            testdata.S1,
		querySrcNamespaceID: true,
		want: []model.Node{
			testdata.S1out,
			&model.Source{
				Type:       "git",
				Namespaces: []*model.SourceNamespace{},
			}},
		wantErr: false,
	}, {
		name:           "source - srcName",
		srcInput:       testdata.S1,
		querySrcNameID: true,
		want: []model.Node{
			&model.Source{
				Type: "git",
				Namespaces: []*model.SourceNamespace{{
					Namespace: "github.com/jeff",
					Names:     []*model.SourceName{},
				}},
			}},
		wantErr: false,
	}, {
		name:            "vulnerability - type",
		vulnInput:       testdata.C1,
		queryVulnTypeID: true,
		want: []model.Node{&model.Vulnerability{
			Type:             "cve",
			VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
		}},
	}, {
		name:        "vulnerability - vulnID",
		vulnInput:   testdata.C1,
		queryVulnID: true,
		want: []model.Node{&model.Vulnerability{
			Type:             "cve",
			VulnerabilityIDs: []*model.VulnerabilityID{},
		}},
	}, {
		name:  "certifyBad - Artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A2},
		certifyBadCall: &certifyBadCall{
			Sub: model.PackageSourceOrArtifactInput{
				Artifact: testdata.A2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CB: &model.CertifyBadInputSpec{
				Justification: "test justification",
			},
		},
		queryArtifactID: true,
		want: []model.Node{&model.CertifyBad{
			Subject:       testdata.A2out,
			Justification: "test justification",
		}},
	}, {
		name:  "certifyBad - PkgName",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		certifyBadCall: &certifyBadCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			CB: &model.CertifyBadInputSpec{
				Justification: "test justification",
			},
		},
		queryPkgNameID: true,
		want: []model.Node{
			testdata.P2out,
			testdata.P1out,
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{},
				}}},
			&model.CertifyBad{
				Subject:       testdata.P2outName,
				Justification: "test justification",
			}},
	}, {
		name:  "certifyBad - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		certifyBadCall: &certifyBadCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CB: &model.CertifyBadInputSpec{
				Justification: "test justification",
			},
		},
		queryPkgVersionID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}},
			},
			&model.CertifyBad{
				Subject:       testdata.P2out,
				Justification: "test justification",
			}},
	}, {
		name:  "certifyBad - srcName",
		inSrc: []*model.SourceInputSpec{testdata.S1},
		certifyBadCall: &certifyBadCall{
			Sub: model.PackageSourceOrArtifactInput{
				Source: testdata.S1,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CB: &model.CertifyBadInputSpec{
				Justification: "test justification",
			},
		},
		querySrcNameID: true,
		want: []model.Node{
			&model.Source{
				Type: "git",
				Namespaces: []*model.SourceNamespace{{
					Namespace: "github.com/jeff",
					Names:     []*model.SourceName{},
				}},
			},
			&model.CertifyBad{
				Subject:       testdata.S1out,
				Justification: "test justification",
			}},
	}, {
		name:  "certifyBad - query certifyBadID artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A2},
		certifyBadCall: &certifyBadCall{
			Sub: model.PackageSourceOrArtifactInput{
				Artifact: testdata.A2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CB: &model.CertifyBadInputSpec{
				Justification: "test justification",
			},
		},
		queryCertifyBadID: true,
		want:              []model.Node{testdata.A2out},
	}, {
		name:  "certifyBad - query certifyBadID PkgName",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		certifyBadCall: &certifyBadCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			CB: &model.CertifyBadInputSpec{
				Justification: "test justification",
			},
		},
		queryCertifyBadID: true,
		want:              []model.Node{testdata.P2outName},
	}, {
		name:  "certifyBad - query certifyBadID pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		certifyBadCall: &certifyBadCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CB: &model.CertifyBadInputSpec{
				Justification: "test justification",
			},
		},
		queryCertifyBadID: true,
		want:              []model.Node{testdata.P2out},
	}, {
		name:  "certifyBad - query certifyBadID srcName",
		inSrc: []*model.SourceInputSpec{testdata.S1},
		certifyBadCall: &certifyBadCall{
			Sub: model.PackageSourceOrArtifactInput{
				Source: testdata.S1,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CB: &model.CertifyBadInputSpec{
				Justification: "test justification",
			},
		},
		queryCertifyBadID: true,
		want:              []model.Node{testdata.S1out},
	}, {
		name:  "certifyGood - artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A2},
		certifyGoodCall: &certifyGoodCall{
			Sub: model.PackageSourceOrArtifactInput{
				Artifact: testdata.A2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CG: &model.CertifyGoodInputSpec{
				Justification: "test justification",
			},
		},
		queryArtifactID: true,
		want: []model.Node{&model.CertifyGood{
			Subject:       testdata.A2out,
			Justification: "test justification",
		}},
	}, {
		name:  "certifyGood - PkgName",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		certifyGoodCall: &certifyGoodCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			CG: &model.CertifyGoodInputSpec{
				Justification: "test justification",
			},
		},
		queryPkgNameID: true,
		want: []model.Node{
			testdata.P2out,
			testdata.P1out,
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{},
				}}},
			&model.CertifyGood{
				Subject:       testdata.P2outName,
				Justification: "test justification",
			}},
	}, {
		name:  "certifyGood - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		certifyGoodCall: &certifyGoodCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CG: &model.CertifyGoodInputSpec{
				Justification: "test justification",
			},
		},
		queryPkgVersionID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}},
			},
			&model.CertifyGood{
				Subject:       testdata.P2out,
				Justification: "test justification",
			}},
	}, {
		name:  "certifyGood - srcName",
		inSrc: []*model.SourceInputSpec{testdata.S1},
		certifyGoodCall: &certifyGoodCall{
			Sub: model.PackageSourceOrArtifactInput{
				Source: testdata.S1,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CG: &model.CertifyGoodInputSpec{
				Justification: "test justification",
			},
		},
		querySrcNameID: true,
		want: []model.Node{
			&model.Source{
				Type: "git",
				Namespaces: []*model.SourceNamespace{{
					Namespace: "github.com/jeff",
					Names:     []*model.SourceName{},
				}},
			},
			&model.CertifyGood{
				Subject:       testdata.S1out,
				Justification: "test justification",
			}},
	}, {
		name:  "certifyGood - query certifyGoodID artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A2},
		certifyGoodCall: &certifyGoodCall{
			Sub: model.PackageSourceOrArtifactInput{
				Artifact: testdata.A2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CG: &model.CertifyGoodInputSpec{
				Justification: "test justification",
			},
		},
		queryCertifyGoodID: true,
		want:               []model.Node{testdata.A2out},
	}, {
		name:  "certifyGood - query certifyGoodID PkgName",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		certifyGoodCall: &certifyGoodCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			CG: &model.CertifyGoodInputSpec{
				Justification: "test justification",
			},
		},
		queryCertifyGoodID: true,
		want:               []model.Node{testdata.P2outName},
	}, {
		name:  "certifyGood - query certifyGoodID pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		certifyGoodCall: &certifyGoodCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CG: &model.CertifyGoodInputSpec{
				Justification: "test justification",
			},
		},
		queryCertifyGoodID: true,
		want:               []model.Node{testdata.P2out},
	}, {
		name:  "certifyGood - query certifyGoodID srcName",
		inSrc: []*model.SourceInputSpec{testdata.S1},
		certifyGoodCall: &certifyGoodCall{
			Sub: model.PackageSourceOrArtifactInput{
				Source: testdata.S1,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			CG: &model.CertifyGoodInputSpec{
				Justification: "test justification",
			},
		},
		queryCertifyGoodID: true,
		want:               []model.Node{testdata.S1out},
	}, {
		name:  "certifyLegal - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		inLic: []*model.LicenseInputSpec{testdata.L1},
		certifyLegalCall: &certifyLegalCall{
			PkgSrc: model.PackageOrSourceInput{
				Package: testdata.P1,
			},
			Dec: []*model.LicenseInputSpec{testdata.L1},
			Legal: &model.CertifyLegalInputSpec{
				Justification: "test justification 2",
			},
		},
		queryPkgVersionID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}},
			},
			&model.CertifyLegal{
				Subject:          testdata.P1out,
				DeclaredLicenses: []*model.License{testdata.L1out},
				Justification:    "test justification 2",
			}},
	}, {
		name:  "certifyLegal - srcName",
		inSrc: []*model.SourceInputSpec{testdata.S1},
		inLic: []*model.LicenseInputSpec{testdata.L1},
		certifyLegalCall: &certifyLegalCall{
			PkgSrc: model.PackageOrSourceInput{
				Source: testdata.S1,
			},
			Dec: []*model.LicenseInputSpec{testdata.L1},
			Legal: &model.CertifyLegalInputSpec{
				Justification: "test justification 2",
			},
		},
		querySrcNameID: true,
		want: []model.Node{
			&model.Source{
				Type: "git",
				Namespaces: []*model.SourceNamespace{{
					Namespace: "github.com/jeff",
					Names:     []*model.SourceName{},
				}},
			},
			&model.CertifyLegal{
				Subject:          testdata.S1out,
				DeclaredLicenses: []*model.License{testdata.L1out},
				Justification:    "test justification 2",
			}},
	}, {
		name:  "certifyLegal - Declared License",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		inLic: []*model.LicenseInputSpec{testdata.L2},
		certifyLegalCall: &certifyLegalCall{
			PkgSrc: model.PackageOrSourceInput{
				Package: testdata.P1,
			},
			Dec: []*model.LicenseInputSpec{testdata.L2},
			Legal: &model.CertifyLegalInputSpec{
				Justification: "test justification 2",
			},
		},
		queryDeclaredLicenseID: true,
		want: []model.Node{
			&model.CertifyLegal{
				Subject:          testdata.P1out,
				DeclaredLicenses: []*model.License{testdata.L2out},
				Justification:    "test justification 2",
			}},
	}, {
		name:  "certifyLegal - Discovered License",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		inLic: []*model.LicenseInputSpec{testdata.L3},
		certifyLegalCall: &certifyLegalCall{
			PkgSrc: model.PackageOrSourceInput{
				Package: testdata.P1,
			},
			Dis: []*model.LicenseInputSpec{testdata.L3},
			Legal: &model.CertifyLegalInputSpec{
				Justification: "test justification 2",
			},
		},
		queryDiscoveredLicenseID: true,
		want: []model.Node{
			&model.CertifyLegal{
				Subject:            testdata.P1out,
				DiscoveredLicenses: []*model.License{testdata.L3out},
				Justification:      "test justification 2",
			}},
	}, {
		name:  "certifyLegal - query certifyLegalID pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		inLic: []*model.LicenseInputSpec{testdata.L1},
		certifyLegalCall: &certifyLegalCall{
			PkgSrc: model.PackageOrSourceInput{
				Package: testdata.P1,
			},
			Dec: []*model.LicenseInputSpec{testdata.L1},
			Legal: &model.CertifyLegalInputSpec{
				Justification: "test justification 2",
			},
		},
		queryCertifyLegalID: true,
		usingOnly:           []model.Edge{model.EdgeCertifyLegalPackage},
		want:                []model.Node{testdata.P1out},
	}, {
		name:  "certifyLegal - srcName",
		inSrc: []*model.SourceInputSpec{testdata.S1},
		inLic: []*model.LicenseInputSpec{testdata.L1},
		certifyLegalCall: &certifyLegalCall{
			PkgSrc: model.PackageOrSourceInput{
				Source: testdata.S1,
			},
			Dec: []*model.LicenseInputSpec{testdata.L1},
			Legal: &model.CertifyLegalInputSpec{
				Justification: "test justification 2",
			},
		},
		queryCertifyLegalID: true,
		usingOnly:           []model.Edge{model.EdgeCertifyLegalSource},
		want:                []model.Node{testdata.S1out},
	}, {
		name:  "certifyLegal - Declared License",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		inLic: []*model.LicenseInputSpec{testdata.L2},
		certifyLegalCall: &certifyLegalCall{
			PkgSrc: model.PackageOrSourceInput{
				Package: testdata.P1,
			},
			Dec: []*model.LicenseInputSpec{testdata.L2},
			Legal: &model.CertifyLegalInputSpec{
				Justification: "test justification 2",
			},
		},
		queryCertifyLegalID: true,
		usingOnly:           []model.Edge{model.EdgeCertifyLegalLicense},
		want:                []model.Node{testdata.L2out},
	}, {
		name:  "certifyLegal - Discovered License",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		inLic: []*model.LicenseInputSpec{testdata.L3},
		certifyLegalCall: &certifyLegalCall{
			PkgSrc: model.PackageOrSourceInput{
				Package: testdata.P1,
			},
			Dis: []*model.LicenseInputSpec{testdata.L3},
			Legal: &model.CertifyLegalInputSpec{
				Justification: "test justification 2",
			},
		},
		queryCertifyLegalID: true,
		usingOnly:           []model.Edge{model.EdgeCertifyLegalLicense},
		want:                []model.Node{testdata.L3out},
	}, {
		name:  "scorecard",
		inSrc: []*model.SourceInputSpec{testdata.S2},
		scorecardCall: &scorecardCall{
			Src: testdata.S2,
			SC: &model.ScorecardInputSpec{
				Origin: "test origin",
			},
		},
		querySrcNameID: true,
		want: []model.Node{
			&model.Source{
				Type: "git",
				Namespaces: []*model.SourceNamespace{{
					Namespace: "github.com/bob",
					Names:     []*model.SourceName{},
				}},
			},
			&model.CertifyScorecard{
				Source: testdata.S2out,
				Scorecard: &model.Scorecard{
					Checks: []*model.ScorecardCheck{},
					Origin: "test origin",
				},
			}},
	}, {
		name:  "scorecard - certifyScoreID",
		inSrc: []*model.SourceInputSpec{testdata.S2},
		scorecardCall: &scorecardCall{
			Src: testdata.S2,
			SC: &model.ScorecardInputSpec{
				Origin: "test origin",
			},
		},
		queryScorecardID: true,
		usingOnly:        []model.Edge{model.EdgeCertifyScorecardSource},
		want:             []model.Node{testdata.S2out},
	}, {
		name:   "vex - artifact",
		inArt:  []*model.ArtifactInputSpec{testdata.A2},
		inVuln: []*model.VulnerabilityInputSpec{testdata.O2},
		vexCall: &vexCall{
			Sub: model.PackageOrArtifactInput{
				Artifact: testdata.A2,
			},
			Vuln: testdata.O2,
			In: &model.VexStatementInputSpec{
				VexJustification: "test justification",
				KnownSince:       time.Unix(1e9, 0),
			},
		},
		queryArtifactID: true,
		want: []model.Node{&model.CertifyVEXStatement{
			Subject: testdata.A2out,
			Vulnerability: &model.Vulnerability{
				Type:             "osv",
				VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
			},
			VexJustification: "test justification",
			KnownSince:       time.Unix(1e9, 0),
		}},
	}, {
		name:   "vex - pkgVersion",
		inPkg:  []*model.PkgInputSpec{testdata.P1},
		inVuln: []*model.VulnerabilityInputSpec{testdata.O2},
		vexCall: &vexCall{
			Sub: model.PackageOrArtifactInput{
				Package: testdata.P1,
			},
			Vuln: testdata.O2,
			In: &model.VexStatementInputSpec{
				VexJustification: "test justification",
				KnownSince:       time.Unix(1e9, 0),
			},
		},
		queryPkgVersionID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}},
			},
			&model.CertifyVEXStatement{
				Subject: testdata.P1out,
				Vulnerability: &model.Vulnerability{
					Type:             "osv",
					VulnerabilityIDs: []*model.VulnerabilityID{testdata.O2out},
				},
				VexJustification: "test justification",
				KnownSince:       time.Unix(1e9, 0),
			}},
	}, {
		name:   "vex - vulnID",
		inPkg:  []*model.PkgInputSpec{testdata.P1},
		inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
		vexCall: &vexCall{
			Sub: model.PackageOrArtifactInput{
				Package: testdata.P1,
			},
			Vuln: testdata.G1,
			In: &model.VexStatementInputSpec{
				VexJustification: "test justification",
				KnownSince:       time.Unix(1e9, 0),
			},
		},
		queryVulnID: true,
		want: []model.Node{
			&model.Vulnerability{
				Type:             "ghsa",
				VulnerabilityIDs: []*model.VulnerabilityID{},
			},
			&model.CertifyVEXStatement{
				Subject: testdata.P1out,
				Vulnerability: &model.Vulnerability{
					Type:             "ghsa",
					VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
				},
				VexJustification: "test justification",
				KnownSince:       time.Unix(1e9, 0),
			}},
	}, {
		name:   "vex - certifyVexID - artifact",
		inArt:  []*model.ArtifactInputSpec{testdata.A2},
		inVuln: []*model.VulnerabilityInputSpec{testdata.O2},
		vexCall: &vexCall{
			Sub: model.PackageOrArtifactInput{
				Artifact: testdata.A2,
			},
			Vuln: testdata.O2,
			In: &model.VexStatementInputSpec{
				VexJustification: "test justification",
				KnownSince:       time.Unix(1e9, 0),
			},
		},
		queryCertifyVexID: true,
		usingOnly:         []model.Edge{model.EdgeCertifyVexStatementArtifact},
		want:              []model.Node{testdata.A2out},
	}, {
		name:   "vex - certifyVexID - pkgVersion",
		inPkg:  []*model.PkgInputSpec{testdata.P1},
		inVuln: []*model.VulnerabilityInputSpec{testdata.O2},
		vexCall: &vexCall{
			Sub: model.PackageOrArtifactInput{
				Package: testdata.P1,
			},
			Vuln: testdata.O2,
			In: &model.VexStatementInputSpec{
				VexJustification: "test justification",
				KnownSince:       time.Unix(1e9, 0),
			},
		},
		queryCertifyVexID: true,
		usingOnly:         []model.Edge{model.EdgeCertifyVexStatementPackage},
		want:              []model.Node{testdata.P1out},
	}, {
		name:   "vex - certifyVexID - vulnID",
		inPkg:  []*model.PkgInputSpec{testdata.P1},
		inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
		vexCall: &vexCall{
			Sub: model.PackageOrArtifactInput{
				Package: testdata.P1,
			},
			Vuln: testdata.G1,
			In: &model.VexStatementInputSpec{
				VexJustification: "test justification",
				KnownSince:       time.Unix(1e9, 0),
			},
		},
		queryCertifyVexID: true,
		usingOnly:         []model.Edge{model.EdgeCertifyVexStatementVulnerability},
		want: []model.Node{&model.Vulnerability{
			Type:             "ghsa",
			VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
		}},
	}, {
		name:   "certifyVuln - pkgVersion",
		inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
		inPkg:  []*model.PkgInputSpec{testdata.P2},
		certifyVulnCall: &certifyVulnCall{
			Pkg:  testdata.P2,
			Vuln: testdata.G1,
			CertifyVuln: &model.ScanMetadataInput{
				Collector:      "test collector",
				Origin:         "test origin",
				ScannerVersion: "v1.0.0",
				ScannerURI:     "test scanner uri",
				DbVersion:      "2023.01.01",
				DbURI:          "test db uri",
				TimeScanned:    testdata.T1,
			},
		},
		queryPkgVersionID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}},
			},
			&model.CertifyVuln{
				Package: testdata.P2out,
				Vulnerability: &model.Vulnerability{
					Type:             "ghsa",
					VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
				},
				Metadata: vmd1,
			}},
	}, {
		name:   "certifyVuln - vulnID",
		inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
		inPkg:  []*model.PkgInputSpec{testdata.P2},
		certifyVulnCall: &certifyVulnCall{
			Pkg:  testdata.P2,
			Vuln: testdata.G1,
			CertifyVuln: &model.ScanMetadataInput{
				Collector:      "test collector",
				Origin:         "test origin",
				ScannerVersion: "v1.0.0",
				ScannerURI:     "test scanner uri",
				DbVersion:      "2023.01.01",
				DbURI:          "test db uri",
				TimeScanned:    testdata.T1,
			},
		},
		queryVulnID: true,
		want: []model.Node{
			&model.Vulnerability{
				Type:             "ghsa",
				VulnerabilityIDs: []*model.VulnerabilityID{},
			},
			&model.CertifyVuln{
				Package: testdata.P2out,
				Vulnerability: &model.Vulnerability{
					Type:             "ghsa",
					VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
				},
				Metadata: vmd1,
			}},
	}, {
		name:   "certifyVuln - certifyVulnID -  pkgVersion",
		inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
		inPkg:  []*model.PkgInputSpec{testdata.P2},
		certifyVulnCall: &certifyVulnCall{
			Pkg:  testdata.P2,
			Vuln: testdata.G1,
			CertifyVuln: &model.ScanMetadataInput{
				Collector:      "test collector",
				Origin:         "test origin",
				ScannerVersion: "v1.0.0",
				ScannerURI:     "test scanner uri",
				DbVersion:      "2023.01.01",
				DbURI:          "test db uri",
				TimeScanned:    testdata.T1,
			},
		},
		queryCertifyVulnID: true,
		usingOnly:          []model.Edge{model.EdgeCertifyVulnPackage},
		want:               []model.Node{testdata.P2out},
	}, {
		name:   "certifyVuln - vulnID",
		inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
		inPkg:  []*model.PkgInputSpec{testdata.P2},
		certifyVulnCall: &certifyVulnCall{
			Pkg:  testdata.P2,
			Vuln: testdata.G1,
			CertifyVuln: &model.ScanMetadataInput{
				Collector:      "test collector",
				Origin:         "test origin",
				ScannerVersion: "v1.0.0",
				ScannerURI:     "test scanner uri",
				DbVersion:      "2023.01.01",
				DbURI:          "test db uri",
				TimeScanned:    testdata.T1,
			},
		},
		queryCertifyVulnID: true,
		usingOnly:          []model.Edge{model.EdgeCertifyVulnVulnerability},
		want: []model.Node{&model.Vulnerability{
			Type:             "ghsa",
			VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
		}},
	}, {
		name:  "hashEqual - artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3},
		hashEqualCall: &hashEqualCall{
			A1: testdata.A1,
			A2: testdata.A3,
			HE: &model.HashEqualInputSpec{},
		},
		queryArtifactID: true,
		want: []model.Node{&model.HashEqual{
			Artifacts: []*model.Artifact{testdata.A3out, testdata.A1out},
		}},
	}, {
		name:  "hashEqual - second artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3},
		hashEqualCall: &hashEqualCall{
			A1: testdata.A1,
			A2: testdata.A3,
			HE: &model.HashEqualInputSpec{},
		},
		queryEqualArtifactID: true,
		want: []model.Node{&model.HashEqual{
			Artifacts: []*model.Artifact{testdata.A3out, testdata.A1out},
		}},
	}, {
		name:  "hashEqual - hashEqualID",
		inArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2, testdata.A3},
		hashEqualCall: &hashEqualCall{
			A1: testdata.A1,
			A2: testdata.A3,
			HE: &model.HashEqualInputSpec{},
		},
		queryHashEqualID: true,
		want:             []model.Node{testdata.A3out, testdata.A1out},
	}, {
		name:  "hasMetadata - artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A2},
		hasMetadataCall: &hasMetadataCall{
			Sub: model.PackageSourceOrArtifactInput{
				Artifact: testdata.A2,
			},
			HM: &model.HasMetadataInputSpec{
				Justification: "test justification",
			},
		},
		queryArtifactID: true,
		want: []model.Node{&model.HasMetadata{
			Subject:       testdata.A2out,
			Justification: "test justification",
		}},
	}, {
		name:  "hasMetadata - pkgName",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		hasMetadataCall: &hasMetadataCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			HM: &model.HasMetadataInputSpec{
				Justification: "test justification",
			},
		},
		queryPkgNameID: true,
		want: []model.Node{
			testdata.P2out,
			testdata.P1out,
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{},
				}}},
			&model.HasMetadata{
				Subject:       testdata.P2outName,
				Justification: "test justification",
			}},
	}, {
		name:  "hasMetadata - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		hasMetadataCall: &hasMetadataCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			HM: &model.HasMetadataInputSpec{
				Justification: "test justification",
			},
		},
		queryPkgVersionID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}},
			},
			&model.HasMetadata{
				Subject:       testdata.P2out,
				Justification: "test justification",
			}},
	}, {
		name:  "hasMetadata - srcName",
		inSrc: []*model.SourceInputSpec{testdata.S1},
		hasMetadataCall: &hasMetadataCall{
			Sub: model.PackageSourceOrArtifactInput{
				Source: testdata.S1,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			HM: &model.HasMetadataInputSpec{
				Justification: "test justification",
			},
		},
		querySrcNameID: true,
		want: []model.Node{
			&model.Source{
				Type: "git",
				Namespaces: []*model.SourceNamespace{{
					Namespace: "github.com/jeff",
					Names:     []*model.SourceName{},
				}},
			},
			&model.HasMetadata{
				Subject:       testdata.S1out,
				Justification: "test justification",
			}},
	}, {
		name:  "hasMetadata - hasMetadataID - artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A2},
		hasMetadataCall: &hasMetadataCall{
			Sub: model.PackageSourceOrArtifactInput{
				Artifact: testdata.A2,
			},
			HM: &model.HasMetadataInputSpec{
				Justification: "test justification",
			},
		},
		queryHasMetadataID: true,
		usingOnly:          []model.Edge{model.EdgeHasMetadataArtifact},
		want:               []model.Node{testdata.A2out},
	}, {
		name:  "hasMetadata - hasMetadataID - pkgName",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		hasMetadataCall: &hasMetadataCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			HM: &model.HasMetadataInputSpec{
				Justification: "test justification",
			},
		},
		queryHasMetadataID: true,
		usingOnly:          []model.Edge{model.EdgeHasMetadataPackage},
		want:               []model.Node{testdata.P2outName},
	}, {
		name:  "hasMetadata - hasMetadataID - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		hasMetadataCall: &hasMetadataCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			HM: &model.HasMetadataInputSpec{
				Justification: "test justification",
			},
		},
		queryHasMetadataID: true,
		usingOnly:          []model.Edge{model.EdgeHasMetadataPackage},
		want:               []model.Node{testdata.P2out},
	}, {
		name:  "hasMetadata - hasMetadataID - srcName",
		inSrc: []*model.SourceInputSpec{testdata.S1},
		hasMetadataCall: &hasMetadataCall{
			Sub: model.PackageSourceOrArtifactInput{
				Source: testdata.S1,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			HM: &model.HasMetadataInputSpec{
				Justification: "test justification",
			},
		},
		queryHasMetadataID: true,
		usingOnly:          []model.Edge{model.EdgeHasMetadataSource},
		want:               []model.Node{testdata.S1out},
	}, {
		name:  "hasSBOM - artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A2},
		hasSBOMCall: &hasSBOMCall{
			Sub: model.PackageOrArtifactInput{
				Artifact: testdata.A2,
			},
			HS: &model.HasSBOMInputSpec{
				DownloadLocation: "location two",
			},
		},
		queryArtifactID: true,
		want: []model.Node{&model.HasSbom{
			Subject:          testdata.A2out,
			DownloadLocation: "location two",
		}},
	}, {
		name:  "hasSBOM - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		hasSBOMCall: &hasSBOMCall{
			Sub: model.PackageOrArtifactInput{
				Package: testdata.P2,
			},
			HS: &model.HasSBOMInputSpec{
				DownloadLocation: "location two",
			},
		},
		queryPkgVersionID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}},
			},
			&model.HasSbom{
				Subject:          testdata.P2out,
				DownloadLocation: "location two",
			}},
	}, {
		name:  "hasSBOM - hasSbomID - artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A2},
		hasSBOMCall: &hasSBOMCall{
			Sub: model.PackageOrArtifactInput{
				Artifact: testdata.A2,
			},
			HS: &model.HasSBOMInputSpec{
				DownloadLocation: "location two",
			},
		},
		queryHasSbomID: true,
		usingOnly:      []model.Edge{model.EdgeHasSbomArtifact},
		want:           []model.Node{testdata.A2out},
	}, {
		name:  "hasSBOM - hasSbomID - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		hasSBOMCall: &hasSBOMCall{
			Sub: model.PackageOrArtifactInput{
				Package: testdata.P2,
			},
			HS: &model.HasSBOMInputSpec{
				DownloadLocation: "location two",
			},
		},
		queryHasSbomID: true,
		usingOnly:      []model.Edge{model.EdgeHasSbomPackage},
		want:           []model.Node{testdata.P2out},
	}, {
		name:  "hasSLSA - builder",
		inArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
		inBld: []*model.BuilderInputSpec{testdata.B1, testdata.B2},
		hasSlsaCall: &hasSlsaCall{
			Sub:  testdata.A1,
			BF:   []*model.ArtifactInputSpec{testdata.A2},
			BB:   testdata.B2,
			SLSA: &model.SLSAInputSpec{},
		},
		queryBuilderID: true,
		want: []model.Node{&model.HasSlsa{
			Subject: testdata.A1out,
			Slsa: &model.Slsa{
				BuiltBy:   testdata.B2out,
				BuiltFrom: []*model.Artifact{testdata.A2out},
			},
		}},
	}, {
		name:  "hasSLSA - subject artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
		inBld: []*model.BuilderInputSpec{testdata.B1, testdata.B2},
		hasSlsaCall: &hasSlsaCall{
			Sub:  testdata.A1,
			BF:   []*model.ArtifactInputSpec{testdata.A2},
			BB:   testdata.B2,
			SLSA: &model.SLSAInputSpec{},
		},
		queryArtifactID: true,
		want: []model.Node{&model.HasSlsa{
			Subject: testdata.A1out,
			Slsa: &model.Slsa{
				BuiltBy:   testdata.B2out,
				BuiltFrom: []*model.Artifact{testdata.A2out},
			},
		}},
	}, {
		name:  "hasSLSA - hasSlsaID - builder",
		inArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
		inBld: []*model.BuilderInputSpec{testdata.B1, testdata.B2},
		hasSlsaCall: &hasSlsaCall{
			Sub:  testdata.A1,
			BF:   []*model.ArtifactInputSpec{testdata.A2},
			BB:   testdata.B2,
			SLSA: &model.SLSAInputSpec{},
		},
		queryHasSlsaID: true,
		usingOnly:      []model.Edge{model.EdgeHasSlsaBuiltBy},
		want:           []model.Node{testdata.B2out},
	}, {
		name:  "hasSLSA - hasSlsaID - subject artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
		inBld: []*model.BuilderInputSpec{testdata.B1, testdata.B2},
		hasSlsaCall: &hasSlsaCall{
			Sub:  testdata.A1,
			BF:   []*model.ArtifactInputSpec{testdata.A2},
			BB:   testdata.B2,
			SLSA: &model.SLSAInputSpec{},
		},
		queryHasSlsaID: true,
		usingOnly:      []model.Edge{model.EdgeHasSlsaSubject},
		want:           []model.Node{testdata.A1out},
	}, {
		name:  "hasSLSA - hasSlsaID - builtFrom",
		inArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
		inBld: []*model.BuilderInputSpec{testdata.B1, testdata.B2},
		hasSlsaCall: &hasSlsaCall{
			Sub:  testdata.A1,
			BF:   []*model.ArtifactInputSpec{testdata.A2},
			BB:   testdata.B2,
			SLSA: &model.SLSAInputSpec{},
		},
		queryHasSlsaID: true,
		usingOnly:      []model.Edge{model.EdgeHasSlsaMaterials},
		want:           []model.Node{testdata.A2out},
	}, {
		name:  "hasSourceAt - pkgName",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		inSrc: []*model.SourceInputSpec{testdata.S1},
		hasSourceAtCall: &hasSourceAtCall{
			Pkg: testdata.P2,
			Src: testdata.S1,
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			HSA: &model.HasSourceAtInputSpec{},
		},
		queryPkgNameID: true,
		want: []model.Node{
			testdata.P2out,
			testdata.P1out,
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{},
				}}},
			&model.HasSourceAt{
				Package: testdata.P2outName,
				Source:  testdata.S1out,
			}},
	}, {
		name:  "hasSourceAt - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		inSrc: []*model.SourceInputSpec{testdata.S1},
		hasSourceAtCall: &hasSourceAtCall{
			Pkg: testdata.P2,
			Src: testdata.S1,
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			HSA: &model.HasSourceAtInputSpec{},
		},
		queryPkgVersionID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}}},
			&model.HasSourceAt{
				Package: testdata.P2out,
				Source:  testdata.S1out,
			}},
	}, {
		name:  "hasSourceAt - srcName",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		inSrc: []*model.SourceInputSpec{testdata.S1},
		hasSourceAtCall: &hasSourceAtCall{
			Pkg: testdata.P2,
			Src: testdata.S1,
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			HSA: &model.HasSourceAtInputSpec{},
		},
		querySrcNameID: true,
		want: []model.Node{
			&model.Source{
				Type: "git",
				Namespaces: []*model.SourceNamespace{{
					Namespace: "github.com/jeff",
					Names:     []*model.SourceName{},
				}},
			},
			&model.HasSourceAt{
				Package: testdata.P2out,
				Source:  testdata.S1out,
			},
			&model.HasSourceAt{
				Package: testdata.P2outName,
				Source:  testdata.S1out,
			}},
	}, {
		name:  "hasSourceAt - hasSourceAtID - pkgName",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		inSrc: []*model.SourceInputSpec{testdata.S1},
		hasSourceAtCall: &hasSourceAtCall{
			Pkg: testdata.P2,
			Src: testdata.S1,
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			HSA: &model.HasSourceAtInputSpec{},
		},
		queryHasSourceAtID: true,
		usingOnly:          []model.Edge{model.EdgeHasSourceAtPackage},
		want:               []model.Node{testdata.P2outName},
	}, {
		name:  "hasSourceAt - hasSourceAtID - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		inSrc: []*model.SourceInputSpec{testdata.S1},
		hasSourceAtCall: &hasSourceAtCall{
			Pkg: testdata.P2,
			Src: testdata.S1,
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			HSA: &model.HasSourceAtInputSpec{},
		},
		queryHasSourceAtID: true,
		usingOnly:          []model.Edge{model.EdgeHasSourceAtPackage},
		want:               []model.Node{testdata.P2out},
	}, {
		name:  "hasSourceAt - hasSourceAtID - srcName",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		inSrc: []*model.SourceInputSpec{testdata.S1},
		hasSourceAtCall: &hasSourceAtCall{
			Pkg: testdata.P2,
			Src: testdata.S1,
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			HSA: &model.HasSourceAtInputSpec{},
		},
		queryHasSourceAtID: true,
		usingOnly:          []model.Edge{model.EdgeHasSourceAtSource},
		want:               []model.Node{testdata.S1out},
	}, {
		name:  "isDependency - pkgName",
		inPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
		isDepCall: &isDepCall{
			P1: testdata.P1,
			P2: testdata.P2,
			MF: mAll,
			ID: &model.IsDependencyInputSpec{},
		},
		queryPkgNameID: true,
		want: []model.Node{
			testdata.P2out,
			testdata.P1out,
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{},
				}}},
			&model.IsDependency{
				Package:           testdata.P1out,
				DependencyPackage: testdata.P2outName,
			}},
	}, {
		name:  "isDependency - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
		isDepCall: &isDepCall{
			P1: testdata.P1,
			P2: testdata.P2,
			MF: mSpecific,
			ID: &model.IsDependencyInputSpec{},
		},
		queryPkgVersionID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}}},
			&model.IsDependency{
				Package:           testdata.P1out,
				DependencyPackage: testdata.P2out,
			}},
	}, {
		name:  "isDependency - isDependencyID - pkgName",
		inPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
		isDepCall: &isDepCall{
			P1: testdata.P1,
			P2: testdata.P2,
			MF: mAll,
			ID: &model.IsDependencyInputSpec{},
		},
		queryIsDependencyID: true,
		usingOnly:           []model.Edge{model.EdgeIsDependencyPackage},
		want:                []model.Node{testdata.P1out, testdata.P2outName},
	}, {
		name:  "isDependency - isDependencyID - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
		isDepCall: &isDepCall{
			P1: testdata.P1,
			P2: testdata.P2,
			MF: mSpecific,
			ID: &model.IsDependencyInputSpec{},
		},
		queryIsDependencyID: true,
		usingOnly:           []model.Edge{model.EdgeIsDependencyPackage},
		want:                []model.Node{testdata.P1out, testdata.P2out},
	}, {
		name:  "isOccurrence - artifact",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		inArt: []*model.ArtifactInputSpec{testdata.A1},
		isOcurCall: &isOcurCall{
			PkgSrc: model.PackageOrSourceInput{
				Package: testdata.P1,
			},
			Artifact: testdata.A1,
			Occurrence: &model.IsOccurrenceInputSpec{
				Justification: "test justification",
			},
		},
		queryArtifactID: true,
		want: []model.Node{&model.IsOccurrence{
			Subject:       testdata.P1out,
			Artifact:      testdata.A1out,
			Justification: "test justification",
		}},
	}, {
		name:  "isOccurrence - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		inArt: []*model.ArtifactInputSpec{testdata.A1},
		isOcurCall: &isOcurCall{
			PkgSrc: model.PackageOrSourceInput{
				Package: testdata.P1,
			},
			Artifact: testdata.A1,
			Occurrence: &model.IsOccurrenceInputSpec{
				Justification: "test justification",
			},
		},
		queryPkgVersionID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}}},
			&model.IsOccurrence{
				Subject:       testdata.P1out,
				Artifact:      testdata.A1out,
				Justification: "test justification",
			}},
	}, {
		name:  "isOccurrence - srcName",
		inSrc: []*model.SourceInputSpec{testdata.S1},
		inArt: []*model.ArtifactInputSpec{testdata.A1},
		isOcurCall: &isOcurCall{
			PkgSrc: model.PackageOrSourceInput{
				Source: testdata.S1,
			},
			Artifact: testdata.A1,
			Occurrence: &model.IsOccurrenceInputSpec{
				Justification: "test justification",
			},
		},
		querySrcNameID: true,
		want: []model.Node{
			&model.Source{
				Type: "git",
				Namespaces: []*model.SourceNamespace{{
					Namespace: "github.com/jeff",
					Names:     []*model.SourceName{},
				}},
			},
			&model.IsOccurrence{
				Subject:       testdata.S1out,
				Artifact:      testdata.A1out,
				Justification: "test justification",
			}},
	}, {
		name:  "isOccurrence - isOccurrenceID - artifact",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		inArt: []*model.ArtifactInputSpec{testdata.A1},
		isOcurCall: &isOcurCall{
			PkgSrc: model.PackageOrSourceInput{
				Package: testdata.P1,
			},
			Artifact: testdata.A1,
			Occurrence: &model.IsOccurrenceInputSpec{
				Justification: "test justification",
			},
		},
		queryIsOccurrenceID: true,
		usingOnly:           []model.Edge{model.EdgeIsOccurrenceArtifact},
		want:                []model.Node{testdata.A1out},
	}, {
		name:  "isOccurrence - isOccurrenceID - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P1},
		inArt: []*model.ArtifactInputSpec{testdata.A1},
		isOcurCall: &isOcurCall{
			PkgSrc: model.PackageOrSourceInput{
				Package: testdata.P1,
			},
			Artifact: testdata.A1,
			Occurrence: &model.IsOccurrenceInputSpec{
				Justification: "test justification",
			},
		},
		queryIsOccurrenceID: true,
		usingOnly:           []model.Edge{model.EdgeIsOccurrencePackage},
		want:                []model.Node{testdata.P1out},
	}, {
		name:  "isOccurrence - isOccurrenceID - srcName",
		inSrc: []*model.SourceInputSpec{testdata.S1},
		inArt: []*model.ArtifactInputSpec{testdata.A1},
		isOcurCall: &isOcurCall{
			PkgSrc: model.PackageOrSourceInput{
				Source: testdata.S1,
			},
			Artifact: testdata.A1,
			Occurrence: &model.IsOccurrenceInputSpec{
				Justification: "test justification",
			},
		},
		queryIsOccurrenceID: true,
		usingOnly:           []model.Edge{model.EdgeIsOccurrenceSource},
		want:                []model.Node{testdata.S1out},
	}, {
		name:  "pkgEqual",
		inPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
		pkgEqualCall: &pkgEqualCall{
			P1: testdata.P1,
			P2: testdata.P2,
			HE: &model.PkgEqualInputSpec{
				Justification: "test justification two",
			},
		},
		queryPkgVersionID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}},
			},
			&model.PkgEqual{
				Packages:      []*model.Package{testdata.P1out, testdata.P2out},
				Justification: "test justification two",
			}},
	}, {
		name:  "pkgEqual - equal package",
		inPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
		pkgEqualCall: &pkgEqualCall{
			P1: testdata.P1,
			P2: testdata.P2,
			HE: &model.PkgEqualInputSpec{
				Justification: "test justification two",
			},
		},
		queryEqualPkgID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}},
			},
			&model.PkgEqual{
				Packages:      []*model.Package{testdata.P1out, testdata.P2out},
				Justification: "test justification two",
			}},
	}, {
		name:  "pkgEqual - pkgEqualID",
		inPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
		pkgEqualCall: &pkgEqualCall{
			P1: testdata.P1,
			P2: testdata.P2,
			HE: &model.PkgEqualInputSpec{
				Justification: "test justification two",
			},
		},
		queryPkgEqualID: true,
		usingOnly:       []model.Edge{model.EdgePkgEqualPackage},
		want:            []model.Node{testdata.P1out, testdata.P2out},
	}, {
		name:  "pointOfContact - artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A1},
		pointOfContactCall: &pointOfContactCall{
			Sub: model.PackageSourceOrArtifactInput{
				Artifact: testdata.A1,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			POC: &model.PointOfContactInputSpec{
				Justification: "test justification",
			},
		},
		queryArtifactID: true,
		want: []model.Node{&model.PointOfContact{
			Subject:       testdata.A1out,
			Justification: "test justification",
		}},
	}, {
		name:  "pointOfContact - PkgName",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		pointOfContactCall: &pointOfContactCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			POC: &model.PointOfContactInputSpec{
				Justification: "test justification",
			},
		},
		queryPkgNameID: true,
		want: []model.Node{
			testdata.P2out,
			testdata.P1out,
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{},
				}}},
			&model.PointOfContact{
				Subject:       testdata.P2outName,
				Justification: "test justification",
			}},
	}, {
		name:  "pointOfContact - srcName",
		inSrc: []*model.SourceInputSpec{testdata.S1},
		pointOfContactCall: &pointOfContactCall{
			Sub: model.PackageSourceOrArtifactInput{
				Source: testdata.S1,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			POC: &model.PointOfContactInputSpec{
				Justification: "test justification",
			},
		},
		querySrcNameID: true,
		want: []model.Node{
			&model.Source{
				Type: "git",
				Namespaces: []*model.SourceNamespace{{
					Namespace: "github.com/jeff",
					Names:     []*model.SourceName{},
				}},
			},
			&model.PointOfContact{
				Subject:       testdata.S1out,
				Justification: "test justification",
			}},
	}, {
		name:  "pointOfContact - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		pointOfContactCall: &pointOfContactCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			POC: &model.PointOfContactInputSpec{
				Justification: "test justification",
			},
		},
		queryPkgVersionID: true,
		want: []model.Node{
			&model.Package{
				Type: "pypi",
				Namespaces: []*model.PackageNamespace{{
					Names: []*model.PackageName{{
						Name:     "tensorflow",
						Versions: []*model.PackageVersion{},
					}},
				}},
			},
			&model.PointOfContact{
				Subject:       testdata.P2out,
				Justification: "test justification",
			}},
	}, {
		name:  "pointOfContact - pointOfContactID - artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A1},
		pointOfContactCall: &pointOfContactCall{
			Sub: model.PackageSourceOrArtifactInput{
				Artifact: testdata.A1,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			POC: &model.PointOfContactInputSpec{
				Justification: "test justification",
			},
		},
		queryPointOfContactID: true,
		usingOnly:             []model.Edge{model.EdgePointOfContactArtifact},
		want:                  []model.Node{testdata.A1out},
	}, {
		name:  "pointOfContact - pointOfContactID - PkgName",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		pointOfContactCall: &pointOfContactCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			POC: &model.PointOfContactInputSpec{
				Justification: "test justification",
			},
		},
		queryPointOfContactID: true,
		usingOnly:             []model.Edge{model.EdgePointOfContactPackage},
		want:                  []model.Node{testdata.P2outName},
	}, {
		name:  "pointOfContact - pointOfContactID - srcName",
		inSrc: []*model.SourceInputSpec{testdata.S1},
		pointOfContactCall: &pointOfContactCall{
			Sub: model.PackageSourceOrArtifactInput{
				Source: testdata.S1,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			POC: &model.PointOfContactInputSpec{
				Justification: "test justification",
			},
		},
		queryPointOfContactID: true,
		usingOnly:             []model.Edge{model.EdgePointOfContactSource},
		want:                  []model.Node{testdata.S1out},
	}, {
		name:  "pointOfContact - pointOfContactID - pkgVersion",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		pointOfContactCall: &pointOfContactCall{
			Sub: model.PackageSourceOrArtifactInput{
				Package: testdata.P2,
			},
			Match: &model.MatchFlags{
				Pkg: model.PkgMatchTypeSpecificVersion,
			},
			POC: &model.PointOfContactInputSpec{
				Justification: "test justification",
			},
		},
		queryPointOfContactID: true,
		usingOnly:             []model.Edge{model.EdgePointOfContactPackage},
		want:                  []model.Node{testdata.P2out},
	}, {
		name:   "vulnEqual - vulnID",
		inVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.G1},
		vulnEqualCall: &vulnEqualCall{
			Vuln:      testdata.O1,
			OtherVuln: testdata.G1,
			In: &model.VulnEqualInputSpec{
				Justification: "test justification",
			},
		},
		queryVulnID: true,
		want: []model.Node{
			&model.Vulnerability{
				Type:             "osv",
				VulnerabilityIDs: []*model.VulnerabilityID{},
			},
			&model.VulnEqual{
				Vulnerabilities: []*model.Vulnerability{
					{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
				},
				Justification: "test justification",
			}},
	}, {
		name:   "vulnEqual - second vulnID",
		inVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.G1},
		vulnEqualCall: &vulnEqualCall{
			Vuln:      testdata.O1,
			OtherVuln: testdata.G1,
			In: &model.VulnEqualInputSpec{
				Justification: "test justification",
			},
		},
		queryEqualVulnID: true,
		want: []model.Node{
			&model.Vulnerability{
				Type:             "ghsa",
				VulnerabilityIDs: []*model.VulnerabilityID{},
			},
			&model.VulnEqual{
				Vulnerabilities: []*model.Vulnerability{
					{
						Type:             "osv",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
					},
					{
						Type:             "ghsa",
						VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
					},
				},
				Justification: "test justification",
			}},
	}, {
		name:   "vulnEqual - vulnEqualID",
		inVuln: []*model.VulnerabilityInputSpec{testdata.O1, testdata.G1},
		vulnEqualCall: &vulnEqualCall{
			Vuln:      testdata.O1,
			OtherVuln: testdata.G1,
			In: &model.VulnEqualInputSpec{
				Justification: "test justification",
			},
		},
		queryVulnEqualID: true,
		usingOnly:        []model.Edge{model.EdgeVulnEqualVulnerability},
		want: []model.Node{&model.Vulnerability{
			Type:             "osv",
			VulnerabilityIDs: []*model.VulnerabilityID{testdata.O1out},
		},
			&model.Vulnerability{
				Type:             "ghsa",
				VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
			}},
	}, {
		name:   "vulnMetadata - vulnID",
		inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
		vulnMetadataCall: &vulnMetadataCall{
			Vuln: testdata.G1,
			VulnMetadata: &model.VulnerabilityMetadataInputSpec{
				ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
				ScoreValue: 8.9,
				Timestamp:  testdata.T1,
				Collector:  "test collector",
				Origin:     "test origin",
			},
		},
		queryVulnID: true,
		want: []model.Node{
			&model.Vulnerability{
				Type:             "ghsa",
				VulnerabilityIDs: []*model.VulnerabilityID{},
			},
			&model.VulnerabilityMetadata{
				Vulnerability: &model.Vulnerability{
					Type:             "ghsa",
					VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
				},
				ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
				ScoreValue: 8.9,
				Timestamp:  testdata.T1,
				Collector:  "test collector",
				Origin:     "test origin",
			}},
	}, {
		name:   "vulnMetadata - vulnMetadataID",
		inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
		vulnMetadataCall: &vulnMetadataCall{
			Vuln: testdata.G1,
			VulnMetadata: &model.VulnerabilityMetadataInputSpec{
				ScoreType:  model.VulnerabilityScoreTypeCVSSv2,
				ScoreValue: 8.9,
				Timestamp:  testdata.T1,
				Collector:  "test collector",
				Origin:     "test origin",
			},
		},
		queryVulnMetadataID: true,
		usingOnly:           []model.Edge{model.EdgeVulnMetadataVulnerability},
		want: []model.Node{&model.Vulnerability{
			Type:             "ghsa",
			VulnerabilityIDs: []*model.VulnerabilityID{testdata.G1out},
		}},
	}}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nodeID string
			for _, p := range tt.inPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range tt.inSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range tt.inArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, bld := range tt.inBld {
				if _, err := b.IngestBuilder(ctx, bld); err != nil {
					t.Fatalf("Could not ingest builder: %v", err)
				}
			}
			for _, a := range tt.inLic {
				if _, err := b.IngestLicense(ctx, a); err != nil {
					t.Fatalf("Could not ingest license: %v", err)
				}
			}
			for _, g := range tt.inVuln {
				if _, err := b.IngestVulnerability(ctx, *g); err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				}
			}
			if tt.pkgInput != nil {
				ingestedPkg, err := b.IngestPackage(ctx, *tt.pkgInput)
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if tt.queryPkgTypeID {
					nodeID = ingestedPkg.ID
					tt.usingOnly = []model.Edge{}
				}
				if tt.queryPkgNamespaceID {
					nodeID = ingestedPkg.Namespaces[0].ID
					tt.usingOnly = []model.Edge{}
				}
				if tt.queryPkgNameID {
					nodeID = ingestedPkg.Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{}
				}
				if tt.queryPkgVersionID {
					nodeID = ingestedPkg.Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{}
				}
			}
			if tt.srcInput != nil {
				ingestedSrc, err := b.IngestSource(ctx, *tt.srcInput)
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestSource() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if tt.querySrcTypeID {
					nodeID = ingestedSrc.ID
					tt.usingOnly = []model.Edge{}
				}
				if tt.querySrcNamespaceID {
					nodeID = ingestedSrc.Namespaces[0].ID
					tt.usingOnly = []model.Edge{}
				}
				if tt.querySrcNameID {
					nodeID = ingestedSrc.Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{}
				}
			}
			if tt.vulnInput != nil {
				ingestVuln, err := b.IngestVulnerability(ctx, *tt.vulnInput)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.want, err)
				}
				if tt.queryVulnTypeID {
					nodeID = ingestVuln.ID
					tt.usingOnly = []model.Edge{}
				}
				if tt.queryVulnID {
					nodeID = ingestVuln.VulnerabilityIDs[0].ID
					tt.usingOnly = []model.Edge{}
				}
			}
			if tt.licenseInput != nil {
				ingestedLicense, err := b.IngestLicense(ctx, tt.licenseInput)
				if (err != nil) != tt.wantErr {
					t.Errorf("demoClient.IngestLicense() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedLicense.ID
			}
			if tt.certifyBadCall != nil {
				found, err := b.IngestCertifyBad(ctx, tt.certifyBadCall.Sub, tt.certifyBadCall.Match, *tt.certifyBadCall.CB)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryArtifactID {
					nodeID = found.Subject.(*model.Artifact).ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactCertifyBad}
				}
				if tt.queryPkgNameID {
					nodeID = found.Subject.(*model.Package).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyBad, model.EdgePackageNamePackageNamespace, model.EdgePackageNamePackageVersion}
				}
				if tt.queryPkgVersionID {
					nodeID = found.Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyBad, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found.Subject.(*model.Source).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceCertifyBad, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryCertifyBadID {
					nodeID = found.ID
					tt.usingOnly = []model.Edge{model.EdgeCertifyBadPackage, model.EdgeCertifyBadArtifact, model.EdgeCertifyBadSource}
				}
			}
			if tt.certifyGoodCall != nil {
				found, err := b.IngestCertifyGood(ctx, tt.certifyGoodCall.Sub, tt.certifyGoodCall.Match, *tt.certifyGoodCall.CG)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryArtifactID {
					nodeID = found.Subject.(*model.Artifact).ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactCertifyGood}
				}
				if tt.queryPkgNameID {
					nodeID = found.Subject.(*model.Package).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyGood, model.EdgePackageNamePackageNamespace, model.EdgePackageNamePackageVersion}
				}
				if tt.queryPkgVersionID {
					nodeID = found.Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyGood, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found.Subject.(*model.Source).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceCertifyGood, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryCertifyGoodID {
					nodeID = found.ID
					tt.usingOnly = []model.Edge{model.EdgeCertifyGoodPackage, model.EdgeCertifyGoodArtifact, model.EdgeCertifyGoodSource}
				}
			}
			if tt.certifyLegalCall != nil {
				found, err := b.IngestCertifyLegal(ctx, tt.certifyLegalCall.PkgSrc, tt.certifyLegalCall.Dec, tt.certifyLegalCall.Dis, tt.certifyLegalCall.Legal)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryPkgVersionID {
					nodeID = found.Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyLegal, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found.Subject.(*model.Source).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceCertifyLegal, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryDeclaredLicenseID {
					nodeID = found.DeclaredLicenses[0].ID
					tt.usingOnly = []model.Edge{model.EdgeLicenseCertifyLegal}
				}
				if tt.queryDiscoveredLicenseID {
					nodeID = found.DiscoveredLicenses[0].ID
					tt.usingOnly = []model.Edge{model.EdgeLicenseCertifyLegal}
				}
				if tt.queryCertifyLegalID {
					nodeID = found.ID
				}
			}
			if tt.scorecardCall != nil {
				found, err := b.IngestScorecard(ctx, *tt.scorecardCall.Src, *tt.scorecardCall.SC)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.querySrcNameID {
					nodeID = found.Source.Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceCertifyScorecard, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryScorecardID {
					nodeID = found.ID
				}
			}
			if tt.vexCall != nil {
				found, err := b.IngestVEXStatement(ctx, tt.vexCall.Sub, *tt.vexCall.Vuln, *tt.vexCall.In)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryArtifactID {
					nodeID = found.Subject.(*model.Artifact).ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactCertifyVexStatement}
				}
				if tt.queryPkgVersionID {
					nodeID = found.Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyVexStatement, model.EdgePackageVersionPackageName}
				}
				if tt.queryVulnID {
					nodeID = found.Vulnerability.VulnerabilityIDs[0].ID
					tt.usingOnly = []model.Edge{model.EdgeVulnerabilityCertifyVexStatement, model.EdgeVulnerabilityIDVulnerabilityType}
				}
				if tt.queryCertifyVexID {
					nodeID = found.ID
				}
			}
			if tt.certifyVulnCall != nil {
				found, err := b.IngestCertifyVuln(ctx, *tt.certifyVulnCall.Pkg, *tt.certifyVulnCall.Vuln, *tt.certifyVulnCall.CertifyVuln)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryPkgVersionID {
					nodeID = found.Package.Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyVuln, model.EdgePackageVersionPackageName}
				}
				if tt.queryVulnID {
					nodeID = found.Vulnerability.VulnerabilityIDs[0].ID
					tt.usingOnly = []model.Edge{model.EdgeVulnerabilityCertifyVuln, model.EdgeVulnerabilityIDVulnerabilityType}
				}
				if tt.queryCertifyVulnID {
					nodeID = found.ID
				}
			}
			if tt.hashEqualCall != nil {
				found, err := b.IngestHashEqual(ctx, *tt.hashEqualCall.A1, *tt.hashEqualCall.A2, *tt.hashEqualCall.HE)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryArtifactID {
					nodeID = found.Artifacts[0].ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactHashEqual}
				}
				if tt.queryEqualArtifactID {
					nodeID = found.Artifacts[1].ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactHashEqual}
				}
				if tt.queryHashEqualID {
					nodeID = found.ID
					tt.usingOnly = []model.Edge{model.EdgeHashEqualArtifact}
				}
			}
			if tt.hasMetadataCall != nil {
				found, err := b.IngestHasMetadata(ctx, tt.hasMetadataCall.Sub, tt.hasMetadataCall.Match, *tt.hasMetadataCall.HM)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryArtifactID {
					nodeID = found.Subject.(*model.Artifact).ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactHasMetadata}
				}
				if tt.queryPkgNameID {
					nodeID = found.Subject.(*model.Package).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageHasMetadata, model.EdgePackageNamePackageNamespace, model.EdgePackageNamePackageVersion}
				}
				if tt.queryPkgVersionID {
					nodeID = found.Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageHasMetadata, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found.Subject.(*model.Source).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceHasMetadata, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryHasMetadataID {
					nodeID = found.ID
				}
			}
			if tt.hasSBOMCall != nil {
				// TODO (knrc) handle includes
				found, err := b.IngestHasSbom(ctx, tt.hasSBOMCall.Sub, *tt.hasSBOMCall.HS, model.HasSBOMIncludesInputSpec{})
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryArtifactID {
					nodeID = found.Subject.(*model.Artifact).ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactHasSbom}
				}
				if tt.queryPkgVersionID {
					nodeID = found.Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageHasSbom, model.EdgePackageVersionPackageName}
				}
				if tt.queryHasSbomID {
					nodeID = found.ID
				}
			}
			if tt.hasSlsaCall != nil {
				found, err := b.IngestSLSA(ctx, *tt.hasSlsaCall.Sub, tt.hasSlsaCall.BF, *tt.hasSlsaCall.BB, *tt.hasSlsaCall.SLSA)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryBuilderID {
					nodeID = found.Slsa.BuiltBy.ID
					tt.usingOnly = []model.Edge{model.EdgeBuilderHasSlsa}
				}
				if tt.queryArtifactID {
					nodeID = found.Subject.ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactHasSlsa}
				}
				if tt.queryHasSlsaID {
					nodeID = found.ID
				}
			}
			if tt.hasSourceAtCall != nil {
				found, err := b.IngestHasSourceAt(ctx, *tt.hasSourceAtCall.Pkg, *tt.hasSourceAtCall.Match, *tt.hasSourceAtCall.Src, *tt.hasSourceAtCall.HSA)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryPkgNameID {
					nodeID = found.Package.Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageHasSourceAt, model.EdgePackageNamePackageNamespace, model.EdgePackageNamePackageVersion}
				}
				if tt.queryPkgVersionID {
					nodeID = found.Package.Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageHasSourceAt, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found.Source.Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceHasSourceAt, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryHasSourceAtID {
					nodeID = found.ID
				}
			}
			if tt.isDepCall != nil {
				found, err := b.IngestDependency(ctx, *tt.isDepCall.P1, *tt.isDepCall.P2, tt.isDepCall.MF, *tt.isDepCall.ID)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryPkgNameID {
					nodeID = found.DependencyPackage.Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageIsDependency, model.EdgePackageNamePackageNamespace, model.EdgePackageNamePackageVersion}
				}
				if tt.queryPkgVersionID {
					nodeID = found.DependencyPackage.Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageIsDependency, model.EdgePackageVersionPackageName}
				}
				if tt.queryIsDependencyID {
					nodeID = found.ID
				}
			}
			if tt.isOcurCall != nil {
				found, err := b.IngestOccurrence(ctx, tt.isOcurCall.PkgSrc, *tt.isOcurCall.Artifact, *tt.isOcurCall.Occurrence)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryArtifactID {
					nodeID = found.Artifact.ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactIsOccurrence}
				}
				if tt.queryPkgVersionID {
					nodeID = found.Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageIsOccurrence, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found.Subject.(*model.Source).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceIsOccurrence, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryIsOccurrenceID {
					nodeID = found.ID
				}
			}
			if tt.pkgEqualCall != nil {
				found, err := b.IngestPkgEqual(ctx, *tt.pkgEqualCall.P1, *tt.pkgEqualCall.P2, *tt.pkgEqualCall.HE)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryPkgVersionID {
					nodeID = found.Packages[0].Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackagePkgEqual, model.EdgePackageVersionPackageName}
				}
				if tt.queryEqualPkgID {
					nodeID = found.Packages[1].Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackagePkgEqual, model.EdgePackageVersionPackageName}
				}
				if tt.queryPkgEqualID {
					nodeID = found.ID
				}
			}
			if tt.pointOfContactCall != nil {
				found, err := b.IngestPointOfContact(ctx, tt.pointOfContactCall.Sub, tt.pointOfContactCall.Match, *tt.pointOfContactCall.POC)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryArtifactID {
					nodeID = found.Subject.(*model.Artifact).ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactPointOfContact}
				}
				if tt.queryPkgNameID {
					nodeID = found.Subject.(*model.Package).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackagePointOfContact, model.EdgePackageNamePackageNamespace, model.EdgePackageNamePackageVersion}
				}
				if tt.queryPkgVersionID {
					nodeID = found.Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackagePointOfContact, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found.Subject.(*model.Source).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourcePointOfContact, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryPointOfContactID {
					nodeID = found.ID
				}
			}
			if tt.vulnEqualCall != nil {
				found, err := b.IngestVulnEqual(ctx, *tt.vulnEqualCall.Vuln, *tt.vulnEqualCall.OtherVuln, *tt.vulnEqualCall.In)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryVulnID {
					nodeID = found.Vulnerabilities[0].VulnerabilityIDs[0].ID
					tt.usingOnly = []model.Edge{model.EdgeVulnerabilityVulnEqual, model.EdgeVulnerabilityIDVulnerabilityType}
				}
				if tt.queryEqualVulnID {
					nodeID = found.Vulnerabilities[1].VulnerabilityIDs[0].ID
					tt.usingOnly = []model.Edge{model.EdgeVulnerabilityVulnEqual, model.EdgeVulnerabilityIDVulnerabilityType}
				}
				if tt.queryVulnEqualID {
					nodeID = found.ID
				}
			}
			if tt.vulnMetadataCall != nil {
				ingestedVuln, err := b.IngestVulnerability(ctx, *tt.inVuln[0])
				if err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				}

				vulnMetadataID, err := b.IngestVulnerabilityMetadata(ctx, *tt.vulnMetadataCall.Vuln, *tt.vulnMetadataCall.VulnMetadata)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryVulnID {
					nodeID = ingestedVuln.VulnerabilityIDs[0].ID
					tt.usingOnly = []model.Edge{model.EdgeVulnMetadataVulnerability, model.EdgeVulnerabilityIDVulnerabilityType}
				}
				if tt.queryVulnMetadataID {
					nodeID = vulnMetadataID
				}
			}
			got, err := b.Neighbors(ctx, nodeID, tt.usingOnly)
			if (err != nil) != tt.wantErr {
				t.Errorf("neighbors query error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
