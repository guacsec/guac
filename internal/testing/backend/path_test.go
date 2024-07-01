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
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestPath(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
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
		wantPathErr            bool
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
			name:   "certifyVuln - edges provided",
			inVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			inPkg:  []*model.PkgInputSpec{testdata.P2},
			edges:  []model.Edge{model.EdgePackageCertifyVuln, model.EdgeCertifyVulnVulnerability},
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
			edges:  []model.Edge{model.EdgePackageCertifyVuln, model.EdgeCertifyVulnVulnerability},
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var startID string
			var stopID string
			if tt.certifyVulnTwoPkgsCall != nil {
				var nonVulnPkgID string
				for _, p := range tt.inPkg {
					pkg, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: p})
					if err != nil {
						t.Fatalf("Could not ingest package: %v", err)
					}
					nonVulnPkgID = pkg.PackageVersionID
				}
				cvID, err := b.IngestCertifyVuln(ctx, model.IDorPkgInput{PackageInput: tt.certifyVulnTwoPkgsCall.Pkg}, model.IDorVulnerabilityInput{VulnerabilityInput: tt.certifyVulnTwoPkgsCall.Vuln}, *tt.certifyVulnTwoPkgsCall.CertifyVuln)
				if err != nil {
					t.Fatalf("did not get expected ingest error, got: %v", err)
				}
				if err != nil {
					return
				}
				startID = cvID
				stopID = nonVulnPkgID
			}
			if tt.certifyVulnCall != nil {
				for _, p := range tt.inPkg {
					if pkgIDs, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: p}); err != nil {
						t.Fatalf("Could not ingest package: %v", err)
					} else {
						startID = pkgIDs.PackageVersionID
					}
				}
				for _, g := range tt.inVuln {
					if vulnIDs, err := b.IngestVulnerability(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: g}); err != nil {
						t.Fatalf("Could not ingest vulnerability: %a", err)
					} else {
						stopID = vulnIDs.VulnerabilityNodeID
					}
				}
				_, err := b.IngestCertifyVuln(ctx, model.IDorPkgInput{PackageInput: tt.certifyVulnCall.Pkg}, model.IDorVulnerabilityInput{VulnerabilityInput: tt.certifyVulnCall.Vuln}, *tt.certifyVulnCall.CertifyVuln)
				if err != nil {
					t.Fatalf("did not get expected ingest error, got: %v", err)
				}
				if err != nil {
					return
				}
			}
			if tt.isDepCall != nil {
				for _, p := range tt.inPkg {
					if _, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: p}); err != nil {
						t.Fatalf("Could not ingest package: %v", err)
					}
				}
				dID, err := b.IngestDependency(ctx, model.IDorPkgInput{PackageInput: tt.isDepCall.P1}, model.IDorPkgInput{PackageInput: tt.isDepCall.P2}, tt.isDepCall.MF, *tt.isDepCall.ID)
				if err != nil {
					t.Fatalf("did not get expected ingest error, got: %v", err)
				}
				if err != nil {
					return
				}
				found, err := b.IsDependency(ctx, &model.IsDependencySpec{ID: &dID})
				if err != nil {
					t.Fatal()
				}
				startID = found[0].Package.Namespaces[0].Names[0].Versions[0].ID
				stopID = found[0].DependencyPackage.Namespaces[0].Names[0].ID
			}
			got, err := b.Path(ctx, startID, stopID, 5, tt.edges)
			if (err != nil) != tt.wantPathErr {
				t.Errorf("node query error = %v, wantErr %v", err, tt.wantPathErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNodes(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
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
		Dec    []*model.IDorLicenseInput
		Dis    []*model.IDorLicenseInput
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
		BF   []*model.IDorArtifactInput
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
		pkgVersionInput    *model.PkgInputSpec
		pkgNameInput       *model.PkgInputSpec
		pkgNamespaceInput  *model.PkgInputSpec
		pkgTypeInput       *model.PkgInputSpec
		artifactInput      *model.ArtifactInputSpec
		builderInput       *model.BuilderInputSpec
		srcNameInput       *model.SourceInputSpec
		srcNamespaceInput  *model.SourceInputSpec
		srcTypeInput       *model.SourceInputSpec
		vulnInput          *model.VulnerabilityInputSpec
		vulnTypeInput      *model.VulnerabilityInputSpec
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
		name:            "package version",
		pkgVersionInput: testdata.P1,
		want:            []model.Node{testdata.P1out},
		wantErr:         false,
	}, {
		name:         "package name",
		pkgNameInput: testdata.P1,
		want: []model.Node{&model.Package{
			Type: "pypi",
			Namespaces: []*model.PackageNamespace{{
				Names: []*model.PackageName{{
					Name:     "tensorflow",
					Versions: []*model.PackageVersion{},
				}},
			}},
		}},
		wantErr: false,
	}, {
		name:              "package namespace",
		pkgNamespaceInput: testdata.P1,
		want: []model.Node{&model.Package{
			Type: "pypi",
			Namespaces: []*model.PackageNamespace{{
				Names: []*model.PackageName{},
			}},
		}},
		wantErr: false,
	}, {
		name:         "package type",
		pkgTypeInput: testdata.P1,
		want: []model.Node{&model.Package{
			Type:       "pypi",
			Namespaces: []*model.PackageNamespace{},
		}},
		wantErr: false,
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
		name:         "source name",
		srcNameInput: testdata.S1,
		want:         []model.Node{testdata.S1out},
		wantErr:      false,
	}, {
		name:              "source namespace",
		srcNamespaceInput: testdata.S1,
		want: []model.Node{&model.Source{
			Type: "git",
			Namespaces: []*model.SourceNamespace{{
				Namespace: "github.com/jeff",
				Names:     []*model.SourceName{},
			}},
		}},
		wantErr: false,
	}, {
		name:         "source type",
		srcTypeInput: testdata.S1,
		want: []model.Node{&model.Source{
			Type:       "git",
			Namespaces: []*model.SourceNamespace{},
		}},
		wantErr: false,
	}, {
		name:      "vulnerability",
		vulnInput: testdata.C1,
		want: []model.Node{&model.Vulnerability{
			Type:             "cve",
			VulnerabilityIDs: []*model.VulnerabilityID{testdata.C1out},
		}},
	}, {
		name:          "vulnerability type",
		vulnTypeInput: testdata.C1,
		want: []model.Node{&model.Vulnerability{
			Type:             "cve",
			VulnerabilityIDs: []*model.VulnerabilityID{},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
			},
			Dec: []*model.IDorLicenseInput{{LicenseInput: testdata.L1}},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
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
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
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
			BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
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
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nodeID string
			for _, p := range tt.inPkg {
				if _, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: p}); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range tt.inSrc {
				if _, err := b.IngestSource(ctx, model.IDorSourceInput{SourceInput: s}); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range tt.inArt {
				if _, err := b.IngestArtifact(ctx, &model.IDorArtifactInput{ArtifactInput: a}); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, bld := range tt.inBld {
				if _, err := b.IngestBuilder(ctx, &model.IDorBuilderInput{BuilderInput: bld}); err != nil {
					t.Fatalf("Could not ingest builder: %v", err)
				}
			}
			for _, a := range tt.inLic {
				if _, err := b.IngestLicense(ctx, &model.IDorLicenseInput{LicenseInput: a}); err != nil {
					t.Fatalf("Could not ingest license: %v", err)
				}
			}
			for _, g := range tt.inVuln {
				if _, err := b.IngestVulnerability(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: g}); err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				}
			}
			if tt.pkgVersionInput != nil {
				ingestedPkg, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: tt.pkgVersionInput})
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedPkg.PackageVersionID
			}
			if tt.pkgNameInput != nil {
				ingestedPkg, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: tt.pkgNameInput})
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedPkg.PackageNameID
			}
			if tt.pkgNamespaceInput != nil {
				ingestedPkg, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: tt.pkgNamespaceInput})
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedPkg.PackageNamespaceID
			}
			if tt.pkgTypeInput != nil {
				ingestedPkg, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: tt.pkgTypeInput})
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedPkg.PackageTypeID
			}
			if tt.artifactInput != nil {
				ingestedArtID, err := b.IngestArtifact(ctx, &model.IDorArtifactInput{ArtifactInput: tt.artifactInput})
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestArtifact() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedArtID
			}
			if tt.builderInput != nil {
				ingestedBuilderID, err := b.IngestBuilder(ctx, &model.IDorBuilderInput{BuilderInput: tt.builderInput})
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestBuilder() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedBuilderID
			}
			if tt.srcNameInput != nil {
				ingestedSrc, err := b.IngestSource(ctx, model.IDorSourceInput{SourceInput: tt.srcNameInput})
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestSource() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedSrc.SourceNameID
			}
			if tt.srcNamespaceInput != nil {
				ingestedSrc, err := b.IngestSource(ctx, model.IDorSourceInput{SourceInput: tt.srcNamespaceInput})
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestSource() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedSrc.SourceNamespaceID
			}
			if tt.srcTypeInput != nil {
				ingestedSrc, err := b.IngestSource(ctx, model.IDorSourceInput{SourceInput: tt.srcTypeInput})
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestSource() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedSrc.SourceTypeID
			}
			if tt.vulnInput != nil {
				ingestVuln, err := b.IngestVulnerability(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: tt.vulnInput})
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.want, err)
				}
				nodeID = ingestVuln.VulnerabilityNodeID
			}
			if tt.vulnTypeInput != nil {
				ingestVuln, err := b.IngestVulnerability(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: tt.vulnTypeInput})
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.want, err)
				}
				nodeID = ingestVuln.VulnerabilityTypeID
			}
			if tt.licenseInput != nil {
				ingestedLicenseID, err := b.IngestLicense(ctx, &model.IDorLicenseInput{LicenseInput: tt.licenseInput})
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestLicense() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedLicenseID
			}
			if tt.certifyBadCall != nil {
				cbID, err := b.IngestCertifyBad(ctx, tt.certifyBadCall.Sub, tt.certifyBadCall.Match, *tt.certifyBadCall.CB)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = cbID
			}
			if tt.certifyGoodCall != nil {
				cgID, err := b.IngestCertifyGood(ctx, tt.certifyGoodCall.Sub, tt.certifyGoodCall.Match, *tt.certifyGoodCall.CG)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = cgID
			}
			if tt.certifyLegalCall != nil {
				cLID, err := b.IngestCertifyLegal(ctx, tt.certifyLegalCall.PkgSrc, tt.certifyLegalCall.Dec, tt.certifyLegalCall.Dis, tt.certifyLegalCall.Legal)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = cLID
			}
			if tt.scorecardCall != nil {
				sID, err := b.IngestScorecard(ctx, model.IDorSourceInput{SourceInput: tt.scorecardCall.Src}, *tt.scorecardCall.SC)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = sID
			}
			if tt.vexCall != nil {
				vID, err := b.IngestVEXStatement(ctx, tt.vexCall.Sub, model.IDorVulnerabilityInput{VulnerabilityInput: tt.vexCall.Vuln}, *tt.vexCall.In)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = vID
			}
			if tt.certifyVulnCall != nil {
				cvID, err := b.IngestCertifyVuln(ctx, model.IDorPkgInput{PackageInput: tt.certifyVulnCall.Pkg}, model.IDorVulnerabilityInput{VulnerabilityInput: tt.certifyVulnCall.Vuln}, *tt.certifyVulnCall.CertifyVuln)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = cvID
			}
			if tt.hashEqualCall != nil {
				heID, err := b.IngestHashEqual(ctx, model.IDorArtifactInput{ArtifactInput: tt.hashEqualCall.A1}, model.IDorArtifactInput{ArtifactInput: tt.hashEqualCall.A2}, *tt.hashEqualCall.HE)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = heID
			}
			if tt.hasMetadataCall != nil {
				hmID, err := b.IngestHasMetadata(ctx, tt.hasMetadataCall.Sub, tt.hasMetadataCall.Match, *tt.hasMetadataCall.HM)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = hmID
			}
			if tt.hasSBOMCall != nil {
				// TODO (knrc) handle includes
				hsID, err := b.IngestHasSbom(ctx, tt.hasSBOMCall.Sub, *tt.hasSBOMCall.HS, model.HasSBOMIncludesInputSpec{})
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = hsID
			}
			if tt.hasSlsaCall != nil {
				sID, err := b.IngestSLSA(ctx, model.IDorArtifactInput{ArtifactInput: tt.hasSlsaCall.Sub}, tt.hasSlsaCall.BF, model.IDorBuilderInput{BuilderInput: tt.hasSlsaCall.BB}, *tt.hasSlsaCall.SLSA)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = sID
			}
			if tt.hasSourceAtCall != nil {
				hsID, err := b.IngestHasSourceAt(ctx, model.IDorPkgInput{PackageInput: tt.hasSourceAtCall.Pkg}, *tt.hasSourceAtCall.Match, model.IDorSourceInput{SourceInput: tt.hasSourceAtCall.Src}, *tt.hasSourceAtCall.HSA)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = hsID
			}
			if tt.isDepCall != nil {
				dID, err := b.IngestDependency(ctx, model.IDorPkgInput{PackageInput: tt.isDepCall.P1}, model.IDorPkgInput{PackageInput: tt.isDepCall.P2}, tt.isDepCall.MF, *tt.isDepCall.ID)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = dID
			}
			if tt.isOcurCall != nil {
				oID, err := b.IngestOccurrence(ctx, tt.isOcurCall.PkgSrc, model.IDorArtifactInput{ArtifactInput: tt.isOcurCall.Artifact}, *tt.isOcurCall.Occurrence)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = oID
			}
			if tt.pkgEqualCall != nil {
				peID, err := b.IngestPkgEqual(ctx, model.IDorPkgInput{PackageInput: tt.pkgEqualCall.P1}, model.IDorPkgInput{PackageInput: tt.pkgEqualCall.P2}, *tt.pkgEqualCall.HE)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = peID
			}
			if tt.pointOfContactCall != nil {
				pocID, err := b.IngestPointOfContact(ctx, tt.pointOfContactCall.Sub, tt.pointOfContactCall.Match, *tt.pointOfContactCall.POC)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = pocID
			}
			if tt.vulnEqualCall != nil {
				veID, err := b.IngestVulnEqual(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: tt.vulnEqualCall.Vuln}, model.IDorVulnerabilityInput{VulnerabilityInput: tt.vulnEqualCall.OtherVuln}, *tt.vulnEqualCall.In)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = veID
			}
			if tt.vulnMetadataCall != nil {
				vmID, err := b.IngestVulnerabilityMetadata(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: tt.vulnMetadataCall.Vuln}, *tt.vulnMetadataCall.VulnMetadata)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				nodeID = vmID
			}
			got, err := b.Nodes(ctx, []string{nodeID})
			if (err != nil) != tt.wantErr {
				t.Errorf("node query error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNeighbors(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
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
		Dec    []*model.IDorLicenseInput
		Dis    []*model.IDorLicenseInput
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
		Sub    model.PackageOrArtifactInput
		HS     *model.HasSBOMInputSpec
		PkgArt *model.PackageOrArtifactInputs
		InSrc  []*model.SourceInputSpec
		IsDeps []testDependency
		IsOccs []testOccurrence
	}
	type hasSlsaCall struct {
		Sub  *model.ArtifactInputSpec
		BF   []*model.IDorArtifactInput
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
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
			testdata.P1out,
			testdata.P2out,
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
				Source: &model.IDorSourceInput{SourceInput: testdata.S1},
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
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
				Source: &model.IDorSourceInput{SourceInput: testdata.S1},
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
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
			testdata.P1out,
			testdata.P2out,
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
				Source: &model.IDorSourceInput{SourceInput: testdata.S1},
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
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
				Source: &model.IDorSourceInput{SourceInput: testdata.S1},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
			},
			Dec: []*model.IDorLicenseInput{{LicenseInput: testdata.L1}},
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
				Source: &model.IDorSourceInput{SourceInput: testdata.S1},
			},
			Dec: []*model.IDorLicenseInput{{LicenseInput: testdata.L1}},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
			},
			Dec: []*model.IDorLicenseInput{{LicenseInput: testdata.L2}},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
			},
			Dis: []*model.IDorLicenseInput{{LicenseInput: testdata.L3}},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
			},
			Dec: []*model.IDorLicenseInput{{LicenseInput: testdata.L1}},
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
				Source: &model.IDorSourceInput{SourceInput: testdata.S1},
			},
			Dec: []*model.IDorLicenseInput{{LicenseInput: testdata.L1}},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
			},
			Dec: []*model.IDorLicenseInput{{LicenseInput: testdata.L2}},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
			},
			Dis: []*model.IDorLicenseInput{{LicenseInput: testdata.L3}},
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
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
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
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
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
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
			testdata.P1out,
			testdata.P2out,
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
				Source: &model.IDorSourceInput{SourceInput: testdata.S1},
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
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
				Source: &model.IDorSourceInput{SourceInput: testdata.S1},
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
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
		name:  "hasSBOM - Includes",
		inPkg: []*model.PkgInputSpec{testdata.P2},
		hasSBOMCall: &hasSBOMCall{
			Sub: model.PackageOrArtifactInput{
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
			},
			HS: &model.HasSBOMInputSpec{
				DownloadLocation: "location two",
			},
			PkgArt: includedPackageArtifacts,
			InSrc:  includedSources,
			IsDeps: includedTestDependencies,
			IsOccs: includedTestOccurrences,
		},
		queryHasSbomID: true,
		want: []model.Node{
			testdata.P2out,
			includedTestExpectedArtifact1,
			includedTestExpectedArtifact2,
			includedTestExpectedPackage1,
			includedTestExpectedPackage2,
			includedTestExpectedPackage3,
			&model.IsDependency{
				Package:           includedTestExpectedPackage1,
				DependencyPackage: includedTestExpectedPackage2,
				VersionRange:      "dep1_range",
				DependencyType:    model.DependencyTypeDirect,
				Justification:     "dep1_justification",
				Origin:            "dep1_origin",
				Collector:         "dep1_collector",
			},
			&model.IsDependency{
				Package:           includedTestExpectedPackage1,
				DependencyPackage: includedTestExpectedPackage3,
				VersionRange:      "dep2_range",
				DependencyType:    model.DependencyTypeIndirect,
				Justification:     "dep2_justification",
				Origin:            "dep2_origin",
				Collector:         "dep2_collector",
			},
			&model.IsOccurrence{
				Subject:       includedTestExpectedPackage1,
				Artifact:      includedTestExpectedArtifact1,
				Justification: "occ_justification",
				Origin:        "occ_origin",
				Collector:     "occ_collector",
			},
			&model.IsOccurrence{
				Subject:       includedTestExpectedSource,
				Artifact:      includedTestExpectedArtifact1,
				Justification: "occ_justification",
				Origin:        "occ_origin",
				Collector:     "occ_collector",
			},
		},
	}, {
		name:  "hasSBOM - hasSbomID - artifact",
		inArt: []*model.ArtifactInputSpec{testdata.A2},
		hasSBOMCall: &hasSBOMCall{
			Sub: model.PackageOrArtifactInput{
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A2},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
			BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
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
			BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
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
			BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
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
			BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
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
			BF:   []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A2}},
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
			testdata.P1out,
			testdata.P2out,
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
				Package: testdata.P2outName,
				Source:  testdata.S1out,
			},
			&model.HasSourceAt{
				Package: testdata.P2out,
				Source:  testdata.S1out,
			},
		},
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
			testdata.P1out,
			testdata.P2out,
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
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
				Source: &model.IDorSourceInput{SourceInput: testdata.S1},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P1},
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
				Source: &model.IDorSourceInput{SourceInput: testdata.S1},
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
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
			testdata.P1out,
			testdata.P2out,
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
				Source: &model.IDorSourceInput{SourceInput: testdata.S1},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
				Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
				Source: &model.IDorSourceInput{SourceInput: testdata.S1},
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
				Package: &model.IDorPkgInput{PackageInput: testdata.P2},
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nodeID string
			for _, p := range tt.inPkg {
				if _, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: p}); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range tt.inSrc {
				if _, err := b.IngestSource(ctx, model.IDorSourceInput{SourceInput: s}); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range tt.inArt {
				if _, err := b.IngestArtifact(ctx, &model.IDorArtifactInput{ArtifactInput: a}); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, bld := range tt.inBld {
				if _, err := b.IngestBuilder(ctx, &model.IDorBuilderInput{BuilderInput: bld}); err != nil {
					t.Fatalf("Could not ingest builder: %v", err)
				}
			}
			for _, a := range tt.inLic {
				if _, err := b.IngestLicense(ctx, &model.IDorLicenseInput{LicenseInput: a}); err != nil {
					t.Fatalf("Could not ingest license: %v", err)
				}
			}
			for _, g := range tt.inVuln {
				if _, err := b.IngestVulnerability(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: g}); err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				}
			}
			if tt.pkgInput != nil {
				ingestedPkg, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: tt.pkgInput})
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestPackage() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if tt.queryPkgTypeID {
					nodeID = ingestedPkg.PackageTypeID
					tt.usingOnly = []model.Edge{}
				}
				if tt.queryPkgNamespaceID {
					nodeID = ingestedPkg.PackageNamespaceID
					tt.usingOnly = []model.Edge{}
				}
				if tt.queryPkgNameID {
					nodeID = ingestedPkg.PackageNameID
					tt.usingOnly = []model.Edge{}
				}
				if tt.queryPkgVersionID {
					nodeID = ingestedPkg.PackageVersionID
					tt.usingOnly = []model.Edge{}
				}
			}
			if tt.srcInput != nil {
				ingestedSrc, err := b.IngestSource(ctx, model.IDorSourceInput{SourceInput: tt.srcInput})
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestSource() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if tt.querySrcTypeID {
					nodeID = ingestedSrc.SourceTypeID
					tt.usingOnly = []model.Edge{}
				}
				if tt.querySrcNamespaceID {
					nodeID = ingestedSrc.SourceNamespaceID
					tt.usingOnly = []model.Edge{}
				}
				if tt.querySrcNameID {
					nodeID = ingestedSrc.SourceNameID
					tt.usingOnly = []model.Edge{}
				}
			}
			if tt.vulnInput != nil {
				ingestVuln, err := b.IngestVulnerability(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: tt.vulnInput})
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.want, err)
				}
				if tt.queryVulnTypeID {
					nodeID = ingestVuln.VulnerabilityTypeID
					tt.usingOnly = []model.Edge{}
				}
				if tt.queryVulnID {
					nodeID = ingestVuln.VulnerabilityNodeID
					tt.usingOnly = []model.Edge{}
				}
			}
			if tt.licenseInput != nil {
				ingestedLicenseID, err := b.IngestLicense(ctx, &model.IDorLicenseInput{LicenseInput: tt.licenseInput})
				if (err != nil) != tt.wantErr {
					t.Errorf("arangoClient.IngestLicense() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				nodeID = ingestedLicenseID
			}
			if tt.certifyBadCall != nil {
				cbID, err := b.IngestCertifyBad(ctx, tt.certifyBadCall.Sub, tt.certifyBadCall.Match, *tt.certifyBadCall.CB)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.CertifyBad(ctx, &model.CertifyBadSpec{ID: &cbID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryArtifactID {
					nodeID = found[0].Subject.(*model.Artifact).ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactCertifyBad}
				}
				if tt.queryPkgNameID {
					nodeID = found[0].Subject.(*model.Package).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyBad, model.EdgePackageNamePackageNamespace, model.EdgePackageNamePackageVersion}
				}
				if tt.queryPkgVersionID {
					nodeID = found[0].Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyBad, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found[0].Subject.(*model.Source).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceCertifyBad, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryCertifyBadID {
					nodeID = cbID
					tt.usingOnly = []model.Edge{model.EdgeCertifyBadPackage, model.EdgeCertifyBadArtifact, model.EdgeCertifyBadSource}
				}
			}
			if tt.certifyGoodCall != nil {
				cgID, err := b.IngestCertifyGood(ctx, tt.certifyGoodCall.Sub, tt.certifyGoodCall.Match, *tt.certifyGoodCall.CG)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.CertifyGood(ctx, &model.CertifyGoodSpec{ID: &cgID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryArtifactID {
					nodeID = found[0].Subject.(*model.Artifact).ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactCertifyGood}
				}
				if tt.queryPkgNameID {
					nodeID = found[0].Subject.(*model.Package).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyGood, model.EdgePackageNamePackageNamespace, model.EdgePackageNamePackageVersion}
				}
				if tt.queryPkgVersionID {
					nodeID = found[0].Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyGood, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found[0].Subject.(*model.Source).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceCertifyGood, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryCertifyGoodID {
					nodeID = cgID
					tt.usingOnly = []model.Edge{model.EdgeCertifyGoodPackage, model.EdgeCertifyGoodArtifact, model.EdgeCertifyGoodSource}
				}
			}
			if tt.certifyLegalCall != nil {
				clID, err := b.IngestCertifyLegal(ctx, tt.certifyLegalCall.PkgSrc, tt.certifyLegalCall.Dec, tt.certifyLegalCall.Dis, tt.certifyLegalCall.Legal)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.CertifyLegal(ctx, &model.CertifyLegalSpec{ID: &clID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryPkgVersionID {
					nodeID = found[0].Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyLegal, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found[0].Subject.(*model.Source).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceCertifyLegal, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryDeclaredLicenseID {
					nodeID = found[0].DeclaredLicenses[0].ID
					tt.usingOnly = []model.Edge{model.EdgeLicenseCertifyLegal}
				}
				if tt.queryDiscoveredLicenseID {
					nodeID = found[0].DiscoveredLicenses[0].ID
					tt.usingOnly = []model.Edge{model.EdgeLicenseCertifyLegal}
				}
				if tt.queryCertifyLegalID {
					nodeID = clID
				}
			}
			if tt.scorecardCall != nil {
				sID, err := b.IngestScorecard(ctx, model.IDorSourceInput{SourceInput: tt.scorecardCall.Src}, *tt.scorecardCall.SC)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.Scorecards(ctx, &model.CertifyScorecardSpec{ID: &sID})
				if err != nil {
					t.Fatal()
				}
				if tt.querySrcNameID {
					nodeID = found[0].Source.Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceCertifyScorecard, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryScorecardID {
					nodeID = sID
				}
			}
			if tt.vexCall != nil {
				vexID, err := b.IngestVEXStatement(ctx, tt.vexCall.Sub, model.IDorVulnerabilityInput{VulnerabilityInput: tt.vexCall.Vuln}, *tt.vexCall.In)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.CertifyVEXStatement(ctx, &model.CertifyVEXStatementSpec{ID: &vexID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryArtifactID {
					nodeID = found[0].Subject.(*model.Artifact).ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactCertifyVexStatement}
				}
				if tt.queryPkgVersionID {
					nodeID = found[0].Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyVexStatement, model.EdgePackageVersionPackageName}
				}
				if tt.queryVulnID {
					nodeID = found[0].Vulnerability.VulnerabilityIDs[0].ID
					tt.usingOnly = []model.Edge{model.EdgeVulnerabilityCertifyVexStatement, model.EdgeVulnerabilityIDVulnerabilityType}
				}
				if tt.queryCertifyVexID {
					nodeID = vexID
				}
			}
			if tt.certifyVulnCall != nil {
				cvID, err := b.IngestCertifyVuln(ctx, model.IDorPkgInput{PackageInput: tt.certifyVulnCall.Pkg}, model.IDorVulnerabilityInput{VulnerabilityInput: tt.certifyVulnCall.Vuln}, *tt.certifyVulnCall.CertifyVuln)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.CertifyVuln(ctx, &model.CertifyVulnSpec{ID: &cvID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryPkgVersionID {
					nodeID = found[0].Package.Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageCertifyVuln, model.EdgePackageVersionPackageName}
				}
				if tt.queryVulnID {
					nodeID = found[0].Vulnerability.VulnerabilityIDs[0].ID
					tt.usingOnly = []model.Edge{model.EdgeVulnerabilityCertifyVuln, model.EdgeVulnerabilityIDVulnerabilityType}
				}
				if tt.queryCertifyVulnID {
					nodeID = cvID
				}
			}
			if tt.hashEqualCall != nil {
				heID, err := b.IngestHashEqual(ctx, model.IDorArtifactInput{ArtifactInput: tt.hashEqualCall.A1}, model.IDorArtifactInput{ArtifactInput: tt.hashEqualCall.A2}, *tt.hashEqualCall.HE)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.HashEqual(ctx, &model.HashEqualSpec{ID: &heID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryArtifactID {
					nodeID = found[0].Artifacts[0].ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactHashEqual}
				}
				if tt.queryEqualArtifactID {
					nodeID = found[0].Artifacts[1].ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactHashEqual}
				}
				if tt.queryHashEqualID {
					nodeID = heID
					tt.usingOnly = []model.Edge{model.EdgeHashEqualArtifact}
				}
			}
			if tt.hasMetadataCall != nil {
				hmID, err := b.IngestHasMetadata(ctx, tt.hasMetadataCall.Sub, tt.hasMetadataCall.Match, *tt.hasMetadataCall.HM)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.HasMetadata(ctx, &model.HasMetadataSpec{ID: &hmID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryArtifactID {
					nodeID = found[0].Subject.(*model.Artifact).ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactHasMetadata}
				}
				if tt.queryPkgNameID {
					nodeID = found[0].Subject.(*model.Package).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageHasMetadata, model.EdgePackageNamePackageNamespace, model.EdgePackageNamePackageVersion}
				}
				if tt.queryPkgVersionID {
					nodeID = found[0].Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageHasMetadata, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found[0].Subject.(*model.Source).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceHasMetadata, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryHasMetadataID {
					nodeID = hmID
				}
			}
			if tt.hasSBOMCall != nil {
				includes := model.HasSBOMIncludesInputSpec{}
				for _, s := range tt.hasSBOMCall.InSrc {
					if _, err := b.IngestSource(ctx, model.IDorSourceInput{SourceInput: s}); err != nil {
						t.Fatalf("Could not ingest source: %v", err)
					}
				}
				if tt.hasSBOMCall.PkgArt != nil {
					if pkgs, err := b.IngestPackages(ctx, tt.hasSBOMCall.PkgArt.Packages); err != nil {
						t.Fatalf("Could not ingest package: %v", err)
					} else {
						for _, pkg := range pkgs {
							includes.Packages = append(includes.Packages, pkg.PackageVersionID)
						}
					}
					if arts, err := b.IngestArtifacts(ctx, tt.hasSBOMCall.PkgArt.Artifacts); err != nil {
						t.Fatalf("Could not ingest artifact: %v", err)
					} else {
						if arts != nil {
							includes.Artifacts = append(includes.Artifacts, arts...)
						}
					}
				}

				for _, dep := range tt.hasSBOMCall.IsDeps {
					if isDep, err := b.IngestDependency(ctx, model.IDorPkgInput{PackageInput: dep.pkg}, model.IDorPkgInput{PackageInput: dep.depPkg}, dep.matchType, *dep.isDep); err != nil {
						t.Fatalf("Could not ingest dependency: %v", err)
					} else {
						includes.Dependencies = append(includes.Dependencies, isDep)
					}
				}

				for _, occ := range tt.hasSBOMCall.IsOccs {
					if isOcc, err := b.IngestOccurrence(ctx, *occ.Subj, model.IDorArtifactInput{ArtifactInput: occ.Art}, *occ.isOcc); err != nil {
						t.Fatalf("Could not ingest occurrence: %v", err)
					} else {
						includes.Occurrences = append(includes.Occurrences, isOcc)
					}
				}
				hsID, err := b.IngestHasSbom(ctx, tt.hasSBOMCall.Sub, *tt.hasSBOMCall.HS, includes)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.HasSBOM(ctx, &model.HasSBOMSpec{ID: &hsID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryArtifactID {
					nodeID = found[0].Subject.(*model.Artifact).ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactHasSbom}
				}
				if tt.queryPkgVersionID {
					nodeID = found[0].Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageHasSbom, model.EdgePackageVersionPackageName}
				}
				if tt.queryHasSbomID {
					nodeID = hsID
				}
			}
			if tt.hasSlsaCall != nil {
				slsaID, err := b.IngestSLSA(ctx, model.IDorArtifactInput{ArtifactInput: tt.hasSlsaCall.Sub}, tt.hasSlsaCall.BF, model.IDorBuilderInput{BuilderInput: tt.hasSlsaCall.BB}, *tt.hasSlsaCall.SLSA)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.HasSlsa(ctx, &model.HasSLSASpec{ID: &slsaID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryBuilderID {
					nodeID = found[0].Slsa.BuiltBy.ID
					tt.usingOnly = []model.Edge{model.EdgeBuilderHasSlsa}
				}
				if tt.queryArtifactID {
					nodeID = found[0].Subject.ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactHasSlsa}
				}
				if tt.queryHasSlsaID {
					nodeID = slsaID
				}
			}
			if tt.hasSourceAtCall != nil {
				hsID, err := b.IngestHasSourceAt(ctx, model.IDorPkgInput{PackageInput: tt.hasSourceAtCall.Pkg}, *tt.hasSourceAtCall.Match, model.IDorSourceInput{SourceInput: tt.hasSourceAtCall.Src}, *tt.hasSourceAtCall.HSA)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.HasSourceAt(ctx, &model.HasSourceAtSpec{ID: &hsID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryPkgNameID {
					nodeID = found[0].Package.Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageHasSourceAt, model.EdgePackageNamePackageNamespace, model.EdgePackageNamePackageVersion}
				}
				if tt.queryPkgVersionID {
					nodeID = found[0].Package.Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageHasSourceAt, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found[0].Source.Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceHasSourceAt, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryHasSourceAtID {
					nodeID = hsID
				}
			}
			if tt.isDepCall != nil {
				dID, err := b.IngestDependency(ctx, model.IDorPkgInput{PackageInput: tt.isDepCall.P1}, model.IDorPkgInput{PackageInput: tt.isDepCall.P2}, tt.isDepCall.MF, *tt.isDepCall.ID)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.IsDependency(ctx, &model.IsDependencySpec{ID: &dID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryPkgNameID {
					nodeID = found[0].DependencyPackage.Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageIsDependency, model.EdgePackageNamePackageNamespace, model.EdgePackageNamePackageVersion}
				}
				if tt.queryPkgVersionID {
					nodeID = found[0].DependencyPackage.Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageIsDependency, model.EdgePackageVersionPackageName}
				}
				if tt.queryIsDependencyID {
					nodeID = dID
				}
			}
			if tt.isOcurCall != nil {
				oID, err := b.IngestOccurrence(ctx, tt.isOcurCall.PkgSrc, model.IDorArtifactInput{ArtifactInput: tt.isOcurCall.Artifact}, *tt.isOcurCall.Occurrence)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.IsOccurrence(ctx, &model.IsOccurrenceSpec{ID: &oID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryArtifactID {
					nodeID = found[0].Artifact.ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactIsOccurrence}
				}
				if tt.queryPkgVersionID {
					nodeID = found[0].Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackageIsOccurrence, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found[0].Subject.(*model.Source).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourceIsOccurrence, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryIsOccurrenceID {
					nodeID = oID
				}
			}
			if tt.pkgEqualCall != nil {
				peID, err := b.IngestPkgEqual(ctx, model.IDorPkgInput{PackageInput: tt.pkgEqualCall.P1}, model.IDorPkgInput{PackageInput: tt.pkgEqualCall.P2}, *tt.pkgEqualCall.HE)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.PkgEqual(ctx, &model.PkgEqualSpec{ID: &peID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryPkgVersionID {
					nodeID = found[0].Packages[0].Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackagePkgEqual, model.EdgePackageVersionPackageName}
				}
				if tt.queryEqualPkgID {
					nodeID = found[0].Packages[1].Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackagePkgEqual, model.EdgePackageVersionPackageName}
				}
				if tt.queryPkgEqualID {
					nodeID = peID
				}
			}
			if tt.pointOfContactCall != nil {
				pocID, err := b.IngestPointOfContact(ctx, tt.pointOfContactCall.Sub, tt.pointOfContactCall.Match, *tt.pointOfContactCall.POC)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.PointOfContact(ctx, &model.PointOfContactSpec{ID: &pocID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryArtifactID {
					nodeID = found[0].Subject.(*model.Artifact).ID
					tt.usingOnly = []model.Edge{model.EdgeArtifactPointOfContact}
				}
				if tt.queryPkgNameID {
					nodeID = found[0].Subject.(*model.Package).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackagePointOfContact, model.EdgePackageNamePackageNamespace, model.EdgePackageNamePackageVersion}
				}
				if tt.queryPkgVersionID {
					nodeID = found[0].Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID
					tt.usingOnly = []model.Edge{model.EdgePackagePointOfContact, model.EdgePackageVersionPackageName}
				}
				if tt.querySrcNameID {
					nodeID = found[0].Subject.(*model.Source).Namespaces[0].Names[0].ID
					tt.usingOnly = []model.Edge{model.EdgeSourcePointOfContact, model.EdgeSourceNameSourceNamespace}
				}
				if tt.queryPointOfContactID {
					nodeID = pocID
				}
			}
			if tt.vulnEqualCall != nil {
				veID, err := b.IngestVulnEqual(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: tt.vulnEqualCall.Vuln}, model.IDorVulnerabilityInput{VulnerabilityInput: tt.vulnEqualCall.OtherVuln}, *tt.vulnEqualCall.In)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				found, err := b.VulnEqual(ctx, &model.VulnEqualSpec{ID: &veID})
				if err != nil {
					t.Fatal()
				}
				if tt.queryVulnID {
					nodeID = found[0].Vulnerabilities[0].VulnerabilityIDs[0].ID
					tt.usingOnly = []model.Edge{model.EdgeVulnerabilityVulnEqual, model.EdgeVulnerabilityIDVulnerabilityType}
				}
				if tt.queryEqualVulnID {
					nodeID = found[0].Vulnerabilities[1].VulnerabilityIDs[0].ID
					tt.usingOnly = []model.Edge{model.EdgeVulnerabilityVulnEqual, model.EdgeVulnerabilityIDVulnerabilityType}
				}
				if tt.queryVulnEqualID {
					nodeID = veID
				}
			}
			if tt.vulnMetadataCall != nil {
				ingestedVuln, err := b.IngestVulnerability(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: tt.inVuln[0]})
				if err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				}

				vulnMetadataID, err := b.IngestVulnerabilityMetadata(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: tt.vulnMetadataCall.Vuln}, *tt.vulnMetadataCall.VulnMetadata)
				if (err != nil) != tt.wantErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", tt.wantErr, err)
				}
				if err != nil {
					return
				}
				if tt.queryVulnID {
					nodeID = ingestedVuln.VulnerabilityNodeID
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
			if diff := cmp.Diff(tt.want, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
