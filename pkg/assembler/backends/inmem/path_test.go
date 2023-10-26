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

package inmem_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func Test_Nodes(t *testing.T) {
	ctx := context.Background()
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
			Artifacts: []*model.Artifact{testdata.A1out, testdata.A3out},
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
		inPkg: []*model.PkgInputSpec{testdata.P2, testdata.P4},
		inArt: []*model.ArtifactInputSpec{testdata.A1},
		isDepCall: &isDepCall{
			P1: testdata.P2,
			P2: testdata.P4,
			MF: mSpecific,
			ID: &model.IsDependencyInputSpec{
				Justification: "test justification",
			},
		},
		isOcurCall: &isOcurCall{
			PkgSrc: model.PackageOrSourceInput{
				Package: testdata.P4,
			},
			Artifact: testdata.A1,
			Occurrence: &model.IsOccurrenceInputSpec{
				Justification: "test justification",
			},
		},
		hasSBOMCall: &hasSBOMCall{
			Sub: model.PackageOrArtifactInput{
				Package: testdata.P2,
			},
			HS: &model.HasSBOMInputSpec{
				DownloadLocation: "location two",
			},
		},
		want: []model.Node{&model.HasSbom{
			Subject:          testdata.P2out,
			DownloadLocation: "location two",
			IncludedSoftware: []model.PackageOrArtifact{testdata.P2out, testdata.P4out, testdata.A1out},
			IncludedDependencies: []*model.IsDependency{{
				Package:           testdata.P2out,
				DependencyPackage: testdata.P4out,
				Justification:     "test justification",
			}},
			IncludedOccurrences: []*model.IsOccurrence{{
				Subject:       testdata.P4out,
				Artifact:      testdata.A1out,
				Justification: "test justification",
			}},
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
			b, err := backends.Get("inmem", nil, nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			var nodeID string
			includes := model.HasSBOMIncludesInputSpec{}
			for _, p := range tt.inPkg {
				if pkg, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				} else {
					includes.Software = append(includes.Software, pkg.Namespaces[0].Names[0].Versions[0].ID)
				}
			}
			for _, s := range tt.inSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range tt.inArt {
				if art, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				} else {
					includes.Software = append(includes.Software, art.ID)
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
				includes.Software = append(includes.Software, nodeID)
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
				includes.Dependencies = append(includes.Dependencies, nodeID)
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
				includes.Occurrences = append(includes.Occurrences, nodeID)
			}
			if tt.hasSBOMCall != nil {
				// After isDepCall and isOcurCall so they can set up includes.
				found, err := b.IngestHasSbom(ctx, tt.hasSBOMCall.Sub, *tt.hasSBOMCall.HS, includes)
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
