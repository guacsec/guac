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

package deps_dev

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
)

func TestNewDepsDevParser(t *testing.T) {
	tests := []struct {
		name string
		want common.DocumentParser
	}{{
		name: "new deps.dev parser",
		want: &depsDevParser{},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewDepsDevParser(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDepsDevParser() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_depsDevParser_Parse(t *testing.T) {
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	ctx := logging.WithLogger(context.Background())

	tests := []struct {
		name           string
		doc            *processor.Document
		wantPredicates *assembler.IngestPredicates
		wantErr        bool
	}{{
		name: "package foreign-types",
		doc: &processor.Document{
			Blob:              []byte(testdata.CollectedForeignTypes),
			Type:              processor.DocumentDepsDev,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		wantPredicates: &assembler.IngestPredicates{
			CertifyScorecard: []assembler.CertifyScorecardIngest{
				{
					Source: &model.SourceInputSpec{
						Type:      "git",
						Namespace: "github.com/sfackler",
						Name:      "foreign-types",
					},
					Scorecard: &model.ScorecardInputSpec{
						Checks: []model.ScorecardCheckInputSpec{
							{Check: "Code-Review", Score: 2},
							{Check: "Maintained", Score: 0},
							{Check: "CII-Best-Practices", Score: 0},
							{Check: "Vulnerabilities", Score: 10},
							{Check: "Signed-Releases", Score: -1},
							{Check: "Branch-Protection", Score: 0},
							{Check: "License", Score: 10},
							{Check: "Pinned-Dependencies", Score: 7},
							{Check: "Binary-Artifacts", Score: 10},
							{Check: "Token-Permissions", Score: 0},
							{Check: "Dangerous-Workflow", Score: 10},
							{Check: "SAST", Score: 0},
							{Check: "Packaging", Score: -1},
							{Check: "Dependency-Update-Tool", Score: 0},
							{Check: "Fuzzing", Score: 0},
							{Check: "Security-Policy", Score: 0},
						},
						AggregateScore:   3.700000047683716,
						TimeScanned:      tm.UTC(),
						ScorecardVersion: "v4.8.0-78-gfb07860",
						ScorecardCommit:  "fb07860d86065cdcbd2d0d5c6b998ff4542d53fe",
						Origin:           "",
						Collector:        "",
					},
				}, {
					Source: &model.SourceInputSpec{
						Type:      "git",
						Namespace: "github.com/sfackler",
						Name:      "foreign-types",
					},
					Scorecard: &model.ScorecardInputSpec{
						Checks: []model.ScorecardCheckInputSpec{
							{Check: "Code-Review", Score: 2},
							{Check: "Maintained", Score: 0},
							{Check: "CII-Best-Practices", Score: 0},
							{Check: "Vulnerabilities", Score: 10},
							{Check: "Signed-Releases", Score: -1},
							{Check: "Branch-Protection", Score: 0},
							{Check: "License", Score: 10},
							{Check: "Pinned-Dependencies", Score: 7},
							{Check: "Binary-Artifacts", Score: 10},
							{Check: "Token-Permissions", Score: 0},
							{Check: "Dangerous-Workflow", Score: 10},
							{Check: "SAST", Score: 0},
							{Check: "Packaging", Score: -1},
							{Check: "Dependency-Update-Tool", Score: 0},
							{Check: "Fuzzing", Score: 0},
							{Check: "Security-Policy", Score: 0},
						},
						AggregateScore:   3.700000047683716,
						TimeScanned:      tm.UTC(),
						ScorecardVersion: "v4.8.0-78-gfb07860",
						ScorecardCommit:  "fb07860d86065cdcbd2d0d5c6b998ff4542d53fe",
						Origin:           "",
						Collector:        "",
					},
				},
			},
			IsDependency: []assembler.IsDependencyIngest{
				{
					Pkg: &model.PkgInputSpec{
						Type:      "cargo",
						Namespace: ptrfrom.String(""),
						Name:      "foreign-types",
						Version:   ptrfrom.String("0.3.2"),
						Subpath:   ptrfrom.String(""),
					},
					DepPkg: &model.PkgInputSpec{
						Type:      "cargo",
						Namespace: ptrfrom.String(""),
						Name:      "foreign-types-shared",
						Version:   ptrfrom.String("0.1.1"),
						Subpath:   ptrfrom.String(""),
					},
					IsDependency: &model.IsDependencyInputSpec{
						VersionRange:  "0.1.1",
						Justification: "dependency data collected via deps.dev",
						Origin:        "",
						Collector:     "",
					},
				},
			},
			HasSourceAt: []assembler.HasSourceAtIngest{
				{
					Pkg: &model.PkgInputSpec{
						Type:      "cargo",
						Namespace: ptrfrom.String(""),
						Name:      "foreign-types",
						Version:   ptrfrom.String("0.3.2"),
						Subpath:   ptrfrom.String(""),
					},
					PkgMatchFlag: model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					Src: &model.SourceInputSpec{
						Type:      "git",
						Namespace: "github.com/sfackler",
						Name:      "foreign-types",
					},
					HasSourceAt: &model.HasSourceAtInputSpec{
						KnownSince:    tm.UTC(),
						Justification: "collected via deps.dev",
						Origin:        "",
						Collector:     "",
					},
				}, {
					Pkg: &model.PkgInputSpec{
						Type:      "cargo",
						Namespace: ptrfrom.String(""),
						Name:      "foreign-types-shared",
						Version:   ptrfrom.String("0.1.1"),
						Subpath:   ptrfrom.String(""),
					},
					PkgMatchFlag: model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					Src: &model.SourceInputSpec{
						Type:      "git",
						Namespace: "github.com/sfackler",
						Name:      "foreign-types",
					},
					HasSourceAt: &model.HasSourceAtInputSpec{
						KnownSince:    tm.UTC(),
						Justification: "collected via deps.dev",
						Origin:        "",
						Collector:     "",
					},
				},
			},
		},
		wantErr: false,
	}, {
		name: "package yargs-parser",
		doc: &processor.Document{
			Blob:              []byte(testdata.CollectedYargsParser),
			Type:              processor.DocumentDepsDev,
			Format:            processor.FormatJSON,
			SourceInformation: processor.SourceInformation{},
		},
		wantPredicates: &assembler.IngestPredicates{
			IsDependency: []assembler.IsDependencyIngest{
				{
					Pkg: &model.PkgInputSpec{
						Type:      "npm",
						Namespace: ptrfrom.String(""),
						Name:      "yargs-parser",
						Version:   ptrfrom.String("4.2.1"),
						Subpath:   ptrfrom.String(""),
					},
					DepPkg: &model.PkgInputSpec{
						Type:      "npm",
						Namespace: ptrfrom.String(""),
						Name:      "camelcase",
						Version:   ptrfrom.String("3.0.0"),
						Subpath:   ptrfrom.String(""),
					},
					IsDependency: &model.IsDependencyInputSpec{
						VersionRange:  "3.0.0",
						Justification: "dependency data collected via deps.dev",
						Origin:        "",
						Collector:     "",
					},
				},
			},
			CertifyVuln: []assembler.CertifyVulnIngest{
				{
					Pkg: &model.PkgInputSpec{
						Type:      "npm",
						Namespace: ptrfrom.String(""),
						Name:      "yargs-parser",
						Version:   ptrfrom.String("4.2.1"),
						Subpath:   ptrfrom.String(""),
					},
					OSV: &model.OSVInputSpec{
						OsvId: "GHSA-p9pc-299p-vxgp",
					},
					VulnData: &model.VulnerabilityMetaDataInput{
						TimeScanned:    tm.UTC(),
						DbUri:          "",
						DbVersion:      "",
						ScannerUri:     "osv.dev",
						ScannerVersion: "",
						Origin:         "",
						Collector:      "",
					},
				},
			},
			IsVuln: []assembler.IsVulnIngest{
				{
					OSV: &model.OSVInputSpec{
						OsvId: "GHSA-p9pc-299p-vxgp",
					},
					GHSA: &model.GHSAInputSpec{
						GhsaId: "GHSA-p9pc-299p-vxgp",
					},
					IsVuln: &model.IsVulnerabilityInputSpec{
						Justification: "decoded OSV data collected via deps.dev",
						Origin:        "",
						Collector:     "",
					},
				},
			},
			HasSourceAt: []assembler.HasSourceAtIngest{
				{
					Pkg: &model.PkgInputSpec{
						Type:      "npm",
						Namespace: ptrfrom.String(""),
						Name:      "yargs-parser",
						Version:   ptrfrom.String("4.2.1"),
						Subpath:   ptrfrom.String(""),
					},
					PkgMatchFlag: model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					Src: &model.SourceInputSpec{
						Type:      "git",
						Namespace: "github.com/yargs",
						Name:      "yargs-parser.git",
					},
					HasSourceAt: &model.HasSourceAtInputSpec{
						KnownSince:    tm.UTC(),
						Justification: "collected via deps.dev",
						Origin:        "",
						Collector:     "",
					},
				},
				{
					Pkg: &model.PkgInputSpec{
						Type:      "npm",
						Namespace: ptrfrom.String(""),
						Name:      "camelcase",
						Version:   ptrfrom.String("3.0.0"),
						Subpath:   ptrfrom.String(""),
					},
					PkgMatchFlag: model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					Src: &model.SourceInputSpec{
						Type:      "git",
						Namespace: "github.com/sindresorhus",
						Name:      "camelcase.git",
					},
					HasSourceAt: &model.HasSourceAtInputSpec{
						KnownSince:    tm.UTC(),
						Justification: "collected via deps.dev",
						Origin:        "",
						Collector:     "",
					},
				},
			},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDepsDevParser()
			if err := d.Parse(ctx, tt.doc); (err != nil) != tt.wantErr {
				t.Errorf("scorecard.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			preds := d.GetPredicates(ctx)
			if d := cmp.Diff(tt.wantPredicates, preds, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
				t.Errorf("scorecard.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}
