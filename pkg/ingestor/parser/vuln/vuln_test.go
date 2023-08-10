//
// Copyright 2022 The GUAC Authors.
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

package vuln

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func TestParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	tests := []struct {
		name    string
		doc     *processor.Document
		wantCVs []assembler.CertifyVulnIngest
		wantIVs []assembler.VulnEqualIngest
		wantErr bool
	}{{
		name: "valid vulnerability certifier document",
		doc: &processor.Document{
			// TODO(jeffmendoza) Test data does not have multiple packages or digests
			Blob:   testdata.ITE6VulnExample,
			Format: processor.FormatJSON,
			Type:   processor.DocumentITE6Vul,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantCVs: []assembler.CertifyVulnIngest{
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-7rjr-3q55-vv33",
				},
				VulnData: &generated.ScanMetadataInput{
					TimeScanned:    tm,
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
				},
			},
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-8489-44mv-ggj8",
				},
				VulnData: &generated.ScanMetadataInput{
					TimeScanned:    tm,
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
				},
			},
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-fxph-q3j8-mv87",
				},
				VulnData: &generated.ScanMetadataInput{
					TimeScanned:    tm,
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
				},
			},
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-jfh8-c2jp-5v3q",
				},
				VulnData: &generated.ScanMetadataInput{
					TimeScanned:    tm,
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
				},
			},
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-p6xc-xr62-6r2g",
				},
				VulnData: &generated.ScanMetadataInput{
					TimeScanned:    tm,
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
				},
			},
			{
				Pkg: &generated.PkgInputSpec{
					Type:      "maven",
					Namespace: ptrfrom.String("org.apache.logging.log4j"),
					Name:      "log4j-core",
					Version:   ptrfrom.String("2.8.1"),
					Subpath:   ptrfrom.String(""),
				},
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-vwqq-5vrc-xw9h",
				},
				VulnData: &generated.ScanMetadataInput{
					TimeScanned:    tm,
					ScannerUri:     "osv.dev",
					ScannerVersion: "0.0.14",
				},
			},
		},
		wantIVs: []assembler.VulnEqualIngest{
			{
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-vwqq-5vrc-xw9h",
				},
				EqualVulnerability: &generated.VulnerabilityInputSpec{
					Type:            "ghsa",
					VulnerabilityID: "ghsa-vwqq-5vrc-xw9h",
				},
				VulnEqual: &generated.VulnEqualInputSpec{
					Justification: "Decoded OSV data",
				},
			},
			{
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-7rjr-3q55-vv33",
				},
				EqualVulnerability: &generated.VulnerabilityInputSpec{
					Type:            "ghsa",
					VulnerabilityID: "ghsa-7rjr-3q55-vv33",
				},
				VulnEqual: &generated.VulnEqualInputSpec{
					Justification: "Decoded OSV data",
				},
			},
			{
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-8489-44mv-ggj8",
				},
				EqualVulnerability: &generated.VulnerabilityInputSpec{
					Type:            "ghsa",
					VulnerabilityID: "ghsa-8489-44mv-ggj8",
				},
				VulnEqual: &generated.VulnEqualInputSpec{
					Justification: "Decoded OSV data",
				},
			},
			{
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-fxph-q3j8-mv87",
				},
				EqualVulnerability: &generated.VulnerabilityInputSpec{
					Type:            "ghsa",
					VulnerabilityID: "ghsa-fxph-q3j8-mv87",
				},
				VulnEqual: &generated.VulnEqualInputSpec{
					Justification: "Decoded OSV data",
				},
			},
			{
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-jfh8-c2jp-5v3q",
				},
				EqualVulnerability: &generated.VulnerabilityInputSpec{
					Type:            "ghsa",
					VulnerabilityID: "ghsa-jfh8-c2jp-5v3q",
				},
				VulnEqual: &generated.VulnEqualInputSpec{
					Justification: "Decoded OSV data",
				},
			},
			{
				Vulnerability: &generated.VulnerabilityInputSpec{
					Type:            "osv",
					VulnerabilityID: "ghsa-p6xc-xr62-6r2g",
				},
				EqualVulnerability: &generated.VulnerabilityInputSpec{
					Type:            "ghsa",
					VulnerabilityID: "ghsa-p6xc-xr62-6r2g",
				},
				VulnEqual: &generated.VulnEqualInputSpec{
					Justification: "Decoded OSV data",
				},
			},
		},
		wantErr: false,
	}, {
		name: "no vulnerability certifier document with package digest",
		doc: &processor.Document{
			Blob:   testdata.ITE6NoVulnExample,
			Format: processor.FormatJSON,
			Type:   processor.DocumentITE6Vul,
			SourceInformation: processor.SourceInformation{
				Collector: "TestCollector",
				Source:    "TestSource",
			},
		},
		wantCVs: []assembler.CertifyVulnIngest{{
			Pkg: &generated.PkgInputSpec{
				Type:      "maven",
				Namespace: ptrfrom.String("org.apache.logging.log4j"),
				Name:      "log4j-core",
				Version:   ptrfrom.String("2.8.1"),
				Subpath:   ptrfrom.String(""),
			},
			VulnData: &generated.ScanMetadataInput{
				TimeScanned:    tm,
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
			},
		}},
		wantIVs: []assembler.VulnEqualIngest{},
		wantErr: false,
	}}
	ivSortOpt := cmp.Transformer("Sort", func(in []assembler.VulnEqualIngest) []assembler.VulnEqualIngest {
		out := append([]assembler.VulnEqualIngest(nil), in...)
		sort.Slice(out, func(i, j int) bool {
			return strings.Compare(out[i].Vulnerability.VulnerabilityID, out[j].Vulnerability.VulnerabilityID) > 0
		})
		return out
	})
	cvSortOpt := cmp.Transformer("Sort", func(in []assembler.CertifyVulnIngest) []assembler.CertifyVulnIngest {
		out := append([]assembler.CertifyVulnIngest(nil), in...)
		sort.Slice(out, func(i, j int) bool {
			return strings.Compare(out[i].Vulnerability.VulnerabilityID, out[j].Vulnerability.VulnerabilityID) > 0
		})
		return out
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewVulnCertificationParser()
			err := s.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parser.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			ip := s.GetPredicates(ctx)
			if diff := cmp.Diff(tt.wantCVs, ip.CertifyVuln, cvSortOpt); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantIVs, ip.VulnEqual, ivSortOpt); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
