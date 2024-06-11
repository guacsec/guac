//
// Copyright 2024 The GUAC Authors.
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

package scanner

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
)

func TestPurlsToScan(t *testing.T) {
	ctx := context.Background()
	tm, _ := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	tests := []struct {
		name    string
		purls   []string
		wantCVs []assembler.CertifyVulnIngest
		wantVEs []assembler.VulnEqualIngest
		wantErr bool
	}{{
		name:  "valid vulnerability certifier document",
		purls: []string{"pkg:maven/org.apache.logging.log4j/log4j-core@2.8.1"},
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
					Origin:         "osv_certifier",
					Collector:      "osv_certifier",
					DocumentRef:    "sha256_daeea32fb48a532d48ce7a549b7e0cdf98eb6df80869c3b6d3ec21174b015d14",
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
					Origin:         "osv_certifier",
					Collector:      "osv_certifier",
					DocumentRef:    "sha256_daeea32fb48a532d48ce7a549b7e0cdf98eb6df80869c3b6d3ec21174b015d14",
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
					Origin:         "osv_certifier",
					Collector:      "osv_certifier",
					DocumentRef:    "sha256_daeea32fb48a532d48ce7a549b7e0cdf98eb6df80869c3b6d3ec21174b015d14",
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
					Origin:         "osv_certifier",
					Collector:      "osv_certifier",
					DocumentRef:    "sha256_daeea32fb48a532d48ce7a549b7e0cdf98eb6df80869c3b6d3ec21174b015d14",
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
					Origin:         "osv_certifier",
					Collector:      "osv_certifier",
					DocumentRef:    "sha256_daeea32fb48a532d48ce7a549b7e0cdf98eb6df80869c3b6d3ec21174b015d14",
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
					Origin:         "osv_certifier",
					Collector:      "osv_certifier",
					DocumentRef:    "sha256_daeea32fb48a532d48ce7a549b7e0cdf98eb6df80869c3b6d3ec21174b015d14",
				},
			},
		},
		wantVEs: []assembler.VulnEqualIngest{
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
					Origin:        "osv_certifier",
					Collector:     "osv_certifier",
					DocumentRef:   "sha256_daeea32fb48a532d48ce7a549b7e0cdf98eb6df80869c3b6d3ec21174b015d14",
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
					Origin:        "osv_certifier",
					Collector:     "osv_certifier",
					DocumentRef:   "sha256_daeea32fb48a532d48ce7a549b7e0cdf98eb6df80869c3b6d3ec21174b015d14",
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
					Origin:        "osv_certifier",
					Collector:     "osv_certifier",
					DocumentRef:   "sha256_daeea32fb48a532d48ce7a549b7e0cdf98eb6df80869c3b6d3ec21174b015d14",
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
					Origin:        "osv_certifier",
					Collector:     "osv_certifier",
					DocumentRef:   "sha256_daeea32fb48a532d48ce7a549b7e0cdf98eb6df80869c3b6d3ec21174b015d14",
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
					Origin:        "osv_certifier",
					Collector:     "osv_certifier",
					DocumentRef:   "sha256_daeea32fb48a532d48ce7a549b7e0cdf98eb6df80869c3b6d3ec21174b015d14",
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
					Origin:        "osv_certifier",
					Collector:     "osv_certifier",
					DocumentRef:   "sha256_daeea32fb48a532d48ce7a549b7e0cdf98eb6df80869c3b6d3ec21174b015d14",
				},
			},
		},
		wantErr: false,
	}, {
		name:  "no vulnerability purl",
		purls: []string{"pkg:maven/io.vertx/vertx-web-common@4.3.7?type=jar"},
		wantCVs: []assembler.CertifyVulnIngest{{
			Pkg: &generated.PkgInputSpec{
				Type:      "maven",
				Namespace: ptrfrom.String("io.vertx"),
				Name:      "vertx-web-common",
				Version:   ptrfrom.String("4.3.7"),
				Subpath:   ptrfrom.String(""),
				Qualifiers: []generated.PackageQualifierInputSpec{{
					Key:   "type",
					Value: "jar",
				}},
			},
			Vulnerability: &generated.VulnerabilityInputSpec{Type: "noVuln"},
			VulnData: &generated.ScanMetadataInput{
				TimeScanned:    tm,
				ScannerUri:     "osv.dev",
				ScannerVersion: "0.0.14",
				Origin:         "osv_certifier",
				Collector:      "osv_certifier",
				DocumentRef:    "sha256_7868203b875a5d00c4f6c1f31615c9b26eef0189cf611b5f1cf1150fbe40b85e",
			},
		}},
		wantVEs: []assembler.VulnEqualIngest{},
		wantErr: false,
	}, {
		name:    "no vulnerability purl",
		purls:   []string{""},
		wantCVs: []assembler.CertifyVulnIngest{},
		wantVEs: []assembler.VulnEqualIngest{},
		wantErr: true,
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
			gotVEs, gotCVs, err := PurlsToScan(ctx, tt.purls)
			if (err != nil) != tt.wantErr {
				t.Errorf("PurlsToScan() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.wantCVs, gotCVs, cvSortOpt, cmpopts.IgnoreFields(generated.ScanMetadataInput{}, "TimeScanned", "DocumentRef")); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantVEs, gotVEs, ivSortOpt, cmpopts.IgnoreFields(generated.VulnEqualInputSpec{}, "DocumentRef")); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
