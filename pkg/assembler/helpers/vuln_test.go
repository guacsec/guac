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

package helpers_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

func TestVulnInputToVURI(t *testing.T) {
	tests := []struct {
		Name    string
		Input   *generated.VulnerabilityInputSpec
		ExpVURI string
	}{
		{
			Name: "cve",
			Input: &generated.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "cve-2023-8675",
			},
			ExpVURI: "vuln://cve/cve-2023-8675",
		},
		{
			Name: "ghsa",
			Input: &generated.VulnerabilityInputSpec{
				Type:            "ghsa",
				VulnerabilityID: "GHSA-gwvq-rgqf-993f",
			},
			ExpVURI: "vuln://ghsa/ghsa-gwvq-rgqf-993f",
		},
		{
			Name: "dsa",
			Input: &generated.VulnerabilityInputSpec{
				Type:            "DSA",
				VulnerabilityID: "DSA-5464-1",
			},
			ExpVURI: "vuln://dsa/dsa-5464-1",
		},
		{
			Name: "osv",
			Input: &generated.VulnerabilityInputSpec{
				Type:            "osv",
				VulnerabilityID: "DLA-3515-1",
			},
			ExpVURI: "vuln://osv/dla-3515-1",
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			vuln := helpers.VulnInputToVURI(test.Input)
			if diff := cmp.Diff(test.ExpVURI, vuln); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCreateVulnInput(t *testing.T) {
	tests := []struct {
		Name    string
		Input   string
		ExpVuln *generated.VulnerabilityInputSpec
		ExpErr  bool
	}{
		{
			Name:  "Good CVE",
			Input: "CVE-1999-1234",
			ExpVuln: &generated.VulnerabilityInputSpec{
				Type:            "cve",
				VulnerabilityID: "cve-1999-1234",
			},
			ExpErr: false,
		},
		{
			Name:  "Good GHSA",
			Input: "GHSA-1234-asdf-qwer",
			ExpVuln: &generated.VulnerabilityInputSpec{
				Type:            "ghsa",
				VulnerabilityID: "ghsa-1234-asdf-qwer",
			},
			ExpErr: false,
		},
		{
			Name:  "Good OSV - asb",
			Input: "ASB-A-189942529",
			ExpVuln: &generated.VulnerabilityInputSpec{
				Type:            "asb",
				VulnerabilityID: "asb-a-189942529",
			},
			ExpErr: false,
		},
		{
			Name:  "Good OSV - dsa",
			Input: "DSA-5474-1",
			ExpVuln: &generated.VulnerabilityInputSpec{
				Type:            "dsa",
				VulnerabilityID: "dsa-5474-1",
			},
			ExpErr: false,
		},
		{
			Name:    "Bad",
			Input:   "asdf",
			ExpVuln: nil,
			ExpErr:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			vuln, err := helpers.CreateVulnInput(test.Input)
			if (err != nil) != test.ExpErr {
				t.Errorf("Expected error: %v got: %v", test.ExpErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpVuln, vuln); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
