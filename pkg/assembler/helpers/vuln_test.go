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

func TestOSVToGHSACVE(t *testing.T) {
	tests := []struct {
		Name    string
		Input   string
		ExpCVE  *generated.CVEInputSpec
		ExpGHSA *generated.GHSAInputSpec
		ExpErr  bool
	}{
		{
			Name:  "Good CVE",
			Input: "CVE-1999-1234",
			ExpCVE: &generated.CVEInputSpec{
				CveId: "CVE-1999-1234",
				Year:  "1999",
			},
			ExpGHSA: nil,
			ExpErr:  false,
		},
		{
			Name:   "Good GHSA",
			Input:  "GHSA-1234-asdf-qwer",
			ExpCVE: nil,
			ExpGHSA: &generated.GHSAInputSpec{
				GhsaId: "GHSA-1234-asdf-qwer",
			},
			ExpErr: false,
		},
		{
			Name:    "Bad CVE",
			Input:   "CVE-1999",
			ExpCVE:  nil,
			ExpGHSA: nil,
			ExpErr:  true,
		},
		{
			Name:    "Bad",
			Input:   "asdf",
			ExpCVE:  nil,
			ExpGHSA: nil,
			ExpErr:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			cve, ghsa, err := helpers.OSVToGHSACVE(test.Input)
			if (err != nil) != test.ExpErr {
				t.Errorf("Expected error: %v got: %v", test.ExpErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpCVE, cve); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.ExpGHSA, ghsa); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
