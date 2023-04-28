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

package depversion

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
)

// TODO: add tests for "VersionMatchObject.Match"
func Test_VersionRangeParse(t *testing.T) {
	testCases := []struct {
		input  string
		expect VersionMatchObject
	}{
		{
			// deps.dev test set
			input: "",
			expect: VersionMatchObject{
				All: true,
			},
		},
		{
			input: "1.7.21",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"=1.7.21"},
				},
			},
		},
		{
			input: "3.0.3",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"=3.0.3"},
				},
			},
		},
		{
			input: "<2.0,>=0.12",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"<2.0,>=0.12"},
				},
			},
		},
		{
			input: ">=1.0.0",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.0.0"},
				},
			},
		},
		// not even proper semver... We will conver it to semver
		{
			input: ">=1.0.0rc8",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.0.0-rc8"},
				},
			},
		},
		{
			input: ">=v1.0.0rc8",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.0.0-rc8"},
				},
			},
		},
		{
			input: "[1.5.0,1.7.0]",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.5.0,<=1.7.0"},
				},
			},
		},

		{
			input: "[1.5.0,)",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.5.0"},
				},
			},
		},
		{
			input: "[3.0,)",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=3.0"},
				},
			},
		},
		{
			input: "^0.11",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=0.11,<1.0.0"},
				},
			},
		},
		{
			input: "^1",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1,<2.0.0"},
				},
			},
		},
		{
			input: "^1.0.25",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.0.25,<2.0.0"},
				},
			},
		},
		{
			input: "^3.0.0 || ^4.0.0",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=3.0.0,<4.0.0"},
					{">=4.0.0,<5.0.0"},
				},
			},
		},
		{
			input: "v0.0.0-20190603091049-60506f45cf65",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"=0.0.0-20190603091049-60506f45cf65"},
				},
			},
		},

		{
			input: "v1.1.2",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"=1.1.2"},
				},
			},
		},

		// NPM test set
		{
			input: "1.0.0 - 2.9999.9999",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.0.0,<=2.9999.9999"},
				},
			},
		},
		{
			input: ">=1.0.2 <2.1.2",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.0.2,<2.1.2"},
				},
			},
		},
		{
			input: ">1.0.2 <=2.3.4",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">1.0.2,<=2.3.4"},
				},
			},
		},
		{
			input: "2.0.1",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"=2.0.1"},
				},
			},
		},
		{
			input: "<1.0.0 || >=2.3.1 <2.4.5 || >=2.5.2 <3.0.0",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{"<1.0.0"},
					{">=2.3.1,<2.4.5"},
					{">=2.5.2,<3.0.0"},
				},
			},
		},
		{
			input: "http://asdf.com/asdf.tar.gz",
			expect: VersionMatchObject{
				Exact: ptrfrom.String("http://asdf.com/asdf.tar.gz"),
			},
		},
		{
			input: "~1.2",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.2,<1.3.0"},
				},
			},
		},
		{
			input: "~1.2.3",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=1.2.3,<1.3.0"},
				},
			},
		},
		{
			input: "2.x",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=2.0.0,<3.0.0"},
				},
			},
		},
		{
			input: "3.3.x",
			expect: VersionMatchObject{
				VRSet: []VersionRange{
					{">=3.3.0,<3.4.0"},
				},
			},
		},
		{
			// special case latest set to no constraint
			input: "latest",
			expect: VersionMatchObject{
				All: true,
			},
		},
		{
			input: "file:../dyl",
			expect: VersionMatchObject{
				Exact: ptrfrom.String("file:../dyl"),
			},
		},
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("parsing version range %s", tt.input), func(t *testing.T) {

			got, err := ParseVersionRange(tt.input)
			if err != nil {
				t.Errorf("got unexpected err: %v", err)
				return
			}

			if diff := cmp.Diff(tt.expect, got); len(diff) > 0 {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

func Test_ParseVersionValue(t *testing.T) {
	testCases := []struct {
		input  string
		expect VersionValue
	}{
		{
			input: "",
			expect: VersionValue{
				Raw: "",
			},
		},
		{
			input: "1.2.3",
			expect: VersionValue{
				SemVer: ptrfrom.String("1.2.3"),
				Raw:    "1.2.3",
			},
		},
		{
			input: "v1.2.3",
			expect: VersionValue{
				SemVer: ptrfrom.String("1.2.3"),
				Raw:    "v1.2.3",
			},
		},
		{
			input: "v1.2",
			expect: VersionValue{
				// Should be 1.2.0 to be precise, but good enough for now
				SemVer: ptrfrom.String("1.2"),
				Raw:    "v1.2",
			},
		},
		{
			input: "v1.2.3-rc8",
			expect: VersionValue{
				SemVer: ptrfrom.String("1.2.3-rc8"),
				Raw:    "v1.2.3-rc8",
			},
		},
		{
			input: "v1.2.3rc8",
			expect: VersionValue{
				SemVer: ptrfrom.String("1.2.3-rc8"),
				Raw:    "v1.2.3rc8",
			},
		},
		{
			input: "1.2.3rc8",
			expect: VersionValue{
				SemVer: ptrfrom.String("1.2.3-rc8"),
				Raw:    "1.2.3rc8",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("parsing version value %s", tt.input), func(t *testing.T) {

			got := ParseVersionValue(tt.input)
			if diff := cmp.Diff(tt.expect, got); len(diff) > 0 {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

func Test_WhichVersionMatches(t *testing.T) {
	testCases := []struct {
		versions     []string
		versionRange string
		expect       map[string]bool
	}{
		{
			versionRange: "",
			versions:     []string{"0.0.0", "0.5", "1.0.0", "1.2.3", "1.2.3-rc8", "1.2.3rc8", "1.2", "anythingflies"},
			expect: map[string]bool{
				"0.0.0":         true,
				"0.5":           true,
				"1.0.0":         true,
				"1.2.3":         true,
				"1.2.3-rc8":     true,
				"1.2.3rc8":      true,
				"1.2":           true,
				"anythingflies": true,
			},
		},
		{
			versionRange: "<1.2.4-rc9",
			versions:     []string{"0.0.0", "0.5", "1.0.0", "1.2.3", "1.2.3-rc8", "1.2.3rc8", "1.2", "anythingflies"},
			expect: map[string]bool{
				"0.0.0":     true,
				"0.5":       true,
				"1.0.0":     true,
				"1.2.3":     true,
				"1.2":       true,
				"1.2.3-rc8": true,
				"1.2.3rc8":  true,
			},
		},
		{
			versionRange: "<1.2.3",
			versions:     []string{"0.0.0", "0.5", "1.0.0", "1.2.3", "1.2.4", "2.0", "1.2", "anythingflies"},
			expect: map[string]bool{
				"0.0.0": true,
				"0.5":   true,
				"1.0.0": true,
				"1.2":   true,
			},
		},
		{
			versionRange: ">=0.5,<1.2.4",
			versions:     []string{"0.0.0", "0.5", "1.0.0", "1.2.3", "1.2.4", "2.0", "1.2", "anythingflies"},
			expect: map[string]bool{
				"0.5":   true,
				"1.0.0": true,
				"1.2":   true,
				"1.2.3": true,
			},
		},
		{
			versionRange: "<1.0 || >1.2.3",
			versions:     []string{"0.0.0", "0.5", "1.0.0", "1.2.3", "1.2.4", "2.0", "1.2", "anythingflies"},
			expect: map[string]bool{
				"0.0.0": true,
				"0.5":   true,
				"1.2.4": true,
				"2.0":   true,
			},
		},
		{
			versionRange: "anythingflies",
			versions:     []string{"0.0.0", "0.5", "1.0.0", "1.2.3", "1.2.3-rc8", "1.2.3rc8", "1.2", "anythingflies"},
			expect: map[string]bool{
				"anythingflies": true,
			},
		},
		{
			versionRange: "=1.2.3-rc8",
			versions:     []string{"0.0.0", "0.5", "1.0.0", "1.2.3", "1.2.3-rc8", "1.2.3rc8", "1.2", "anythingflies"},
			expect: map[string]bool{
				"1.2.3-rc8": true,
				"1.2.3rc8":  true,
			},
		},
		{
			versionRange: "=1.2.3rc8",
			versions:     []string{"0.0.0", "0.5", "1.0.0", "1.2.3", "1.2.3-rc8", "1.2.3rc8", "1.2", "anythingflies"},
			expect: map[string]bool{
				"1.2.3-rc8": true,
				"1.2.3rc8":  true,
			},
		},
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("which version matches %s", tt.versionRange), func(t *testing.T) {
			got, err := WhichVersionMatches(tt.versions, tt.versionRange)
			if err != nil {
				t.Errorf("got err from WhichVersionMatches: %v", err)
				return
			}

			if diff := cmp.Diff(tt.expect, got); len(diff) > 0 {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}
