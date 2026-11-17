//
// Copyright 2026 The GUAC Authors.
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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// rangeSeeds covers the npm, Maven and SemVer range styles that
// ParseVersionRange understands, taken from the unit tests.
var rangeSeeds = []string{
	"",
	"latest",
	"1.7.21",
	"<2.0,>=0.12",
	">=1.0.0",
	">=1.0.0rc8",
	">=v1.0.0rc8",
	"[1.5.0,1.7.0]",
	"[1.5.0,)",
	"(,2.0)",
	"[3.0,)",
	"^0.11",
	"^1",
	"^1.0.25",
	"^3.0.0 || ^4.0.0",
	"^1.0.x",
	"^1.x",
	"^1.3.x",
	"v0.0.0-20190603091049-60506f45cf65",
	"1.0.0 - 2.9999.9999",
	">=1.0.2 <2.1.2",
	">1.0.2 <=2.3.4",
	"<1.0.0 || >=2.3.1 <2.4.5 || >=2.5.2 <3.0.0",
	"http://asdf.com/asdf.tar.gz",
	"~1.2",
	"~1.2.3",
	"2.x",
	"3.3.x",
	"~0.10.x",
	"file:../dyl",
	"||",
	// version numbers too large for an int
	"^99999999999999999999",
	"~1.99999999999999999999",
	"99999999999999999999.x",
}

// versionSeeds covers valid, almost valid and invalid version strings.
var versionSeeds = []string{
	"",
	"0.0.0",
	"0.5",
	"1.2.3",
	"v1.2.3",
	"v1.2",
	"v1.2.3-rc8",
	"v1.2.3rc8",
	"1.2.3rc8",
	"1.2.3+build.1",
	"anythingflies",
}

func FuzzParseVersionRange(f *testing.F) {
	for _, s := range rangeSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseVersionRange(s)

		// The same input must always give the same result.
		again, err2 := ParseVersionRange(s)
		if (err == nil) != (err2 == nil) {
			t.Fatalf("ParseVersionRange(%q) returned different errors: %v and %v", s, err, err2)
		}
		if diff := cmp.Diff(got, again); diff != "" {
			t.Fatalf("ParseVersionRange(%q) is not deterministic (-first +second):\n%s", s, diff)
		}

		if err != nil {
			return
		}

		// A successful result must describe exactly one kind of match.
		kinds := 0
		if got.All {
			kinds++
		}
		if got.Exact != nil {
			kinds++
		}
		if len(got.VRSet) > 0 {
			kinds++
		}
		if kinds > 1 {
			t.Fatalf("ParseVersionRange(%q) set more than one match kind: %+v", s, got)
		}
		for _, vr := range got.VRSet {
			if vr.Constraint == "" {
				t.Fatalf("ParseVersionRange(%q) returned an empty constraint", s)
			}
		}

		// Matching against any version must not panic.
		for _, v := range versionSeeds {
			got.Match(ParseVersionValue(v))
		}
	})
}

func FuzzParseVersionValue(f *testing.F) {
	for _, s := range versionSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		got := ParseVersionValue(s)

		if got.Raw != s {
			t.Fatalf("ParseVersionValue(%q).Raw = %q, want the input unchanged", s, got.Raw)
		}
		if diff := cmp.Diff(got, ParseVersionValue(s)); diff != "" {
			t.Fatalf("ParseVersionValue(%q) is not deterministic (-first +second):\n%s", s, diff)
		}

		if got.SemVer == nil {
			return
		}
		// A normalized semver must itself be a valid semver, and
		// normalizing it again must not change it.
		if !isSemver(*got.SemVer) {
			t.Fatalf("ParseVersionValue(%q).SemVer = %q, which is not a valid semver", s, *got.SemVer)
		}
		if again := ParseVersionValue(*got.SemVer); again.SemVer == nil || *again.SemVer != *got.SemVer {
			t.Fatalf("ParseVersionValue is not stable for %q: %q then %v", s, *got.SemVer, again.SemVer)
		}
	})
}

func FuzzWhichVersionMatches(f *testing.F) {
	for _, r := range rangeSeeds {
		f.Add(strings.Join(versionSeeds, "\n"), r)
	}

	f.Fuzz(func(t *testing.T, versionList, versionRange string) {
		versions := strings.Split(versionList, "\n")

		matched, err := WhichVersionMatches(versions, versionRange)
		included, err2 := DoesRangeInclude(versions, versionRange)

		if (err == nil) != (err2 == nil) {
			t.Fatalf("WhichVersionMatches and DoesRangeInclude disagree on errors for %q: %v and %v", versionRange, err, err2)
		}
		if err != nil {
			return
		}

		if included != (len(matched) > 0) {
			t.Fatalf("DoesRangeInclude = %v but WhichVersionMatches found %d matches for %q", included, len(matched), versionRange)
		}
		inInput := make(map[string]bool, len(versions))
		for _, v := range versions {
			inInput[v] = true
		}
		for v := range matched {
			if !inInput[v] {
				t.Fatalf("WhichVersionMatches returned %q, which was not in the input", v)
			}
		}
	})
}
