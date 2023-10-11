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
	"regexp"
	"strconv"
	"strings"

	version "github.com/Masterminds/semver"
)

var (
	errNoConstraintFound = fmt.Errorf("no constraint found")
)

type VersionValue struct {
	SemVer *string
	Raw    string
}

type VersionMatchObject struct {
	VRSet []VersionRange
	// Exact used in the case where heuristics can't determine semvers
	Exact *string
	All   bool
}

func WhichVersionMatches(versions []string, versionRange string) (map[string]bool, error) {
	matchedVersions := map[string]bool{}
	vmo, err := ParseVersionRange(versionRange)
	if err != nil {
		return nil, fmt.Errorf("unable to parse ver range: %w", err)
	}

	for _, v := range versions {
		vv := ParseVersionValue(v)
		if vmo.Match(vv) {
			matchedVersions[v] = true
		}
	}

	return matchedVersions, nil
}

func (vmo *VersionMatchObject) Match(v VersionValue) bool {
	if vmo.All {
		return true
	}

	if vmo.Exact != nil {
		return v.Raw == *vmo.Exact
	}

	// else do a semver compare
	vstr := v.Raw
	if v.SemVer != nil {
		vstr = *v.SemVer
	}

	vcmp, err := version.NewVersion(vstr)
	if err != nil {
		// cant match
		return false
	}

	for _, vr := range vmo.VRSet {
		constraints, err := version.NewConstraint(vr.Constraint)
		if err != nil {
			continue
		}
		if constraints.Check(vcmp) {
			return true
		}
	}
	return false
}

func ParseVersionValue(s string) VersionValue {

	vv := VersionValue{Raw: s}

	if isSemver(s) {
		semver, _, _, _, _, _, err := parseSemver(s)
		if err != nil {
			return vv
		}

		vv.SemVer = &semver
		return vv
	} else if almostSemVer(s) {
		fixedS, err := fixAlmostSemVer(s)
		if err != nil {
			return vv
		}
		semver, _, _, _, _, _, err := parseSemver(fixedS)
		if err != nil {
			return vv
		}

		vv.SemVer = &semver
		return vv
	}

	return vv
}

// formatting issues are handled in WhichVersionMatches, errors not expected to be thrown
func DoesRangeInclude(versions []string, versionRange string) (bool, error) {
	versionMap, err := WhichVersionMatches(versions, versionRange)

	if err != nil {
		return false, fmt.Errorf("error for DoesRangeInclude %v", err)
	}

	for len(versionMap) > 0 {
		return true, nil
	}

	return false, nil
}

type VersionRange struct {
	Constraint string
}

// func vrange(ss ...string) VersionMatchObject {
// 	var vrSet []VersionRange
// 	for _, s := range ss {
// 		vrSet = append(vrSet, VersionRange{Constraint: s})
// 	}

// 	return VersionMatchObject{
// 		VRSet: vrSet,
// 	}
// }

// range regular expression
// doing [{semver},{semver}] `[\[\(]{1}` + svR + `,` + svR + `[\]\)]{1}`
var rangeRegexp = regexp.MustCompile(`[\[\(]{1}(v?(?P<semver1>(?P<major1>0|[1-9]\d*)(\.(?P<minor1>0|[1-9]\d*))?(\.(?P<patch1>0|[1-9]\d*))?(?:-(?P<prerelease1>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata1>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)?),\s*(v?(?P<semver2>(?P<major2>0|[1-9]\d*)(\.(?P<minor2>0|[1-9]\d*))?(\.(?P<patch2>0|[1-9]\d*))?(?:-(?P<prerelease2>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata2>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)?)[\]\)]{1}`)

// check for exac semvers
var exactSvR = regexp.MustCompile(`^v?(?P<semver>(?P<major>0|[1-9]\d*)(\.(?P<minor>0|[1-9]\d*))?(\.(?P<patch>0|[1-9]\d*))?(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)$`)

// check for 1.x or 1.0.x cases
var exactSvRWithWildcard = regexp.MustCompile(`^v?(?P<semver>(?P<major>0|[1-9]\d*)(\.(?P<minor>x|0|[1-9]\d*))?(\.(?P<patch>0|x|[1-9]\d*))?(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)$`)

// for bad semvers like v1.0.0rc8 that don't include prerelease dashes
var almostExactSvR = regexp.MustCompile(`^v?(?P<beforerel>(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*))(?P<afterrel>(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)$`)

// Regexp that checks for constraints such as ">1.0" and ">=2.3,<3.0"
var validConstraint = regexp.MustCompile(`^[><~^=]{1,3}v?(?P<semver1>(?P<major1>0|[1-9]\d*)(\.(?P<minor1>0|[1-9]\d*))?(\.(?P<patch1>0|[1-9]\d*))?(?:-(?P<prerelease1>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata1>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)([,\s]?[><~^=]{1,3}v?(?P<semver2>(?P<major2>0|[1-9]\d*)(\.(?P<minor2>0|[1-9]\d*))?(\.(?P<patch2>0|[1-9]\d*))?(?:-(?P<prerelease2>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata2>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?))?$`)

// Regexp that checks for constraints where semvers are malformed around the prerelease like v1.0.0rc8
var almostValidConstraint = regexp.MustCompile(`^(?P<op1>[><~^=]{1,3})v?(?P<semver1>(?P<major1>0|[1-9]\d*)(\.(?P<minor1>0|[1-9]\d*))?(\.(?P<patch1>0|[1-9]\d*))?(?:-?(?P<prerelease1>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata1>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)([,\s]?(?P<op2>[><~^=]{1,3})v?(?P<semver2>(?P<major2>0|[1-9]\d*)(\.(?P<minor2>0|[1-9]\d*))?(\.(?P<patch2>0|[1-9]\d*))?(?:-?(?P<prerelease2>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata2>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?))?$`)

// checks for rnages in the form 1.0.0 - 3.9.9
var dashRangeRegexp = regexp.MustCompile(`(v?(?P<semver1>(?P<major1>0|[1-9]\d*)(\.(?P<minor1>0|[1-9]\d*))?(\.(?P<patch1>0|[1-9]\d*))?(?:-(?P<prerelease1>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata1>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)?)\s\s*-\s*(v?(?P<semver2>(?P<major2>0|[1-9]\d*)(\.(?P<minor2>0|[1-9]\d*))?(\.(?P<patch2>0|[1-9]\d*))?(?:-(?P<prerelease2>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata2>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)?)`)

func almostSemVer(s string) bool {
	return !exactSvR.MatchString(s) && almostExactSvR.MatchString(s)
}

func fixAlmostSemVer(s string) (string, error) {
	matches := almostExactSvR.FindStringSubmatch(s)
	if len(matches) == 0 {
		return "", fmt.Errorf("Did not match AlmostSemVer: %q", s)
	}
	return fmt.Sprintf("%s-%s", matches[almostExactSvR.SubexpIndex("beforerel")], matches[almostExactSvR.SubexpIndex("afterrel")]), nil
}

func isSemver(s string) bool {
	return exactSvR.MatchString(s)
}

func isSemVerWildcard(s string) bool {
	return !exactSvR.MatchString(s) && exactSvRWithWildcard.MatchString(s)
}

func isValidConstraint(s string) bool {
	return validConstraint.MatchString(s)
}

func isAlmostValidConstraint(s string) bool {
	return almostValidConstraint.MatchString(s)
}

func isDashRange(s string) bool {
	return dashRangeRegexp.MatchString(s)
}

func ParseVersionRange(s string) (VersionMatchObject, error) {
	if s == "" {
		return VersionMatchObject{All: true}, nil
	}

	if s == "latest" {
		return VersionMatchObject{All: true}, nil
	}

	// Handle split for "||"s
	ss := strings.Split(s, "||")
	var vrSet []VersionRange
	for _, s := range ss {

		s = sanitize(s)
		if len(s) == 0 {
			continue
		}

		c, err := getConstraint(s)
		// if no constraint found and just 1 single string, return exact match
		if err == errNoConstraintFound && len(ss) == 1 {
			return VersionMatchObject{
				Exact: &s,
			}, nil
		} else if err != nil {
			return VersionMatchObject{}, fmt.Errorf("unable to parse constraint: %v", err)
		}
		vrSet = append(vrSet, VersionRange{Constraint: c})
	}

	return VersionMatchObject{
		VRSet: vrSet,
	}, nil
}

func sanitize(s string) string {
	return strings.TrimSpace(s)
}

func parseWildcardSemver(s string) (semver, major, minor, patch, prerelease, metadata string, err error) {
	return parseSemverHelper(exactSvRWithWildcard, s)
}

func parseSemver(s string) (semver, major, minor, patch, prerelease, metadata string, err error) {
	return parseSemverHelper(exactSvR, s)
}

func parseSemverHelper(re *regexp.Regexp, s string) (semver, major, minor, patch, prerelease, metadata string, err error) {
	matches := re.FindStringSubmatch(s)

	if len(matches) == 0 {
		err = fmt.Errorf("did not match regex: %q %s", s, re)
		return
	}
	semverIdx := re.SubexpIndex("semver")
	majorIdx := re.SubexpIndex("major")
	minorIdx := re.SubexpIndex("minor")
	patchIdx := re.SubexpIndex("patch")
	prereleaseIdx := re.SubexpIndex("prerelease")
	metadataIdx := re.SubexpIndex("metadata")

	if semverIdx < 0 {
		err = fmt.Errorf("unable to find semver")
		return
	}

	semver = matches[re.SubexpIndex("semver")]
	if semver == "" {
		err = fmt.Errorf("unable to find semver")
		return
	}

	if majorIdx < 0 {
		major = "0"
	} else {
		major = matches[majorIdx]
	}

	if minorIdx < 0 {
		minor = "0"
	} else {
		minor = matches[minorIdx]
		if minor == "" {
			minor = "0"
		}
	}

	if patchIdx < 0 {
		patch = "0"
	} else {
		patch = matches[patchIdx]
		if patch == "" {
			patch = "0"
		}
	}

	if prereleaseIdx < 0 {
		prerelease = ""
	} else {
		prerelease = matches[prereleaseIdx]
	}

	if metadataIdx < 0 {
		metadata = ""
	} else {
		metadata = matches[metadataIdx]
	}
	return
}

func getConstraint(s string) (string, error) {
	// TODO Check other unhandled cases like "~=", "^="

	if isSemver(s) {
		semver, _, _, _, _, _, err := parseSemver(s)
		if err != nil {
			return "", fmt.Errorf("unable to parse semver: %v", err)
		}
		return "=" + semver, nil
	} else if almostSemVer(s) {
		s, err := fixAlmostSemVer(s)
		if err != nil {
			return "", err
		}
		return "=" + s, nil
	}

	// ignoring the tilde for the wildcard check
	wildcardVersion := strings.TrimPrefix(s, "~")
	// ignoring the ^ for the wildcard check, but using it during the parsing
	wildcardVersion = strings.TrimPrefix(wildcardVersion, "^")

	// check for 1.x minor and patch versions
	if isSemVerWildcard(wildcardVersion) {
		if strings.HasPrefix(s, "^") {
			split := strings.Split(wildcardVersion, ".")
			if len(split) == 3 {
				wildcardVersion = fmt.Sprintf("%s.%s", split[0], split[2])
			}
		}

		_, major, minor, _, _, _, err := parseWildcardSemver(wildcardVersion)
		if err != nil {
			return "", fmt.Errorf("unable to parse semver with wildcard: %v", err)
		}

		constraint := ""
		if minor == "x" {
			constraint += fmt.Sprintf(">=%s.%s.%s,<%s.%s.%s",
				major, "0", "0",
				plusOne(major), "0", "0")
		} else {
			// assume wildcard on patch
			constraint += fmt.Sprintf(">=%s.%s.%s,<%s.%s.%s",
				major, minor, "0",
				major, plusOne(minor), "0")
		}
		return constraint, nil
	}

	// NPM ^ for major versions
	if strings.HasPrefix(s, "^") {
		version := strings.TrimPrefix(s, "^")
		semver, major, _, _, _, _, err := parseSemver(version)
		if err != nil {
			return "", fmt.Errorf("unable to parse semver %v", err)
		}

		constraint := fmt.Sprintf(">=%v,<%s.%s.%s", semver, plusOne(major), "0", "0")
		return constraint, nil
	}

	// NPM ~ for minor version
	if strings.HasPrefix(s, "~") {
		version := strings.TrimPrefix(s, "~")
		semver, major, minor, _, _, _, err := parseSemver(version)
		if err != nil {
			return "", fmt.Errorf("unable to parse semver %v", err)
		}

		constraint := fmt.Sprintf(">=%v,<%s.%s.%s", semver, major, plusOne(minor), "0")
		return constraint, nil
	}

	// check if its java ranges
	if rangeRegexp.MatchString(s) {
		matches := rangeRegexp.FindStringSubmatch(s)
		semver1Idx := rangeRegexp.SubexpIndex("semver1")
		semver2Idx := rangeRegexp.SubexpIndex("semver2")

		constraint := ""
		if strings.HasPrefix(s, "[") {
			constraint += ">="
		} else {
			constraint += ">"
		}

		if v := matches[semver1Idx]; len(v) > 0 {
			constraint += v
		} else {
			constraint += "0"
		}

		// if no upper bound no additional constraint required
		if v := matches[semver2Idx]; len(v) > 0 {
			constraint += ","
			if strings.HasSuffix(s, "]") {
				constraint += "<="
			} else {
				constraint += "<"
			}
			constraint += v
		}

		return constraint, nil
	}

	if isValidConstraint(s) {
		return strings.ReplaceAll(s, " ", ","), nil
	}

	if isAlmostValidConstraint(s) {
		//s = strings.ReplaceAll(s, " ", ",")
		matches := almostValidConstraint.FindStringSubmatch(s)
		semver1Idx := almostValidConstraint.SubexpIndex("semver1")
		op1Idx := almostValidConstraint.SubexpIndex("op1")
		semver2Idx := almostValidConstraint.SubexpIndex("semver2")
		op2Idx := almostValidConstraint.SubexpIndex("op2")

		if semver1Idx < 0 {
			return "", fmt.Errorf("expected semver1 in almost valid constraint")
		}

		if op1Idx < 0 {
			return "", fmt.Errorf("expected op1 in almost valid constraint")
		}

		op1 := matches[op1Idx]
		semver1, err := fixAlmostSemVer(matches[semver1Idx])
		if err != nil {
			return "", err
		}
		constraint := op1 + semver1

		if op2Idx >= 0 {
			op2 := matches[op2Idx]
			if op2 != "" {
				if semver2Idx < 0 {
					return "", fmt.Errorf("expected semver2 in almost valid constraint with op2")
				}

				semver2 := matches[semver2Idx]
				constraint += "," + op2 + semver2
			}
		}
		return constraint, nil

	}

	if isDashRange(s) {
		matches := dashRangeRegexp.FindStringSubmatch(s)
		semver1Idx := dashRangeRegexp.SubexpIndex("semver1")
		semver2Idx := dashRangeRegexp.SubexpIndex("semver2")
		constraint := fmt.Sprintf(">=%s,<=%s", matches[semver1Idx], matches[semver2Idx])
		return constraint, nil
	}

	return "", errNoConstraintFound
}

func plusOne(s string) string {
	i, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return strconv.Itoa(i + 1)
}
