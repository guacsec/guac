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

package backend_test

import (
	"slices"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var (
	curTime            = time.Now()
	timeAfterOneSecond = curTime.Add(time.Second)
	testTime           = time.Unix(1e9+5, 0)
	testTime2          = time.Unix(1e9, 0)
	startTime          = time.Now()
	finishTime         = time.Now().Add(10 * time.Second)
	mAll               = model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}
	mSpecific          = model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}
)

var ignoreID = cmp.FilterPath(func(p cmp.Path) bool {
	return strings.Compare(".ID", p[len(p)-1].String()) == 0
}, cmp.Ignore())

var commonOpts = cmp.Options{
	ignoreID,
	cmpopts.EquateEmpty(),
	cmpopts.SortSlices(certifyVulnLess),
	cmpopts.SortSlices(certifyVexLess),
	cmpopts.SortSlices(vulnerabilityLess),
	cmpopts.SortSlices(lessVulnID),
	cmpopts.SortSlices(hasSbomLess),
	cmpopts.SortSlices(certifyLegalLess),
	cmpopts.SortSlices(lessBuilder),
	cmpopts.SortSlices(lessCG),
	cmpopts.SortSlices(lessLicense),
	cmpopts.SortSlices(lessSC),
	cmpopts.SortSlices(lessHE),
	cmpopts.SortSlices(lessHM),
	cmpopts.SortSlices(lessPackageOrArtifact),
	cmpopts.SortSlices(lessSLSAPred),
	cmpopts.SortSlices(lessHSA),
	cmpopts.SortSlices(lessIsDep),
	cmpopts.SortSlices(lessIsOcc),
	cmpopts.SortSlices(lessPE),
	cmpopts.SortSlices(lessPOC),
	cmpopts.SortSlices(lessVE),
	cmpopts.SortSlices(lessVM),
	cmpopts.EquateApproxTime(time.Millisecond),
	cmp.Comparer(depTypeCmp),
}

func depTypeCmp(a, b model.DependencyType) bool {
	ac := a
	bc := b
	if ac != model.DependencyTypeDirect && ac != model.DependencyTypeIndirect {
		ac = model.DependencyTypeUnknown
	}
	if bc != model.DependencyTypeDirect && bc != model.DependencyTypeIndirect {
		bc = model.DependencyTypeUnknown
	}
	return ac == bc
}

func certifyVexLess(e1, e2 *model.CertifyVEXStatement) bool {
	if e1.Vulnerability.VulnerabilityIDs[0].VulnerabilityID != e2.Vulnerability.VulnerabilityIDs[0].VulnerabilityID {
		return e1.Vulnerability.VulnerabilityIDs[0].VulnerabilityID < e2.Vulnerability.VulnerabilityIDs[0].VulnerabilityID
	}
	if e1.VexJustification != e2.VexJustification {
		return e1.VexJustification < e2.VexJustification
	}
	return false
}

func vulnerabilityLess(e1, e2 *model.Vulnerability) bool {
	return cmpVuln(e1, e2) < 0
}

func cmpVuln(a, b *model.Vulnerability) int {
	slices.SortFunc(a.VulnerabilityIDs, cmpVulnID)
	slices.SortFunc(b.VulnerabilityIDs, cmpVulnID)
	if d := slices.CompareFunc(a.VulnerabilityIDs, b.VulnerabilityIDs, cmpVulnID); d != 0 {
		return d
	}
	return strings.Compare(a.Type, b.Type)
}

func cmpVulnID(a, b *model.VulnerabilityID) int {
	return strings.Compare(a.VulnerabilityID, b.VulnerabilityID)
}

func lessVulnID(a, b *model.VulnerabilityID) bool {
	return cmpVulnID(a, b) < 0
}

func hasSbomLess(a, b *model.HasSbom) bool {
	if d := strings.Compare(a.URI, b.URI); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Algorithm, b.Algorithm); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Digest, b.Digest); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.DownloadLocation, b.DownloadLocation); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Origin, b.Origin); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Collector, b.Collector); d != 0 {
		return d < 0
	}
	if d := a.KnownSince.Compare(b.KnownSince); d != 0 {
		return d < 0
	}
	if len(a.IncludedSoftware) != len(b.IncludedSoftware) {
		return len(a.IncludedSoftware) < len(b.IncludedSoftware)
	}
	if len(a.IncludedDependencies) != len(b.IncludedDependencies) {
		return len(a.IncludedDependencies) < len(b.IncludedDependencies)
	}
	if len(a.IncludedOccurrences) != len(b.IncludedOccurrences) {
		return len(a.IncludedOccurrences) < len(b.IncludedOccurrences)
	}

	ap, oka := a.Subject.(*model.Package)
	bp, okb := b.Subject.(*model.Package)
	if oka && !okb {
		return false
	}
	if okb && !oka {
		return true
	}
	if oka && okb {
		return cmpPkg(ap, bp) < 0
	}
	aa := a.Subject.(*model.Artifact)
	ba := b.Subject.(*model.Artifact)
	return cmpArt(aa, ba) < 0
}

func certifyLegalLess(e1, e2 *model.CertifyLegal) bool {
	switch subject1 := e1.Subject.(type) {
	case *model.Package:
		switch subject2 := e2.Subject.(type) {
		case *model.Package:
			return cmpPkg(subject1, subject2) < 0
		case *model.Source:
			return false
		}
	case *model.Source:
		switch subject2 := e2.Subject.(type) {
		case *model.Package:
			return true
		case *model.Source:
			return cmpSrc(subject1, subject2) < 0
		}
	}
	return false
}

func lessBuilder(a, b *model.Builder) bool {
	return a.URI < b.URI
}

func lessCG(a, b *model.CertifyGood) bool {
	if d := strings.Compare(a.Justification, b.Justification); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Origin, b.Origin); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Collector, b.Collector); d != 0 {
		return d < 0
	}
	if d := a.KnownSince.Compare(b.KnownSince); d != 0 {
		return d < 0
	}
	ap, oka := a.Subject.(*model.Package)
	bp, okb := b.Subject.(*model.Package)
	if oka && !okb {
		return false
	}
	if okb && !oka {
		return true
	}
	if oka && okb {
		return cmpPkg(ap, bp) < 0
	}
	as, oka := a.Subject.(*model.Source)
	bs, okb := b.Subject.(*model.Source)
	if oka && !okb {
		return false
	}
	if okb && !oka {
		return true
	}
	if oka && okb {
		return cmpSrc(as, bs) < 0
	}
	aa := a.Subject.(*model.Artifact)
	ba := b.Subject.(*model.Artifact)
	return cmpArt(aa, ba) < 0
}

func lessLicense(a, b *model.License) bool {
	if d := strings.Compare(a.Name, b.Name); d != 0 {
		return d < 0
	}
	if a.Inline != nil && b.Inline == nil {
		return false
	}
	if b.Inline != nil && a.Inline == nil {
		return true
	}
	if a.Inline != nil && b.Inline != nil {
		return strings.Compare(*a.Inline, *b.Inline) < 0
	}
	if a.ListVersion != nil && b.ListVersion == nil {
		return false
	}
	if b.ListVersion != nil && a.ListVersion == nil {
		return true
	}
	if a.ListVersion != nil && b.ListVersion != nil {
		return strings.Compare(*a.ListVersion, *b.ListVersion) < 0
	}
	return false
}

func lessSC(a, b *model.CertifyScorecard) bool {
	if d := cmpSrc(a.Source, b.Source); d != 0 {
		return d < 0
	}
	if a.Scorecard.AggregateScore != b.Scorecard.AggregateScore {
		return a.Scorecard.AggregateScore < b.Scorecard.AggregateScore
	}
	if d := a.Scorecard.TimeScanned.Compare(b.Scorecard.TimeScanned); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Scorecard.ScorecardVersion, b.Scorecard.ScorecardVersion); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Scorecard.ScorecardCommit, b.Scorecard.ScorecardCommit); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Scorecard.Origin, b.Scorecard.Origin); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Scorecard.Collector, b.Scorecard.Collector); d != 0 {
		return d < 0
	}
	return false
}

func certifyVulnLess(a, b *model.CertifyVuln) bool {
	if d := cmpPkg(a.Package, b.Package); d != 0 {
		return d < 0
	}
	if d := cmpVuln(a.Vulnerability, b.Vulnerability); d != 0 {
		return d < 0
	}
	if d := a.Metadata.TimeScanned.Compare(b.Metadata.TimeScanned); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Metadata.DbURI, b.Metadata.DbURI); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Metadata.DbVersion, b.Metadata.DbVersion); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Metadata.ScannerURI, b.Metadata.ScannerURI); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Metadata.ScannerVersion, b.Metadata.ScannerVersion); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Metadata.Origin, b.Metadata.Origin); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Metadata.Collector, b.Metadata.Collector); d != 0 {
		return d < 0
	}
	return false
}

func lessHE(a, b *model.HashEqual) bool {
	slices.SortFunc(a.Artifacts, cmpArt)
	slices.SortFunc(b.Artifacts, cmpArt)
	if d := slices.CompareFunc(a.Artifacts, b.Artifacts, cmpArt); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Justification, b.Justification); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Origin, b.Origin); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Collector, b.Collector); d != 0 {
		return d < 0
	}
	return false
}

func lessVE(a, b *model.VulnEqual) bool {
	slices.SortFunc(a.Vulnerabilities, cmpVuln)
	slices.SortFunc(b.Vulnerabilities, cmpVuln)
	if d := slices.CompareFunc(a.Vulnerabilities, b.Vulnerabilities, cmpVuln); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Justification, b.Justification); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Origin, b.Origin); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Collector, b.Collector); d != 0 {
		return d < 0
	}
	return false
}

func lessHM(a, b *model.HasMetadata) bool {
	if d := strings.Compare(a.Key, b.Key); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Value, b.Value); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Justification, b.Justification); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Origin, b.Origin); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Collector, b.Collector); d != 0 {
		return d < 0
	}
	if d := a.Timestamp.Compare(b.Timestamp); d != 0 {
		return d < 0
	}
	ap, oka := a.Subject.(*model.Package)
	bp, okb := b.Subject.(*model.Package)
	if oka && !okb {
		return false
	}
	if okb && !oka {
		return true
	}
	if oka && okb {
		return cmpPkg(ap, bp) < 0
	}
	as, oka := a.Subject.(*model.Source)
	bs, okb := b.Subject.(*model.Source)
	if oka && !okb {
		return false
	}
	if okb && !oka {
		return true
	}
	if oka && okb {
		return cmpSrc(as, bs) < 0
	}
	aa := a.Subject.(*model.Artifact)
	ba := b.Subject.(*model.Artifact)
	return cmpArt(aa, ba) < 0
}

func lessHSA(a, b *model.HasSourceAt) bool {
	if d := cmpPkg(a.Package, b.Package); d != 0 {
		return d < 0
	}
	if d := cmpSrc(a.Source, b.Source); d != 0 {
		return d < 0
	}
	if d := a.KnownSince.Compare(b.KnownSince); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Justification, b.Justification); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Origin, b.Origin); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Collector, b.Collector); d != 0 {
		return d < 0
	}
	return false
}

func lessIsDep(a, b *model.IsDependency) bool {
	if d := cmpPkg(a.Package, b.Package); d != 0 {
		return d < 0
	}
	if d := cmpPkg(a.DependencyPackage, b.DependencyPackage); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.VersionRange, b.VersionRange); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Justification, b.Justification); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Origin, b.Origin); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Collector, b.Collector); d != 0 {
		return d < 0
	}
	return depTypeCmp(a.DependencyType, b.DependencyType)
}

func lessIsOcc(a, b *model.IsOccurrence) bool {
	ap, oka := a.Subject.(*model.Package)
	bp, okb := b.Subject.(*model.Package)
	if oka && !okb {
		return false
	}
	if okb && !oka {
		return true
	}
	if oka && okb {
		if d := cmpPkg(ap, bp); d != 0 {
			return d < 0
		}
	}
	if !oka && !okb {
		as := a.Subject.(*model.Source)
		bs := b.Subject.(*model.Source)
		if d := cmpSrc(as, bs); d != 0 {
			return d < 0
		}
	}
	if d := cmpArt(a.Artifact, b.Artifact); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Justification, b.Justification); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Origin, b.Origin); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Collector, b.Collector); d != 0 {
		return d < 0
	}
	return false
}

func lessPE(a, b *model.PkgEqual) bool {
	slices.SortFunc(a.Packages, cmpPkg)
	slices.SortFunc(b.Packages, cmpPkg)
	if d := slices.CompareFunc(a.Packages, b.Packages, cmpPkg); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Justification, b.Justification); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Origin, b.Origin); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Collector, b.Collector); d != 0 {
		return d < 0
	}
	return false
}

func lessPOC(a, b *model.PointOfContact) bool {
	if d := strings.Compare(a.Email, b.Email); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Info, b.Info); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Justification, b.Justification); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Origin, b.Origin); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Collector, b.Collector); d != 0 {
		return d < 0
	}
	if d := a.Since.Compare(b.Since); d != 0 {
		return d < 0
	}
	ap, oka := a.Subject.(*model.Package)
	bp, okb := b.Subject.(*model.Package)
	if oka && !okb {
		return false
	}
	if okb && !oka {
		return true
	}
	if oka && okb {
		return cmpPkg(ap, bp) < 0
	}
	as, oka := a.Subject.(*model.Source)
	bs, okb := b.Subject.(*model.Source)
	if oka && !okb {
		return false
	}
	if okb && !oka {
		return true
	}
	if oka && okb {
		return cmpSrc(as, bs) < 0
	}
	aa := a.Subject.(*model.Artifact)
	ba := b.Subject.(*model.Artifact)
	return cmpArt(aa, ba) < 0
}

func lessVM(a, b *model.VulnerabilityMetadata) bool {
	if d := cmpVuln(a.Vulnerability, b.Vulnerability); d != 0 {
		return d < 0
	}
	if d := strings.Compare(string(a.ScoreType), string(b.ScoreType)); d != 0 {
		return d < 0
	}
	if a.ScoreValue != b.ScoreValue {
		return a.ScoreValue < b.ScoreValue
	}
	if d := a.Timestamp.Compare(b.Timestamp); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Origin, b.Origin); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Collector, b.Collector); d != 0 {
		return d < 0
	}
	return false
}

func lessSLSAPred(a, b *model.SLSAPredicate) bool {
	if d := strings.Compare(a.Key, b.Key); d != 0 {
		return d < 0
	}
	if d := strings.Compare(a.Value, b.Value); d != 0 {
		return d < 0
	}
	return false
}

func lessPackageOrArtifact(a, b model.PackageOrArtifact) bool {
	return cmpPackageOrArtifact(a, b) < 0
}

func cmpPackageOrArtifact(a, b model.PackageOrArtifact) int {
	ap, oka := a.(*model.Package)
	bp, okb := b.(*model.Package)
	if oka && !okb {
		return -1
	}
	if okb && !oka {
		return 1
	}
	if oka && okb {
		return cmpPkg(ap, bp)
	}
	aa := a.(*model.Artifact)
	ba := b.(*model.Artifact)
	return cmpArt(aa, ba)
}
