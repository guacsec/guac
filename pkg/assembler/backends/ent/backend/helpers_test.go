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

package backend

import (
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

var ignoreID = cmp.FilterPath(func(p cmp.Path) bool {
	return strings.Compare(".ID", p[len(p)-1].String()) == 0
}, cmp.Ignore())

var IngestPredicatesCmpOpts = []cmp.Option{
	ignoreID,
	cmpopts.EquateEmpty(),
	cmpopts.SortSlices(isDependencyLess),
	cmpopts.SortSlices(packageLess),
	cmpopts.SortSlices(sourceLess),
	cmpopts.SortSlices(certifyVulnLess),
	cmpopts.SortSlices(certifyVexLess),
	cmpopts.SortSlices(vulnerabilityLess),
	cmpopts.SortSlices(hasSbomLess),
	cmpopts.SortSlices(certifyLegalLess),
}

func isDependencyLess(e1, e2 *model.IsDependency) bool {
	return packageLess(e1.Package, e2.Package)
}

func packageLess(e1, e2 *model.Package) bool {
	purl1 := helpers.PkgToPurl(e1.Type, e1.Namespaces[0].Namespace, e1.Namespaces[0].Names[0].Name, e1.Namespaces[0].Names[0].Versions[0].Version, e1.Namespaces[0].Names[0].Versions[0].Subpath, nil)
	purl2 := helpers.PkgToPurl(e2.Type, e2.Namespaces[0].Namespace, e2.Namespaces[0].Names[0].Name, e2.Namespaces[0].Names[0].Versions[0].Version, e2.Namespaces[0].Names[0].Versions[0].Subpath, nil)
	return purl1 < purl2
}

func sourceLess(e1, e2 *model.Source) bool {
	purl1 := helpers.PkgToPurl(e1.Type, e1.Namespaces[0].Namespace, e1.Namespaces[0].Names[0].Name, "", "", nil)
	purl2 := helpers.PkgToPurl(e2.Type, e2.Namespaces[0].Namespace, e2.Namespaces[0].Names[0].Name, "", "", nil)
	return purl1 < purl2
}

func certifyVulnLess(e1, e2 *model.CertifyVuln) bool {
	return packageLess(e1.Package, e2.Package)
}

func certifyVexLess(e1, e2 *model.CertifyVEXStatement) bool {
	return e1.Vulnerability.VulnerabilityIDs[0].VulnerabilityID < e2.Vulnerability.VulnerabilityIDs[0].VulnerabilityID
}

func vulnerabilityLess(e1, e2 *model.Vulnerability) bool {
	e1String := e1.Type
	if len(e1.VulnerabilityIDs) > 0 {
		e1String += e1.VulnerabilityIDs[0].VulnerabilityID
	}
	e2String := e1.Type
	if len(e2.VulnerabilityIDs) > 0 {
		e2String += e2.VulnerabilityIDs[0].VulnerabilityID
	}
	return e1String < e2String
}

func hasSbomLess(e1, e2 *model.HasSbom) bool {
	switch subject1 := e1.Subject.(type) {
	case *model.Package:
		switch subject2 := e2.Subject.(type) {
		case *model.Package:
			return packageLess(subject1, subject2)
		case *model.Artifact:
			return false
		}
	case *model.Artifact:
		switch subject2 := e2.Subject.(type) {
		case *model.Package:
			return true
		case *model.Artifact:
			return subject1.Digest < subject2.Digest
		}
	}
	return false
}

func certifyLegalLess(e1, e2 *model.CertifyLegal) bool {
	switch subject1 := e1.Subject.(type) {
	case *model.Package:
		switch subject2 := e2.Subject.(type) {
		case *model.Package:
			return packageLess(subject1, subject2)
		case *model.Source:
			return false
		}
	case *model.Source:
		switch subject2 := e2.Subject.(type) {
		case *model.Package:
			return true
		case *model.Source:
			return sourceLess(subject1, subject2)
		}
	}
	return false
}
