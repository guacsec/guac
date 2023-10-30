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

//go:build integration

package backend

import (
	"reflect"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

func ptr[T any](s T) *T {
	return &s
}

var ignoreID = cmp.FilterPath(func(p cmp.Path) bool {
	return strings.Compare(".ID", p[len(p)-1].String()) == 0
}, cmp.Ignore())

var ignoreEmptySlices = cmp.FilterValues(func(x, y interface{}) bool {
	xv, yv := reflect.ValueOf(x), reflect.ValueOf(y)
	if xv.Kind() == reflect.Slice && yv.Kind() == reflect.Slice {
		return xv.Len() == 0 && yv.Len() == 0
	}
	return false
}, cmp.Ignore())

var IngestPredicatesCmpOpts = []cmp.Option{
	ignoreID,
	cmpopts.EquateEmpty(),
	cmpopts.SortSlices(isDependencyLess),
	cmpopts.SortSlices(packageLess),
	cmpopts.SortSlices(certifyVulnLess),
}

func isDependencyLess(e1, e2 *model.IsDependency) bool {
	return packageLess(e1.Package, e2.Package)
}

func packageLess(e1, e2 *model.Package) bool {
	purl1 := helpers.PkgToPurl(e1.Type, e1.Namespaces[0].Namespace, e1.Namespaces[0].Names[0].Name, e1.Namespaces[0].Names[0].Versions[0].Version, e1.Namespaces[0].Names[0].Versions[0].Subpath, nil)
	purl2 := helpers.PkgToPurl(e2.Type, e2.Namespaces[0].Namespace, e2.Namespaces[0].Names[0].Name, e2.Namespaces[0].Names[0].Versions[0].Version, e2.Namespaces[0].Names[0].Versions[0].Subpath, nil)
	return purl1 < purl2
}

func certifyVulnLess(e1, e2 *model.CertifyVuln) bool {
	return packageLess(e1.Package, e2.Package)
}
