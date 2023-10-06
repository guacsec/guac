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

package inmem

import (
	"cmp"
	"slices"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// helper functions to canonically compare nodes

// this file is a duplicate of testhelpers_test.go -- pkg_test.go is in
// the inmem package, so it cannot use the definitions in testhelpers_test.go

////////////////////// comparison functions //////////////////////

func LessPackageQualifier(a, b *model.PackageQualifier) int {
	return cmp.Compare(a.Key+a.Value, b.Key+b.Value)
}

func LessPackageVersion(a, b *model.PackageVersion) int {
	if res := cmp.Compare(a.Version, b.Version); res != 0 {
		return res
	}
	if res := cmp.Compare(a.Subpath, b.Subpath); res != 0 {
		return res
	}

	for i := 0; i < len(a.Qualifiers); i++ {
		if res := LessPackageQualifier(a.Qualifiers[i], b.Qualifiers[i]); res != 0 {
			return res
		}
	}

	return 0
}
func LessName(a, b *model.PackageName) int {
	if res := cmp.Compare(a.Name, b.Name); res != 0 {
		return res
	}
	if res := len(a.Versions) - len(b.Versions); res != 0 {
		return res
	}

	for i := 0; i < len(a.Versions); i++ {
		if res := LessPackageVersion(a.Versions[i], b.Versions[i]); res != 0 {
			return res
		}
	}
	return 0
}
func LessNameSpace(a, b *model.PackageNamespace) int {
	if res := cmp.Compare(a.Namespace, b.Namespace); res != 0 {
		return res
	}
	if res := len(a.Names) - len(b.Names); res != 0 {
		return res
	}

	for i := 0; i < len(a.Names); i++ {
		if res := LessName(a.Names[i], b.Names[i]); res != 0 {
			return res
		}
	}
	return 0
}
func LessPackage(a, b *model.Package) int {
	if res := cmp.Compare(a.Type, b.Type); res != 0 {
		return res
	}
	if res := len(a.Namespaces) - len(b.Namespaces); res != 0 {
		return res
	}

	for i := 0; i < len(a.Namespaces); i++ {
		if res := LessNameSpace(a.Namespaces[i], b.Namespaces[i]); res != 0 {
			return res
		}
	}
	return 0
}
func LessPkgEquals(a, b *model.PkgEqual) int {
	aStr := a.Justification + a.Origin + a.Collector
	bStr := b.Justification + b.Origin + b.Collector

	if res := cmp.Compare(aStr, bStr); res != 0 {
		return res
	}
	if res := len(a.Packages) - len(b.Packages); res != 0 {
		return res
	}

	for i := 0; i < len(a.Packages); i++ {
		if res := LessPackage(a.Packages[i], b.Packages[i]); res != 0 {
			return res
		}
	}
	return 0
}

////////////////////// making canonical //////////////////////

func MakeCanonicalPkgEqualSlice(s []*model.PkgEqual) {
	for _, pe := range s {
		MakeCanonicalPkgEquals(pe)
	}
	slices.SortFunc(s, LessPkgEquals)
}

func MakeCanonicalPackageSlice(s []*model.Package) {
	for _, p := range s {
		MakeCanonicalPackage(p)
	}
	slices.SortFunc(s, LessPackage)
}

func MakeCanonicalPkgEquals(n *model.PkgEqual) {
	for _, child := range n.Packages {
		MakeCanonicalPackage(child)
	}
	slices.SortFunc(n.Packages, LessPackage)
}

func MakeCanonicalPackage(n *model.Package) {
	for _, child := range n.Namespaces {
		MakeCanonicalNamespace(child)
	}
	slices.SortFunc(n.Namespaces, LessNameSpace)
}

func MakeCanonicalNamespace(n *model.PackageNamespace) {
	for _, child := range n.Names {
		MakeCanonicalName(child)
	}
	slices.SortFunc(n.Names, LessName)
}

func MakeCanonicalName(n *model.PackageName) {
	for _, child := range n.Versions {
		MakeCanonicalPackageVersion(child)
	}
	slices.SortFunc(n.Versions, LessPackageVersion)
}

func MakeCanonicalPackageVersion(n *model.PackageVersion) {
	slices.SortFunc(n.Qualifiers, LessPackageQualifier)
}
