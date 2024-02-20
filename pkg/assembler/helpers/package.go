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

package helpers

import (
	"fmt"
	"sort"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	guacEmpty string = "guac-empty-@@"
)

type PkgIds struct {
	TypeId      string
	NamespaceId string
	NameId      string
	VersionId   string
}

func PkgServerKey(pkg *model.PkgInputSpec) PkgIds {
	qualifiersMap := map[string]string{}
	var keys []string
	for _, kv := range pkg.Qualifiers {
		qualifiersMap[kv.Key] = kv.Value
		keys = append(keys, kv.Key)
	}
	return guacPkgId(pkg.Type, pkg.Namespace, pkg.Name, pkg.Version, qualifiersMap, keys, pkg.Subpath)
}

func PkgClientKey(pkg *generated.PkgInputSpec) PkgIds {
	qualifiersMap := map[string]string{}
	var keys []string
	for _, kv := range pkg.Qualifiers {
		qualifiersMap[kv.Key] = kv.Value
		keys = append(keys, kv.Key)
	}
	return guacPkgId(pkg.Type, pkg.Namespace, pkg.Name, pkg.Version, qualifiersMap, keys, pkg.Subpath)
}

func guacPkgId(pkgType string, namespace *string, name string, pkgVersion *string, qualifiersMap map[string]string, qualifierKeys []string, pkgSubpath *string) PkgIds {
	ids := PkgIds{}

	ids.TypeId = pkgType

	var ns string
	if namespace != nil {
		if *namespace != "" {
			ns = *namespace
		} else {
			ns = guacEmpty
		}
	}
	ids.NamespaceId = fmt.Sprintf("%s::%s", ids.TypeId, ns)
	ids.NameId = fmt.Sprintf("%s::%s", ids.NamespaceId, name)

	var version string
	if pkgVersion != nil {
		if *pkgVersion != "" {
			version = *pkgVersion
		} else {
			version = guacEmpty
		}
	}

	var subpath string
	if pkgSubpath != nil {
		if *pkgSubpath != "" {
			subpath = *pkgSubpath
		} else {
			subpath = guacEmpty
		}
	}

	ids.VersionId = fmt.Sprintf("%s::%s::%s?", ids.NameId, version, subpath)

	sort.Strings(qualifierKeys)
	for _, k := range qualifierKeys {
		ids.VersionId += fmt.Sprintf("%s=%s&", k, qualifiersMap[k])
	}

	return ids
}
