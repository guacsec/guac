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

package helper

import (
	"fmt"
	"sort"
	"strings"

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

type SrcIds struct {
	TypeId      string
	NamespaceId string
	NameId      string
}

type VulnIds struct {
	TypeId          string
	VulnerabilityID string
}

func GuacArtifactKey(input *model.ArtifactInputSpec) string {
	return fmt.Sprintf("%s:%s", strings.ToLower(input.Algorithm), strings.ToLower(input.Digest))
}

func GuacLicenseKey(l *model.LicenseInputSpec) string {
	if l.ListVersion != nil && *l.ListVersion != "" {
		return strings.Join([]string{l.Name, *l.ListVersion}, ":")
	}
	return l.Name
}

func GuacPkgId(pkg model.PkgInputSpec) PkgIds {
	ids := PkgIds{}

	ids.TypeId = pkg.Type

	var ns string
	if pkg.Namespace != nil {
		if *pkg.Namespace != "" {
			ns = *pkg.Namespace
		} else {
			ns = guacEmpty
		}
	}
	ids.NamespaceId = fmt.Sprintf("%s::%s", ids.TypeId, ns)
	ids.NameId = fmt.Sprintf("%s::%s", ids.NamespaceId, pkg.Name)

	var version string
	if pkg.Version != nil {
		if *pkg.Version != "" {
			version = *pkg.Version
		} else {
			version = guacEmpty
		}
	}

	var subpath string
	if pkg.Subpath != nil {
		if *pkg.Subpath != "" {
			subpath = *pkg.Subpath
		} else {
			subpath = guacEmpty
		}
	}

	ids.VersionId = fmt.Sprintf("%s::%s::%s?", ids.NameId, version, subpath)

	qualifiersMap := map[string]string{}
	var keys []string
	for _, kv := range pkg.Qualifiers {
		qualifiersMap[kv.Key] = kv.Value
		keys = append(keys, kv.Key)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ids.VersionId += fmt.Sprintf("%s=%s&", k, qualifiersMap[k])
	}

	return ids
}

func GuacSrcId(src model.SourceInputSpec) SrcIds {
	ids := SrcIds{}

	ids.TypeId = src.Type

	var ns string
	if src.Namespace != "" {
		ns = src.Namespace
	} else {
		ns = guacEmpty
	}
	ids.NamespaceId = fmt.Sprintf("%s::%s", ids.TypeId, ns)

	var tag string
	if src.Tag != nil {
		if *src.Tag != "" {
			tag = *src.Tag
		} else {
			tag = guacEmpty
		}
	}

	var commit string
	if src.Commit != nil {
		if *src.Commit != "" {
			commit = *src.Commit
		} else {
			commit = guacEmpty
		}
	}

	ids.NameId = fmt.Sprintf("%s::%s::%s::%s?", ids.NamespaceId, src.Name, tag, commit)
	return ids
}

func GuacVulnId(vuln model.VulnerabilityInputSpec) VulnIds {
	ids := VulnIds{}
	ids.TypeId = strings.ToLower(vuln.Type)
	ids.VulnerabilityID = fmt.Sprintf("%s::%s", ids.TypeId, strings.ToLower(vuln.VulnerabilityID))
	return ids
}
