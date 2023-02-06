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

package neo4jBackend

import (
	"github.com/guacsec/guac/pkg/assembler"
)

// pkgNode represents the top level pkg->Type->Namespace->Name->Version
type pkgNode struct {
}

func (pn *pkgNode) Type() string {
	return "Pkg"
}

func (pn *pkgNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["pkg"] = "pkg"
	return properties
}

func (pn *pkgNode) PropertyNames() []string {
	fields := []string{"pkg"}
	return fields
}

func (pn *pkgNode) IdentifiablePropertyNames() []string {
	return []string{"pkg"}
}

type pkgType struct {
	pkgType string
}

func (pt *pkgType) Type() string {
	return "PkgType"
}

func (pt *pkgType) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["type"] = pt.pkgType
	return properties
}

func (pt *pkgType) PropertyNames() []string {
	fields := []string{"type"}
	return fields
}

func (pt *pkgType) IdentifiablePropertyNames() []string {
	return []string{"type"}
}

type pkgNamespace struct {
	namespace string
}

func (pn *pkgNamespace) Type() string {
	return "PkgNamespace"
}

func (pn *pkgNamespace) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["namespace"] = pn.namespace
	return properties
}

func (pn *pkgNamespace) PropertyNames() []string {
	fields := []string{"namespace"}
	return fields
}

func (pn *pkgNamespace) IdentifiablePropertyNames() []string {
	return []string{"namespace"}
}

type pkgName struct {
	name string
}

func (pn *pkgName) Type() string {
	return "PkgName"
}

func (pn *pkgName) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["name"] = pn.name
	return properties
}

func (pn *pkgName) PropertyNames() []string {
	fields := []string{"name"}
	return fields
}

func (pn *pkgName) IdentifiablePropertyNames() []string {
	return []string{"name"}
}

type pkgVersion struct {
	version   string
	qualifier map[string]interface{}
	subpath   string
}

func (pv *pkgVersion) Type() string {
	return "PkgVersion"
}

func (pv *pkgVersion) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["version"] = pv.version
	properties["subpath"] = pv.subpath
	for k, v := range pv.qualifier {
		properties[k] = v
	}
	return properties
}

func (pv *pkgVersion) PropertyNames() []string {
	fields := []string{"version", "subpath"}
	for k := range pv.qualifier {
		fields = append(fields, k)
	}
	return fields
}

func (pv *pkgVersion) IdentifiablePropertyNames() []string {
	fields := []string{"version", "subpath"}
	for k := range pv.qualifier {
		fields = append(fields, k)
	}
	return fields
}

type pkgToType struct {
	pkg     *pkgNode
	pkgType *pkgType
}

func (e *pkgToType) Type() string {
	return "PkgHasType"
}

func (e *pkgToType) Nodes() (v, u assembler.GuacNode) {
	return e.pkg, e.pkgType
}

func (e *pkgToType) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *pkgToType) PropertyNames() []string {
	return []string{}
}

func (e *pkgToType) IdentifiablePropertyNames() []string {
	return []string{}
}

type typeToNamespace struct {
	pkgType   *pkgType
	namespace *pkgNamespace
}

func (e *typeToNamespace) Type() string {
	return "PkgHasNamespace"
}

func (e *typeToNamespace) Nodes() (v, u assembler.GuacNode) {
	return e.pkgType, e.namespace
}

func (e *typeToNamespace) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *typeToNamespace) PropertyNames() []string {
	return []string{}
}

func (e *typeToNamespace) IdentifiablePropertyNames() []string {
	return []string{}
}

type namespaceToName struct {
	namespace *pkgNamespace
	name      *pkgName
}

func (e *namespaceToName) Type() string {
	return "PkgHasName"
}

func (e *namespaceToName) Nodes() (v, u assembler.GuacNode) {
	return e.namespace, e.name
}

func (e *namespaceToName) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *namespaceToName) PropertyNames() []string {
	return []string{}
}

func (e *namespaceToName) IdentifiablePropertyNames() []string {
	return []string{}
}

type nameToVersion struct {
	name    *pkgName
	version *pkgVersion
}

func (e *nameToVersion) Type() string {
	return "PkgHasVersion"
}

func (e *nameToVersion) Nodes() (v, u assembler.GuacNode) {
	return e.name, e.version
}

func (e *nameToVersion) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *nameToVersion) PropertyNames() []string {
	return []string{}
}

func (e *nameToVersion) IdentifiablePropertyNames() []string {
	return []string{}
}
