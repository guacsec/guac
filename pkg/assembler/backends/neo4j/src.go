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

// scrNode represents the top level src->Type->Namespace->Name
type srcNode struct {
}

func (sn *srcNode) Type() string {
	return "Src"
}

func (sn *srcNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["src"] = "src"
	return properties
}

func (sn *srcNode) PropertyNames() []string {
	fields := []string{"src"}
	return fields
}

func (sn *srcNode) IdentifiablePropertyNames() []string {
	return []string{"src"}
}

type srcType struct {
	srcType string
}

func (st *srcType) Type() string {
	return "SrcType"
}

func (st *srcType) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["type"] = st.srcType
	return properties
}

func (st *srcType) PropertyNames() []string {
	fields := []string{"type"}
	return fields
}

func (st *srcType) IdentifiablePropertyNames() []string {
	return []string{"type"}
}

type srcNamespace struct {
	namespace string
}

func (sn *srcNamespace) Type() string {
	return "SrcNamespace"
}

func (sn *srcNamespace) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["namespace"] = sn.namespace
	return properties
}

func (sn *srcNamespace) PropertyNames() []string {
	fields := []string{"namespace"}
	return fields
}

func (sn *srcNamespace) IdentifiablePropertyNames() []string {
	return []string{"namespace"}
}

type srcName struct {
	name   string
	tag    string
	commit string
}

func (sn *srcName) Type() string {
	return "SrcName"
}

func (sn *srcName) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["name"] = sn.name
	properties["tag"] = sn.tag
	properties["commit"] = sn.commit
	return properties
}

func (sn *srcName) PropertyNames() []string {
	fields := []string{"name", "tag", "commit"}
	return fields
}

func (sn *srcName) IdentifiablePropertyNames() []string {
	return []string{"name", "tag", "commit"}
}

type srcToType struct {
	src     *srcNode
	srcType *srcType
}

func (e *srcToType) Type() string {
	return "SrcHasType"
}

func (e *srcToType) Nodes() (v, u assembler.GuacNode) {
	return e.src, e.srcType
}

func (e *srcToType) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *srcToType) PropertyNames() []string {
	return []string{}
}

func (e *srcToType) IdentifiablePropertyNames() []string {
	return []string{}
}

type srcTypeToNamespace struct {
	srcType   *srcType
	namespace *srcNamespace
}

func (e *srcTypeToNamespace) Type() string {
	return "SrcHasNamespace"
}

func (e *srcTypeToNamespace) Nodes() (v, u assembler.GuacNode) {
	return e.srcType, e.namespace
}

func (e *srcTypeToNamespace) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *srcTypeToNamespace) PropertyNames() []string {
	return []string{}
}

func (e *srcTypeToNamespace) IdentifiablePropertyNames() []string {
	return []string{}
}

type srcNamespaceToName struct {
	namespace *srcNamespace
	name      *srcName
}

func (e *srcNamespaceToName) Type() string {
	return "SrcHasName"
}

func (e *srcNamespaceToName) Nodes() (v, u assembler.GuacNode) {
	return e.namespace, e.name
}

func (e *srcNamespaceToName) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e *srcNamespaceToName) PropertyNames() []string {
	return []string{}
}

func (e *srcNamespaceToName) IdentifiablePropertyNames() []string {
	return []string{}
}
