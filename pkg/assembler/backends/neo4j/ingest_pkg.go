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
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
)

func registerAllPackages(client *neo4jClient) {
	// TODO: add util to convert from pURL to package fields
	topLevelPkg := createTopLevelPkg(client)
	// pkg:apk/alpine/apk@2.12.9-r3?arch=x86
	client.registerPackage(topLevelPkg, "apk", "alpine", "apk", "2.12.9-r3", "", "arch=x86")
	// pkg:apk/alpine/curl@7.83.0-r0?arch=x86
	client.registerPackage(topLevelPkg, "apk", "alpine", "curl", "7.83.0-r0", "", "arch=x86")
	// pkg:conan/openssl.org/openssl@3.0.3?arch=x86_64&build_type=Debug&compiler=Visual%20Studio&compiler.runtime=MDd&compiler.version=16&os=Windows&shared=True&rrev=93a82349c31917d2d674d22065c7a9ef9f380c8e&prev=b429db8a0e324114c25ec387bfd8281f330d7c5c
	client.registerPackage(topLevelPkg, "conan", "openssl.org", "openssl", "3.0.3", "", "arch=x86_64", "build_type=Debug", "compiler=Visual%20Studio", "compiler.runtime=MDd", "compiler.version=16", "os=Windows", "shared=True", "rrev=93a82349c31917d2d674d22065c7a9ef9f380c8e", "prev=b429db8a0e324114c25ec387bfd8281f330d7c5c")
	// pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
	client.registerPackage(topLevelPkg, "conan", "openssl.org", "openssl", "3.0.3", "", "user=bincrafters", "channel=stable")
	// pkg:conan/openssl@3.0.3
	client.registerPackage(topLevelPkg, "conan", "", "openssl", "3.0.3", "")
	// pkg:deb/debian/attr@1:2.4.47-2?arch=amd64
	client.registerPackage(topLevelPkg, "deb", "debian", "attr", "1:2.4.47-2", "", "arch=amd64")
	// pkg:deb/debian/attr@1:2.4.47-2?arch=source
	client.registerPackage(topLevelPkg, "deb", "debian", "attr", "1:2.4.47-2", "", "arch=source")
	// pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie
	client.registerPackage(topLevelPkg, "deb", "debian", "curl", "7.50.3-1", "", "arch=i386", "distro=jessie")
	// pkg:deb/debian/dpkg@1.19.0.4?arch=amd64&distro=stretch
	client.registerPackage(topLevelPkg, "deb", "debian", "dpkg", "1.19.0.4", "", "arch=amd64", "distro=stretch")
	// pkg:deb/ubuntu/dpkg@1.19.0.4?arch=amd64
	client.registerPackage(topLevelPkg, "deb", "ubuntu", "dpkg", "1.19.0.4", "", "arch=amd64")
	// pkg:docker/cassandra@latest
	client.registerPackage(topLevelPkg, "docker", "", "cassandra", "latest", "")
	// pkg:docker/cassandra@sha256:244fd47e07d1004f0aed9c
	client.registerPackage(topLevelPkg, "docker", "", "cassandra", "sha256:244fd47e07d1004f0aed9c", "")
	// pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io
	client.registerPackage(topLevelPkg, "docker", "customer", "dockerimage", "sha256:244fd47e07d1004f0aed9c", "", "repository_url=gcr.io")
	// pkg:docker/smartentry/debian@dc437cc87d10
	client.registerPackage(topLevelPkg, "docker", "smartentry", "debian", "dc437cc87d10", "")
	// pkg:generic/bitwarderl?vcs_url=git%2Bhttps://git.fsfe.org/dxtr/bitwarderl%40cc55108da32
	client.registerPackage(topLevelPkg, "generic", "", "bitwarderl", "", "", "vcs_url=git%2Bhttps://git.fsfe.org/dxtr/bitwarderl%40cc55108da32")
	// pkg:generic/openssl@1.1.10g
	client.registerPackage(topLevelPkg, "generic", "", "openssl", "1.1.10g", "")
	// pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz&checksum=sha256:de4d501267da
	client.registerPackage(topLevelPkg, "generic", "", "openssl", "1.1.10g", "", "download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz", "checksum=sha256:de4d501267da")
	// pkg:oci/debian@sha256:244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye
	client.registerPackage(topLevelPkg, "oci", "", "debian", "sha256:244fd47e07d10", "", "repository_url=ghcr.io/debian", "tag=bullseye")
	// pkg:oci/hello-wasm@sha256:244fd47e07d10?tag=v1
	client.registerPackage(topLevelPkg, "oci", "", "hello-wasm", "sha256:244fd47e07d10", "", "tag=v1")
	// pkg:oci/static@sha256:244fd47e07d10?repository_url=gcr.io/distroless/static&tag=latest
	client.registerPackage(topLevelPkg, "oci", "", "static", "sha256:244fd47e07d10", "", "repository_url=gcr.io/distroless/static", "tag=latest")
	// pkg:pypi/django-allauth@12.23
	client.registerPackage(topLevelPkg, "pypi", "", "django-allauth", "12.23", "")
	// pkg:pypi/django@1.11.1
	client.registerPackage(topLevelPkg, "pypi", "", "django", "1.11.1", "")
	// pkg:pypi/django@1.11.1#subpath
	client.registerPackage(topLevelPkg, "pypi", "", "django", "1.11.1", "subpath")
}

func createTopLevelPkg(client *neo4jClient) pkgNode {
	collectedPkg := pkgNode{}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedPkg},
	}
	assembler.StoreGraph(assemblerinput, client.driver)
	return collectedPkg
}

func (c *neo4jClient) registerPackage(topLevelPkg pkgNode, packageType, namespace, name, version, subpath string, qualifiers ...string) {

	collectedType := pkgType{pkgType: packageType}
	collectedNamespace := pkgNamespace{namespace: namespace}
	collectedName := pkgName{name: name}
	collectedVersion := pkgVersion{version: version, subpath: subpath, qualifier: map[string]interface{}{}}
	for _, kv := range qualifiers {
		pair := strings.Split(kv, "=")
		collectedVersion.qualifier[pair[0]] = pair[1]
	}
	pkgToTypeEdge := pkgToType{topLevelPkg, collectedType}
	typetoNamespaceEdge := typeToNamespace{collectedType, collectedNamespace}
	namespaceToNameEdge := namespaceToName{collectedNamespace, collectedName}
	nameToVersionEdge := nameToVersion{collectedName, collectedVersion}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedType, collectedNamespace, collectedName, collectedVersion},
		Edges: []assembler.GuacEdge{pkgToTypeEdge, typetoNamespaceEdge, namespaceToNameEdge, nameToVersionEdge},
	}
	assembler.StoreGraph(assemblerinput, c.driver)
}

// pkgNode represents the top level pkg->Type->Namespace->Name->Version
type pkgNode struct {
}

func (pn pkgNode) Type() string {
	return "Pkg"
}

func (pn pkgNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["pkg"] = "pkg"
	return properties
}

func (pn pkgNode) PropertyNames() []string {
	fields := []string{"pkg"}
	return fields
}

func (pn pkgNode) IdentifiablePropertyNames() []string {
	return []string{"pkg"}
}

type pkgType struct {
	pkgType string
}

func (pt pkgType) Type() string {
	return "PkgType"
}

func (pt pkgType) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["pkgType"] = pt.pkgType
	return properties
}

func (pt pkgType) PropertyNames() []string {
	fields := []string{"pkgType"}
	return fields
}

func (pt pkgType) IdentifiablePropertyNames() []string {
	return []string{"pkgType"}
}

type pkgNamespace struct {
	namespace string
}

func (pn pkgNamespace) Type() string {
	return "PkgNamespace"
}

func (pn pkgNamespace) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["namespace"] = pn.namespace
	return properties
}

func (pn pkgNamespace) PropertyNames() []string {
	fields := []string{"namespace"}
	return fields
}

func (pn pkgNamespace) IdentifiablePropertyNames() []string {
	return []string{"namespace"}
}

type pkgName struct {
	name string
}

func (pn pkgName) Type() string {
	return "PkgName"
}

func (pn pkgName) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["name"] = pn.name
	return properties
}

func (pn pkgName) PropertyNames() []string {
	fields := []string{"name"}
	return fields
}

func (pn pkgName) IdentifiablePropertyNames() []string {
	return []string{"name"}
}

type pkgVersion struct {
	version   string
	qualifier map[string]interface{}
	subpath   string
}

func (pv pkgVersion) Type() string {
	return "PkgVersion"
}

func (pv pkgVersion) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["version"] = pv.version
	properties["subpath"] = pv.subpath
	for k, v := range pv.qualifier {
		properties[k] = v
	}
	return properties
}

func (pv pkgVersion) PropertyNames() []string {
	fields := []string{"version", "subpath"}
	for k := range pv.qualifier {
		fields = append(fields, k)
	}
	return fields
}

func (pv pkgVersion) IdentifiablePropertyNames() []string {
	fields := []string{"version", "subpath"}
	for k := range pv.qualifier {
		fields = append(fields, k)
	}
	return fields
}

type pkgToType struct {
	pkg     pkgNode
	pkgType pkgType
}

func (e pkgToType) Type() string {
	return "PkgHasType"
}

func (e pkgToType) Nodes() (v, u assembler.GuacNode) {
	return e.pkg, e.pkgType
}

func (e pkgToType) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e pkgToType) PropertyNames() []string {
	return []string{}
}

func (e pkgToType) IdentifiablePropertyNames() []string {
	return []string{}
}

type typeToNamespace struct {
	pkgType   pkgType
	namespace pkgNamespace
}

func (e typeToNamespace) Type() string {
	return "PkgHasNamespace"
}

func (e typeToNamespace) Nodes() (v, u assembler.GuacNode) {
	return e.pkgType, e.namespace
}

func (e typeToNamespace) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e typeToNamespace) PropertyNames() []string {
	return []string{}
}

func (e typeToNamespace) IdentifiablePropertyNames() []string {
	return []string{}
}

type namespaceToName struct {
	namespace pkgNamespace
	name      pkgName
}

func (e namespaceToName) Type() string {
	return "PkgHasName"
}

func (e namespaceToName) Nodes() (v, u assembler.GuacNode) {
	return e.namespace, e.name
}

func (e namespaceToName) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e namespaceToName) PropertyNames() []string {
	return []string{}
}

func (e namespaceToName) IdentifiablePropertyNames() []string {
	return []string{}
}

type nameToVersion struct {
	name    pkgName
	version pkgVersion
}

func (e nameToVersion) Type() string {
	return "PkgHasVersion"
}

func (e nameToVersion) Nodes() (v, u assembler.GuacNode) {
	return e.name, e.version
}

func (e nameToVersion) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

func (e nameToVersion) PropertyNames() []string {
	return []string{}
}

func (e nameToVersion) IdentifiablePropertyNames() []string {
	return []string{}
}
