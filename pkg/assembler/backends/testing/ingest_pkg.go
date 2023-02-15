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

package testing

import (
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllPackages(client *demoClient) {
	// TODO: add util to convert from pURL to package fields
	// pkg:apk/alpine/apk@2.12.9-r3?arch=x86
	client.registerPackage("apk", "alpine", "apk", "2.12.9-r3", "", "arch=x86")
	// pkg:apk/alpine/curl@7.83.0-r0?arch=x86
	client.registerPackage("apk", "alpine", "curl", "7.83.0-r0", "", "arch=x86")
	// pkg:conan/openssl.org/openssl@3.0.3?arch=x86_64&build_type=Debug&compiler=Visual%20Studio&compiler.runtime=MDd&compiler.version=16&os=Windows&shared=True&rrev=93a82349c31917d2d674d22065c7a9ef9f380c8e&prev=b429db8a0e324114c25ec387bfd8281f330d7c5c
	client.registerPackage("conan", "openssl.org", "openssl", "3.0.3", "", "arch=x86_64", "build_type=Debug", "compiler=Visual%20Studio", "compiler.runtime=MDd", "compiler.version=16", "os=Windows", "shared=True", "rrev=93a82349c31917d2d674d22065c7a9ef9f380c8e", "prev=b429db8a0e324114c25ec387bfd8281f330d7c5c")
	// pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
	client.registerPackage("conan", "openssl.org", "openssl", "3.0.3", "", "user=bincrafters", "channel=stable")
	// pkg:conan/openssl@3.0.3
	client.registerPackage("conan", "", "openssl", "3.0.3", "")
	// pkg:deb/debian/attr@1:2.4.47-2?arch=amd64
	client.registerPackage("deb", "debian", "attr", "1:2.4.47-2", "", "arch=amd64")
	// pkg:deb/debian/attr@1:2.4.47-2?arch=source
	client.registerPackage("deb", "debian", "attr", "1:2.4.47-2", "", "arch=source")
	// pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie
	client.registerPackage("deb", "debian", "curl", "7.50.3-1", "", "arch=i386", "distro=jessie")
	// pkg:deb/debian/dpkg@1.19.0.4?arch=amd64&distro=stretch
	client.registerPackage("deb", "debian", "dpkg", "1.19.0.4", "", "arch=amd64", "distro=stretch")
	// pkg:deb/ubuntu/dpkg@1.19.0.4?arch=amd64
	client.registerPackage("deb", "ubuntu", "dpkg", "1.19.0.4", "", "arch=amd64")
	// pkg:docker/cassandra@latest
	client.registerPackage("docker", "", "cassandra", "latest", "")
	// pkg:docker/cassandra@sha256:244fd47e07d1004f0aed9c
	client.registerPackage("docker", "", "cassandra", "sha256:244fd47e07d1004f0aed9c", "")
	// pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io
	client.registerPackage("docker", "customer", "dockerimage", "sha256:244fd47e07d1004f0aed9c", "", "repository_url=gcr.io")
	// pkg:docker/smartentry/debian@dc437cc87d10
	client.registerPackage("docker", "smartentry", "debian", "dc437cc87d10", "")
	// pkg:generic/bitwarderl?vcs_url=git%2Bhttps://git.fsfe.org/dxtr/bitwarderl%40cc55108da32
	client.registerPackage("generic", "", "bitwarderl", "", "", "vcs_url=git%2Bhttps://git.fsfe.org/dxtr/bitwarderl%40cc55108da32")
	// pkg:generic/openssl@1.1.10g
	client.registerPackage("generic", "", "openssl", "1.1.10g", "")
	// pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz&checksum=sha256:de4d501267da
	client.registerPackage("generic", "", "openssl", "1.1.10g", "", "download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz", "checksum=sha256:de4d501267da")
	// pkg:oci/debian@sha256:244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye
	client.registerPackage("oci", "", "debian", "sha256:244fd47e07d10", "", "repository_url=ghcr.io/debian", "tag=bullseye")
	// pkg:oci/hello-wasm@sha256:244fd47e07d10?tag=v1
	client.registerPackage("oci", "", "hello-wasm", "sha256:244fd47e07d10", "", "tag=v1")
	// pkg:oci/static@sha256:244fd47e07d10?repository_url=gcr.io/distroless/static&tag=latest
	client.registerPackage("oci", "", "static", "sha256:244fd47e07d10", "", "repository_url=gcr.io/distroless/static", "tag=latest")
	// pkg:pypi/django-allauth@12.23
	client.registerPackage("pypi", "", "django-allauth", "12.23", "")
	// pkg:pypi/django@1.11.1
	client.registerPackage("pypi", "", "django", "1.11.1", "")
	// pkg:pypi/django@1.11.1#subpath
	client.registerPackage("pypi", "", "django", "1.11.1", "subpath")
}

func (c *demoClient) registerPackage(pkgType, namespace, name, version, subpath string, qualifiers ...string) *model.Package {
	for i, p := range c.packages {
		if p.Type == pkgType {
			c.packages[i] = registerNamespace(p, namespace, name, version, subpath, qualifiers...)
			return c.packages[i]
		}
	}

	newPkg := &model.Package{Type: pkgType}
	newPkg = registerNamespace(newPkg, namespace, name, version, subpath, qualifiers...)
	c.packages = append(c.packages, newPkg)

	return newPkg
}

func registerNamespace(p *model.Package, namespace, name, version, subpath string, qualifiers ...string) *model.Package {
	for i, ns := range p.Namespaces {
		if ns.Namespace == namespace {
			p.Namespaces[i] = registerName(ns, name, version, subpath, qualifiers...)
			return p
		}
	}

	newNs := &model.PackageNamespace{Namespace: namespace}
	newNs = registerName(newNs, name, version, subpath, qualifiers...)
	p.Namespaces = append(p.Namespaces, newNs)
	return p
}

func registerName(ns *model.PackageNamespace, name, version, subpath string, qualifiers ...string) *model.PackageNamespace {
	for i, n := range ns.Names {
		if n.Name == name {
			ns.Names[i] = registerVersion(n, version, subpath, qualifiers...)
			return ns
		}
	}

	newN := &model.PackageName{Name: name}
	newN = registerVersion(newN, version, subpath, qualifiers...)
	ns.Names = append(ns.Names, newN)
	return ns
}

func registerVersion(n *model.PackageName, version, subpath string, qualifiers ...string) *model.PackageName {
	// TODO(mihaimaruseac): Here we could use a utility to compare if there
	// is already a version matching all of the arguments to not create
	// duplicates, but in the end this is test data and we don't generate
	// duplicates in input right now. Hence, each time this is called, we
	// create a new node.
	newV := &model.PackageVersion{
		Version:    version,
		Subpath:    subpath,
		Qualifiers: buildQualifierSet(qualifiers...),
	}
	n.Versions = append(n.Versions, newV)
	return n
}

func buildQualifierSet(qualifiers ...string) []*model.PackageQualifier {
	var qs []*model.PackageQualifier
	for _, kv := range qualifiers {
		pair := strings.Split(kv, "=")
		qs = append(qs, &model.PackageQualifier{
			Key:   pair[0],
			Value: pair[1],
		})
	}
	return qs
}
