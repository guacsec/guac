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
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllPackages() *demoClient {
	client := demoClient{}
	// pkg:apk/alpine/apk@2.12.9-r3?arch=x86
	client.registerPackage("apk", "alpine", "apk", "2.12.9-r3")
	// pkg:apk/alpine/curl@7.83.0-r0?arch=x86
	client.registerPackage("apk", "alpine", "curl", "7.83.0-r0")
	// pkg:conan/openssl.org/openssl@3.0.3?arch=x86_64&build_type=Debug&compiler=Visual%20Studio&compiler.runtime=MDd&compiler.version=16&os=Windows&shared=True&rrev=93a82349c31917d2d674d22065c7a9ef9f380c8e&prev=b429db8a0e324114c25ec387bfd8281f330d7c5c
	client.registerPackage("conan", "openssl.org", "openssl", "3.0.3")
	// pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
	client.registerPackage("conan", "openssl.org", "openssl", "3.0.3")
	// pkg:conan/openssl@3.0.3
	client.registerPackage("conan", "", "openssl", "3.0.3")
	// pkg:deb/debian/attr@1:2.4.47-2?arch=amd64
	client.registerPackage("deb", "debian", "attr", "1:2.4.47-2")
	// pkg:deb/debian/attr@1:2.4.47-2?arch=source
	client.registerPackage("deb", "debian", "attr", "1:2.4.47-2")
	// pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie
	client.registerPackage("deb", "debian", "curl", "7.50.3-1")
	// pkg:deb/debian/dpkg@1.19.0.4?arch=amd64&distro=stretch
	client.registerPackage("deb", "debian", "dpkg", "1.19.0.4")
	// pkg:deb/ubuntu/dpkg@1.19.0.4?arch=amd64
	client.registerPackage("deb", "ubuntu", "dpkg", "1.19.0.4")
	// pkg:docker/cassandra@latest
	client.registerPackage("docker", "", "cassandra", "latest")
	// pkg:docker/cassandra@sha256:244fd47e07d1004f0aed9c
	client.registerPackage("docker", "", "cassandra", "sha256:244fd47e07d1004f0aed9c")
	// pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io
	client.registerPackage("docker", "customer", "dockerimage", "sha256:244fd47e07d1004f0aed9c")
	// pkg:docker/smartentry/debian@dc437cc87d10
	client.registerPackage("docker", "smartentry", "debian", "dc437cc87d10")
	// pkg:generic/bitwarderl?vcs_url=git%2Bhttps://git.fsfe.org/dxtr/bitwarderl%40cc55108da32
	client.registerPackage("generic", "", "bitwarderl", "")
	// pkg:generic/openssl@1.1.10g
	client.registerPackage("generic", "", "openssl", "1.1.10g")
	// pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz&checksum=sha256:de4d501267da
	client.registerPackage("generic", "", "openssl", "1.1.10g")
	// pkg:oci/debian@sha256:244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye
	client.registerPackage("oci", "", "debian", "sha256:244fd47e07d10")
	// pkg:oci/hello-wasm@sha256:244fd47e07d10?tag=v1
	client.registerPackage("oci", "", "hello-wasm", "sha256:244fd47e07d10")
	// pkg:oci/static@sha256:244fd47e07d10?repository_url=gcr.io/distroless/static&tag=latest
	client.registerPackage("oci", "", "static", "sha256:244fd47e07d10")
	// pkg:pypi/django-allauth@12.23
	client.registerPackage("pypi", "", "django-allauth", "12.23")
	// pkg:pypi/django@1.11.1
	client.registerPackage("pypi", "", "django", "1.11.1")
	return &client
}

func (c *demoClient) registerPackage(pkgType, namespace, name, version string) {
	for i, p := range c.packages {
		if p.Type == pkgType {
			c.packages[i] = registerNamespace(p, namespace, name, version)
			return
		}
	}

	newPkg := &model.Package{Type: pkgType}
	newPkg = registerNamespace(newPkg, namespace, name, version)
	c.packages = append(c.packages, newPkg)
}

func registerNamespace(p *model.Package, namespace, name, version string) *model.Package {
	for i, ns := range p.Namespaces {
		if ns.Namespace == namespace {
			p.Namespaces[i] = registerName(ns, name, version)
			return p
		}
	}

	newNs := &model.PackageNamespace{Namespace: namespace}
	newNs = registerName(newNs, name, version)
	p.Namespaces = append(p.Namespaces, newNs)
	return p
}

func registerName(ns *model.PackageNamespace, name, version string) *model.PackageNamespace {
	for i, n := range ns.Names {
		if n.Name == name {
			ns.Names[i] = registerVersion(n, version)
			return ns
		}
	}

	newN := &model.PackageName{Name: name}
	newN = registerVersion(newN, version)
	ns.Names = append(ns.Names, newN)
	return ns
}

func registerVersion(n *model.PackageName, version string) *model.PackageName {
	for _, v := range n.Versions {
		if v.Version == version {
			// TODO: handle qualifiers and subpath in next PR
			return n
		}
	}

	newV := &model.PackageVersion{Version: version}
	// TODO: handle qualifiers and subpath in next PR
	n.Versions = append(n.Versions, newV)
	return n
}
