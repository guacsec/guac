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
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllPackages(client *demoClient) {
	// TODO: add util to convert from pURL to package fields
	// pkg:apk/alpine/apk@2.12.9-r3?arch=x86
	client.registerPackage("apk", "alpine", "apk", "2.12.9-r3", "", "arch", "x86")
	// pkg:apk/alpine/curl@7.83.0-r0?arch=x86
	client.registerPackage("apk", "alpine", "curl", "7.83.0-r0", "", "arch", "x86")
	// pkg:conan/openssl.org/openssl@3.0.3?arch=x86_64&build_type=Debug&compiler=Visual%20Studio&compiler.runtime=MDd&compiler.version=16&os=Windows&shared=True&rrev=93a82349c31917d2d674d22065c7a9ef9f380c8e&prev=b429db8a0e324114c25ec387bfd8281f330d7c5c
	client.registerPackage("conan", "openssl.org", "openssl", "3.0.3", "", "arch", "x86_64", "build_type", "Debug", "compiler", "Visual%20Studio", "compiler.runtime", "MDd", "compiler.version", "16", "os", "Windows", "shared", "True", "rrev", "93a82349c31917d2d674d22065c7a9ef9f380c8e", "prev", "b429db8a0e324114c25ec387bfd8281f330d7c5c")
	// pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
	client.registerPackage("conan", "openssl.org", "openssl", "3.0.3", "", "user", "bincrafters", "channel", "stable")
	// pkg:conan/openssl@3.0.3
	client.registerPackage("conan", "", "openssl", "3.0.3", "")
	// pkg:deb/debian/attr@1:2.4.47-2?arch=amd64
	client.registerPackage("deb", "debian", "attr", "1:2.4.47-2", "", "arch", "amd64")
	// pkg:deb/debian/attr@1:2.4.47-2?arch=source
	client.registerPackage("deb", "debian", "attr", "1:2.4.47-2", "", "arch", "source")
	// pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie
	client.registerPackage("deb", "debian", "curl", "7.50.3-1", "", "arch", "i386", "distro", "jessie")
	// pkg:deb/debian/dpkg@1.19.0.4?arch=amd64&distro=stretch
	client.registerPackage("deb", "debian", "dpkg", "1.19.0.4", "", "arch", "amd64", "distro", "stretch")
	// pkg:deb/ubuntu/dpkg@1.19.0.4?arch=amd64
	client.registerPackage("deb", "ubuntu", "dpkg", "1.19.0.4", "", "arch", "amd64")
	// pkg:docker/cassandra@latest
	client.registerPackage("docker", "", "cassandra", "latest", "")
	// pkg:docker/cassandra@sha256:244fd47e07d1004f0aed9c
	client.registerPackage("docker", "", "cassandra", "sha256:244fd47e07d1004f0aed9c", "")
	// pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io
	client.registerPackage("docker", "customer", "dockerimage", "sha256:244fd47e07d1004f0aed9c", "", "repository_url", "gcr.io")
	// pkg:docker/smartentry/debian@dc437cc87d10
	client.registerPackage("docker", "smartentry", "debian", "dc437cc87d10", "")
	// pkg:generic/bitwarderl?vcs_url=git%2Bhttps://git.fsfe.org/dxtr/bitwarderl%40cc55108da32
	client.registerPackage("generic", "", "bitwarderl", "", "", "vcs_url", "git%2Bhttps://git.fsfe.org/dxtr/bitwarderl%40cc55108da32")
	// pkg:generic/openssl@1.1.10g
	client.registerPackage("generic", "", "openssl", "1.1.10g", "")
	// pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz&checksum=sha256:de4d501267da
	client.registerPackage("generic", "", "openssl", "1.1.10g", "", "download_url", "https://openssl.org/source/openssl-1.1.0g.tar.gz", "checksum", "sha256:de4d501267da")
	// pkg:oci/debian@sha256:244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye
	client.registerPackage("oci", "", "debian", "sha256:244fd47e07d10", "", "repository_url", "ghcr.io/debian", "tag", "bullseye")
	// pkg:oci/hello-wasm@sha256:244fd47e07d10?tag=v1
	client.registerPackage("oci", "", "hello-wasm", "sha256:244fd47e07d10", "", "tag", "v1")
	// pkg:oci/static@sha256:244fd47e07d10?repository_url=gcr.io/distroless/static&tag=latest
	client.registerPackage("oci", "", "static", "sha256:244fd47e07d10", "", "repository_url", "gcr.io/distroless/static", "tag", "latest")
	// pkg:pypi/django-allauth@12.23
	client.registerPackage("pypi", "", "django-allauth", "12.23", "")
	// pkg:pypi/django@1.11.1
	client.registerPackage("pypi", "", "django", "1.11.1", "")
	// pkg:pypi/django@1.11.1#subpath
	client.registerPackage("pypi", "", "django", "1.11.1", "subpath")
	// pkg:pypi/kubetest@0.9.5
	client.registerPackage("pypi", "", "kubetest", "0.9.5", "")
}

// Ingest Package

func (c *demoClient) IngestPackage(ctx context.Context, pkg *model.PkgInputSpec) (*model.Package, error) {
	pkgType := pkg.Type
	name := pkg.Name

	namespace := ""
	if pkg.Namespace != nil {
		namespace = *pkg.Namespace
	}

	version := ""
	if pkg.Version != nil {
		version = *pkg.Version
	}

	subpath := ""
	if pkg.Subpath != nil {
		subpath = *pkg.Subpath
	}

	var qualifiers []string
	for _, qualifier := range pkg.Qualifiers {
		qualifiers = append(qualifiers, qualifier.Key, qualifier.Value)
	}

	newPkg := c.registerPackage(pkgType, namespace, name, version, subpath, qualifiers...)

	return newPkg, nil
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
	inputQualifiers := buildQualifierSet(qualifiers...)

	for _, v := range n.Versions {
		if v.Version != version {
			continue
		}
		if v.Subpath != subpath {
			continue
		}
		// TODO(mihaimaruseac): This is O(n*m) instead of O(n+m)
		allFound := true
		for i, _ := range v.Qualifiers {
			if i%2 != 0 {
				continue
			}
			dbKey := v.Qualifiers[i]
			dbValue := v.Qualifiers[i+1]
			found := false
			for j, _ := range inputQualifiers {
				if j%2 != 0 {
					continue
				}
				if inputQualifiers[j] == dbKey &&
					inputQualifiers[j+1] == dbValue {
					found = true
					break
				}
			}
			if !found {
				allFound = false
				break
			}
		}
		if allFound {
			return n
		}
	}

	newV := &model.PackageVersion{
		Version:    version,
		Subpath:    subpath,
		Qualifiers: inputQualifiers,
	}
	n.Versions = append(n.Versions, newV)
	return n
}

func buildQualifierSet(qualifiers ...string) []*model.PackageQualifier {
	var qs []*model.PackageQualifier
	for i, _ := range qualifiers {
		if i%2 == 0 {
			qs = append(qs, &model.PackageQualifier{
				Key:   qualifiers[i],
				Value: qualifiers[i+1],
			})
		}
	}
	return qs
}

// Query Package

func (c *demoClient) Packages(ctx context.Context, pkgSpec *model.PkgSpec) ([]*model.Package, error) {
	var packages []*model.Package
	for _, p := range c.packages {
		if pkgSpec.Type == nil || p.Type == *pkgSpec.Type {
			newPkg := filterPackageNamespace(p, pkgSpec)
			if newPkg != nil {
				packages = append(packages, newPkg)
			}
		}
	}
	return packages, nil
}

func filterPackageNamespace(pkg *model.Package, pkgSpec *model.PkgSpec) *model.Package {
	var namespaces []*model.PackageNamespace
	for _, ns := range pkg.Namespaces {
		if pkgSpec.Namespace == nil || ns.Namespace == *pkgSpec.Namespace {
			newNs := filterPackageName(ns, pkgSpec)
			if newNs != nil {
				namespaces = append(namespaces, newNs)
			}
		}
	}
	if len(namespaces) == 0 {
		return nil
	}
	return &model.Package{
		Type:       pkg.Type,
		Namespaces: namespaces,
	}
}

func filterPackageName(ns *model.PackageNamespace, pkgSpec *model.PkgSpec) *model.PackageNamespace {
	var names []*model.PackageName
	for _, n := range ns.Names {
		if pkgSpec.Name == nil || n.Name == *pkgSpec.Name {
			newN := filterPackageVersion(n, pkgSpec)
			if newN != nil {
				names = append(names, newN)
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	return &model.PackageNamespace{
		Namespace: ns.Namespace,
		Names:     names,
	}
}

func filterPackageVersion(n *model.PackageName, pkgSpec *model.PkgSpec) *model.PackageName {
	var versions []*model.PackageVersion
	for _, v := range n.Versions {
		if pkgSpec.Version == nil || v.Version == *pkgSpec.Version {
			newV := filterQualifiersAndSubpath(v, pkgSpec)
			if newV != nil {
				versions = append(versions, newV)
			}
		}
	}
	if len(versions) == 0 {
		return nil
	}
	return &model.PackageName{
		Name:     n.Name,
		Versions: versions,
	}
}

func filterQualifiersAndSubpath(v *model.PackageVersion, pkgSpec *model.PkgSpec) *model.PackageVersion {
	// First check for subpath matching
	if pkgSpec.Subpath != nil && *pkgSpec.Subpath != v.Subpath {
		return nil
	}

	// Allow matching on nodes with no qualifiers
	if pkgSpec.MatchOnlyEmptyQualifiers != nil {
		if *pkgSpec.MatchOnlyEmptyQualifiers && len(v.Qualifiers) != 0 {
			return nil
		}
	}

	// Because we operate on GraphQL-generated structs directly we cannot
	// use a key-value map, so this is O(n^2). Production resolvers will
	// run queries that match the qualifiers faster.
	for _, specQualifier := range pkgSpec.Qualifiers {
		found := false
		for _, versionQualifier := range v.Qualifiers {
			if specQualifier.Key == versionQualifier.Key {
				if specQualifier.Value == nil || *specQualifier.Value == versionQualifier.Value {
					found = true
					break
				}
			}
		}
		if !found {
			return nil
		}
	}
	return v
}
