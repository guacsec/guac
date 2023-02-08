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

func registerAllArtifacts(client *neo4jClient) error {
	// strings.ToLower(string(checksum.Algorithm)) + ":" + checksum.Value
	err := client.registerArtifact("sha256", "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf")
	if err != nil {
		return err
	}
	err = client.registerArtifact("sha1", "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9")
	if err != nil {
		return err
	}
	err = client.registerArtifact("sha512", "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7")
	if err != nil {
		return err
	}
	return nil
}

func registerAllBuilders(client *neo4jClient) error {
	err := client.registerBuilder("https://github.com/Attestations/GitHubHostedActions@v1")
	if err != nil {
		return err
	}
	err = client.registerBuilder("https://tekton.dev/chains/v2")
	if err != nil {
		return err
	}
	return nil
}

func registerAllCVE(client *neo4jClient) error {
	err := client.registerCVE("2019", "CVE-2019-13110")
	if err != nil {
		return err
	}
	err = client.registerCVE("2014", "CVE-2014-8139")
	if err != nil {
		return err
	}
	err = client.registerCVE("2014", "CVE-2014-8140")
	if err != nil {
		return err
	}
	err = client.registerCVE("2022", "CVE-2022-26499")
	if err != nil {
		return err
	}
	err = client.registerCVE("2014", "CVE-2014-8140")
	if err != nil {
		return err
	}
	return nil
}

func registerAllGHSA(client *neo4jClient) error {
	err := client.registerGhsa("GHSA-h45f-rjvw-2rv2")
	if err != nil {
		return err
	}
	err = client.registerGhsa("GHSA-xrw3-wqph-3fxg")
	if err != nil {
		return err
	}
	err = client.registerGhsa("GHSA-8v4j-7jgf-5rg9")
	if err != nil {
		return err
	}
	err = client.registerGhsa("GHSA-h45f-rjvw-2rv2")
	if err != nil {
		return err
	}
	err = client.registerGhsa("GHSA-h45f-rjvw-2rv2")
	if err != nil {
		return err
	}
	return nil
}

func registerAllOSV(client *neo4jClient) error {
	err := client.registerOSV("CVE-2019-3456")
	if err != nil {
		return err
	}
	err = client.registerOSV("CVE-2014-53356")
	if err != nil {
		return err
	}
	err = client.registerOSV("CVE-2014-4432")
	if err != nil {
		return err
	}
	err = client.registerOSV("CVE-2022-9876")
	if err != nil {
		return err
	}
	err = client.registerOSV("CVE-2014-4432")
	if err != nil {
		return err
	}
	return nil
}

func registerAllPackages(client *neo4jClient) error {
	// TODO: add util to convert from pURL to package fields
	// pkg:apk/alpine/apk@2.12.9-r3?arch=x86
	err := client.registerPackage("apk", "alpine", "apk", "2.12.9-r3", "", "arch=x86")
	if err != nil {
		return err
	}
	// pkg:apk/alpine/curl@7.83.0-r0?arch=x86
	err = client.registerPackage("apk", "alpine", "curl", "7.83.0-r0", "", "arch=x86")
	if err != nil {
		return err
	}
	// pkg:conan/openssl.org/openssl@3.0.3?arch=x86_64&build_type=Debug&compiler=Visual%20Studio&compiler.runtime=MDd&compiler.version=16&os=Windows&shared=True&rrev=93a82349c31917d2d674d22065c7a9ef9f380c8e&prev=b429db8a0e324114c25ec387bfd8281f330d7c5c
	// NOTE: neo4j does not like "." for its property. "compiler.runtime" has to be changed to "compiler_runtime"
	err = client.registerPackage("conan", "openssl.org", "openssl", "3.0.3", "", "arch=x86_64", "build_type=Debug", "compiler=Visual%20Studio", "compiler_runtime=MDd", "compiler_version=16", "os=Windows", "shared=True", "rrev=93a82349c31917d2d674d22065c7a9ef9f380c8e", "prev=b429db8a0e324114c25ec387bfd8281f330d7c5c")
	if err != nil {
		return err
	}
	// pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
	err = client.registerPackage("conan", "openssl.org", "openssl", "3.0.3", "", "user=bincrafters", "channel=stable")
	if err != nil {
		return err
	}
	// pkg:conan/openssl@3.0.3
	err = client.registerPackage("conan", "", "openssl", "3.0.3", "")
	if err != nil {
		return err
	}
	// pkg:deb/debian/attr@1:2.4.47-2?arch=amd64
	err = client.registerPackage("deb", "debian", "attr", "1:2.4.47-2", "", "arch=amd64")
	if err != nil {
		return err
	}
	// pkg:deb/debian/attr@1:2.4.47-2?arch=source
	err = client.registerPackage("deb", "debian", "attr", "1:2.4.47-2", "", "arch=source")
	if err != nil {
		return err
	}
	// pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie
	err = client.registerPackage("deb", "debian", "curl", "7.50.3-1", "", "arch=i386", "distro=jessie")
	if err != nil {
		return err
	}
	// pkg:deb/debian/dpkg@1.19.0.4?arch=amd64&distro=stretch
	err = client.registerPackage("deb", "debian", "dpkg", "1.19.0.4", "", "arch=amd64", "distro=stretch")
	if err != nil {
		return err
	}
	// pkg:deb/ubuntu/dpkg@1.19.0.4?arch=amd64
	err = client.registerPackage("deb", "ubuntu", "dpkg", "1.19.0.4", "", "arch=amd64")
	if err != nil {
		return err
	}
	// pkg:docker/cassandra@latest
	err = client.registerPackage("docker", "", "cassandra", "latest", "")
	if err != nil {
		return err
	}
	// pkg:docker/cassandra@sha256:244fd47e07d1004f0aed9c
	err = client.registerPackage("docker", "", "cassandra", "sha256:244fd47e07d1004f0aed9c", "")
	if err != nil {
		return err
	}
	// pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io
	err = client.registerPackage("docker", "customer", "dockerimage", "sha256:244fd47e07d1004f0aed9c", "", "repository_url=gcr.io")
	if err != nil {
		return err
	}
	// pkg:docker/smartentry/debian@dc437cc87d10
	err = client.registerPackage("docker", "smartentry", "debian", "dc437cc87d10", "")
	if err != nil {
		return err
	}
	// pkg:generic/bitwarderl?vcs_url=git%2Bhttps://git.fsfe.org/dxtr/bitwarderl%40cc55108da32
	err = client.registerPackage("generic", "", "bitwarderl", "", "", "vcs_url=git%2Bhttps://git.fsfe.org/dxtr/bitwarderl%40cc55108da32")
	if err != nil {
		return err
	}
	// pkg:generic/openssl@1.1.10g
	err = client.registerPackage("generic", "", "openssl", "1.1.10g", "")
	if err != nil {
		return err
	}
	// pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz&checksum=sha256:de4d501267da
	err = client.registerPackage("generic", "", "openssl", "1.1.10g", "", "download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz", "checksum=sha256:de4d501267da")
	if err != nil {
		return err
	}
	// pkg:oci/debian@sha256:244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye
	err = client.registerPackage("oci", "", "debian", "sha256:244fd47e07d10", "", "repository_url=ghcr.io/debian", "tag=bullseye")
	if err != nil {
		return err
	}
	// pkg:oci/hello-wasm@sha256:244fd47e07d10?tag=v1
	err = client.registerPackage("oci", "", "hello-wasm", "sha256:244fd47e07d10", "", "tag=v1")
	if err != nil {
		return err
	}
	// pkg:oci/static@sha256:244fd47e07d10?repository_url=gcr.io/distroless/static&tag=latest
	err = client.registerPackage("oci", "", "static", "sha256:244fd47e07d10", "", "repository_url=gcr.io/distroless/static", "tag=latest")
	if err != nil {
		return err
	}
	// pkg:pypi/django-allauth@12.23
	err = client.registerPackage("pypi", "", "django-allauth", "12.23", "")
	if err != nil {
		return err
	}
	// pkg:pypi/django@1.11.1
	err = client.registerPackage("pypi", "", "django", "1.11.1", "")
	if err != nil {
		return err
	}
	// pkg:pypi/django@1.11.1#subpath
	err = client.registerPackage("pypi", "", "django", "1.11.1", "subpath")
	if err != nil {
		return err
	}
	return nil
}

func registerAllSources(client *neo4jClient) error {
	// with tag
	err := client.registerSource("git", "github", "github.com/guacsec/guac", "tag=v0.0.1")
	if err != nil {
		return err
	}
	// with commit
	err = client.registerSource("git", "github", "github.com/guacsec/guac", "commit=fcba958b73e27cad8b5c8655d46439984d27853b")
	if err != nil {
		return err
	}
	// with no tag or commit
	err = client.registerSource("git", "github", "github.com/guacsec/guac", "")
	if err != nil {
		return err
	}
	// gitlab namespace
	err = client.registerSource("git", "gitlab", "github.com/guacsec/guacdata", "tag=v0.0.1")
	if err != nil {
		return err
	}
	// differnt type
	err = client.registerSource("svn", "gitlab", "github.com/guacsec/guac", "")
	if err != nil {
		return err
	}
	return nil
}

func (c *neo4jClient) registerArtifact(algorithm, digest string) error {
	// enforce lowercase for both the algorithm and digest when ingesting
	collectedArtifact := &artifactNode{
		algorithm: strings.ToLower(algorithm),
		digest:    strings.ToLower(digest),
	}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedArtifact},
	}
	err := assembler.StoreGraph(assemblerinput, c.driver)
	if err != nil {
		return err
	}
	return nil
}

func (c *neo4jClient) registerBuilder(uri string) error {
	collectedBuilder := &builderNode{
		uri: uri,
	}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedBuilder},
	}
	err := assembler.StoreGraph(assemblerinput, c.driver)
	if err != nil {
		return err
	}
	return nil
}

func (c *neo4jClient) registerCVE(year, id string) error {
	collectedCve := &cveNode{}
	collectedYear := &cveYear{year: year}
	collecteCveId := &cveID{id: strings.ToLower(id)}

	cveToYearEdge := &cveToYear{collectedCve, collectedYear}
	cveYearToIDEdge := &cveYearToCveID{collectedYear, collecteCveId}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedCve, collectedYear, collecteCveId},
		Edges: []assembler.GuacEdge{cveToYearEdge, cveYearToIDEdge},
	}
	err := assembler.StoreGraph(assemblerinput, c.driver)
	if err != nil {
		return err
	}
	return nil
}

func (c *neo4jClient) registerGhsa(id string) error {
	collectedGhsa := &ghsaNode{}
	collecteGhsaId := &ghsaID{id: strings.ToLower(id)}

	ghsaToIDEdge := &ghsaToID{collectedGhsa, collecteGhsaId}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedGhsa, collecteGhsaId},
		Edges: []assembler.GuacEdge{ghsaToIDEdge},
	}
	err := assembler.StoreGraph(assemblerinput, c.driver)
	if err != nil {
		return err
	}
	return nil
}

func (c *neo4jClient) registerOSV(id string) error {
	collectedOsv := &osvNode{}
	collecteOsvId := &osvID{id: strings.ToLower(id)}

	osvToIDEdge := &osvToID{collectedOsv, collecteOsvId}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedOsv, collecteOsvId},
		Edges: []assembler.GuacEdge{osvToIDEdge},
	}
	err := assembler.StoreGraph(assemblerinput, c.driver)
	if err != nil {
		return err
	}
	return nil
}

func (c *neo4jClient) registerPackage(packageType, namespace, name, version, subpath string, qualifiers ...string) error {
	collectedPkg := &pkgNode{}
	collectedType := &pkgType{pkgType: packageType}
	collectedNamespace := &pkgNamespace{namespace: namespace}
	collectedName := &pkgName{name: name}
	collectedVersion := &pkgVersion{version: version, subpath: subpath}

	pkgToTypeEdge := &pkgToType{collectedPkg, collectedType}
	typeToNamespaceEdge := &typeToNamespace{collectedType, collectedNamespace}
	namespaceToNameEdge := &namespaceToName{collectedNamespace, collectedName}
	nameToVersionEdge := &nameToVersion{collectedName, collectedVersion}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedPkg, collectedType, collectedNamespace, collectedName, collectedVersion},
		Edges: []assembler.GuacEdge{pkgToTypeEdge, typeToNamespaceEdge, namespaceToNameEdge, nameToVersionEdge},
	}
	if len(qualifiers) > 0 {
		collectedQualifier := &pkgQualifier{qualifier: map[string]string{}}
		for _, kv := range qualifiers {
			pair := strings.Split(kv, "=")
			collectedQualifier.qualifier[pair[0]] = pair[1]
		}
		versionToQualifierEdge := &versionToQualifier{collectedVersion, collectedQualifier}
		assemblerinput.Nodes = append(assemblerinput.Nodes, collectedQualifier)
		assemblerinput.Edges = append(assemblerinput.Edges, versionToQualifierEdge)
	}
	if len(qualifiers) > 0 {
		collectedQualifier := &pkgQualifier{qualifier: map[string]string{}}
		for _, kv := range qualifiers {
			pair := strings.Split(kv, "=")
			collectedQualifier.qualifier[pair[0]] = pair[1]
		}
		versionToQualiferEdge := &versionToQualifier{collectedVersion, collectedQualifier}
		assemblerinput.Nodes = append(assemblerinput.Nodes, collectedQualifier)
		assemblerinput.Edges = append(assemblerinput.Edges, versionToQualiferEdge)
	}
	err := assembler.StoreGraph(assemblerinput, c.driver)
	if err != nil {
		return err
	}
	return nil
}

func (c *neo4jClient) registerSource(sourceType, namespace, name, qualifier string) error {
	collectedSrc := &srcNode{}
	collectedType := &srcType{srcType: sourceType}
	collectedNamespace := &srcNamespace{namespace: namespace}
	collectedName := &srcName{name: name}
	if qualifier != "" {
		pair := strings.Split(qualifier, "=")
		if pair[0] == "tag" {
			collectedName.tag = pair[1]
		} else {
			collectedName.commit = pair[1]
		}
	}

	srcToTypeEdge := &srcToType{collectedSrc, collectedType}
	typetoNamespaceEdge := &srcTypeToNamespace{collectedType, collectedNamespace}
	namespaceToNameEdge := &srcNamespaceToName{collectedNamespace, collectedName}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedSrc, collectedType, collectedNamespace, collectedName},
		Edges: []assembler.GuacEdge{srcToTypeEdge, typetoNamespaceEdge, namespaceToNameEdge},
	}
	err := assembler.StoreGraph(assemblerinput, c.driver)
	if err != nil {
		return err
	}
	return nil
}
