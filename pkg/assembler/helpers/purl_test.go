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

package helpers

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var cmpOpts = []cmp.Option{
	cmpopts.SortSlices(func(a, b *model.PackageQualifier) bool { return a.Key < b.Key }),
}

func TestPurlConvert(t *testing.T) {
	testCases := []struct {
		purlUri  string
		expected *model.Package
	}{
		{
			// alpine
			purlUri: "pkg:alpm/arch/pacman@6.0.1-1?arch=x86_64",
			expected: pkg("alpm", "arch", "pacman", "6.0.1-1", "", map[string]string{
				"arch": "x86_64",
			}),
		}, {
			purlUri: "pkg:apk/alpine/curl@7.83.0-r0?arch=x86",
			expected: pkg("apk", "alpine", "curl", "7.83.0-r0", "", map[string]string{
				"arch": "x86",
			}),
		}, {
			purlUri:  "pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c",
			expected: pkg("bitbucket", "birkenfeld", "pygments-main", "244fd47e07d1014f0aed9c", "", map[string]string{}),
		}, {
			purlUri:  "pkg:cocoapods/ShareKit@2.0#Twitter",
			expected: pkg("cocoapods", "", "ShareKit", "2.0", "Twitter", map[string]string{}),
		}, {
			purlUri:  "pkg:cargo/rand@0.7.2",
			expected: pkg("cargo", "", "rand", "0.7.2", "", map[string]string{}),
		}, {
			purlUri:  "pkg:composer/laravel/laravel@5.5.0",
			expected: pkg("composer", "laravel", "laravel", "5.5.0", "", map[string]string{}),
		}, {
			purlUri: "pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable",
			expected: pkg("conan", "openssl.org", "openssl", "3.0.3", "", map[string]string{
				"user":    "bincrafters",
				"channel": "stable",
			}),
		}, {
			purlUri: "pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=main&subdir=linux-64&type=tar.bz2",
			expected: pkg("conda", "", "absl-py", "0.4.1", "", map[string]string{
				"build":   "py36h06a4308_0",
				"channel": "main",
				"subdir":  "linux-64",
				"type":    "tar.bz2",
			}),
		}, {
			purlUri:  "pkg:cran/A3@1.0.0",
			expected: pkg("cran", "", "A3", "1.0.0", "", map[string]string{}),
		}, {
			purlUri: "pkg:deb/debian/dpkg@1.19.0.4?arch=amd64&distro=stretch",
			expected: pkg("deb", "debian", "dpkg", "1.19.0.4", "", map[string]string{
				"arch":   "amd64",
				"distro": "stretch",
			}),
		}, {
			// The following are for docker PURLs
			// TODO(lumjjb): docker PURLs are really weird and potentially not well specified
			// due to the namespace indicating it may contain registry but the use of
			// repository_url in the examples. In addition, the versions use in the examples
			// use tags and potentially indicate truncated hashes.
			purlUri:  "pkg:docker/customer/dockerimage@sha256%3A244fd47e07d10?repository_url=gcr.io",
			expected: pkg("docker", "gcr.io/customer", "dockerimage", "sha256:244fd47e07d10", "", map[string]string{}),
		}, {
			purlUri:  "pkg:docker/smartentry/debian@dc437cc87d10",
			expected: pkg("docker", "smartentry", "debian", "dc437cc87d10", "", map[string]string{}),
		}, {
			purlUri:  "pkg:docker/cassandra@latest",
			expected: pkg("docker", "", "cassandra", "latest", "", map[string]string{}),
		}, {
			purlUri:  "pkg:gem/ruby-advisory-db-check@0.12.4",
			expected: pkg("gem", "", "ruby-advisory-db-check", "0.12.4", "", map[string]string{}),
		}, {
			purlUri: "pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz&checksum=sha256:de4d501267da",
			expected: pkg("generic", "", "openssl", "1.1.10g", "", map[string]string{
				"download_url": "https://openssl.org/source/openssl-1.1.0g.tar.gz",
				"checksum":     "sha256:de4d501267da",
			}),
		}, {
			purlUri: "pkg:generic/bitwarderl?vcs_url=git%2Bhttps://git.fsfe.org/dxtr/bitwarderl%40cc55108da32",
			expected: pkg("generic", "", "bitwarderl", "", "", map[string]string{
				"vcs_url": "git+https://git.fsfe.org/dxtr/bitwarderl@cc55108da32",
			}),
		}, {
			purlUri:  "pkg:github/package-url/purl-spec@244fd47e07d1004#everybody/loves/dogs",
			expected: pkg("github", "package-url", "purl-spec", "244fd47e07d1004", "everybody/loves/dogs", map[string]string{}),
		}, {
			purlUri:  "pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c#api",
			expected: pkg("golang", "github.com/gorilla", "context", "234fd47e07d1004f0aed9c", "api", map[string]string{}),
		}, {
			purlUri:  "pkg:hackage/3d-graphics-examples@0.0.0.2",
			expected: pkg("hackage", "", "3d-graphics-examples", "0.0.0.2", "", map[string]string{}),
		}, {
			purlUri: "pkg:hex/bar@1.2.3?repository_url=https://myrepo.example.com",
			expected: pkg("hex", "", "bar", "1.2.3", "", map[string]string{
				"repository_url": "https://myrepo.example.com",
			}),
		}, {
			purlUri:  "pkg:hex/jason@1.1.2",
			expected: pkg("hex", "", "jason", "1.1.2", "", map[string]string{}),
		}, {
			purlUri:  "pkg:huggingface/distilbert-base-uncased@043235d6088ecd3dd5fb5ca3592b6913fd516027",
			expected: pkg("huggingface", "", "distilbert-base-uncased", "043235d6088ecd3dd5fb5ca3592b6913fd516027", "", map[string]string{}),
		}, {
			purlUri: "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=zip&classifier=dist",
			expected: pkg("maven", "org.apache.xmlgraphics", "batik-anim", "1.9.1", "", map[string]string{
				"type":       "zip",
				"classifier": "dist",
			}),
		}, {
			purlUri: "pkg:mlflow/trafficsigns@10?model_uuid=36233173b22f4c89b451f1228d700d49&run_id=410a3121-2709-4f88-98dd-dba0ef056b0a&repository_url=https://adb-5245952564735461.0.azuredatabricks.net/api/2.0/mlflow",
			expected: pkg("mlflow", "", "trafficsigns", "10", "", map[string]string{
				"model_uuid":     "36233173b22f4c89b451f1228d700d49",
				"run_id":         "410a3121-2709-4f88-98dd-dba0ef056b0a",
				"repository_url": "https://adb-5245952564735461.0.azuredatabricks.net/api/2.0/mlflow",
			}),
		}, {
			purlUri:  "pkg:npm/foobar@12.3.1",
			expected: pkg("npm", "", "foobar", "12.3.1", "", map[string]string{}),
		}, {
			purlUri:  "pkg:npm/%40angular/animation@12.3.1",
			expected: pkg("npm", "@angular", "animation", "12.3.1", "", map[string]string{}),
		}, {
			purlUri:  "pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
			expected: pkg("nuget", "", "EnterpriseLibrary.Common", "6.0.1304", "", map[string]string{}),
		}, {
			purlUri:  "pkg:qpkg/blackberry/com.qnx.sdp@7.0.0.SGA201702151847",
			expected: pkg("qpkg", "blackberry", "com.qnx.sdp", "7.0.0.SGA201702151847", "", map[string]string{}),
		}, {
			// Special OCI case
			purlUri: "pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=docker.io/library/debian&arch=amd64&tag=latest",
			expected: pkg("oci", "docker.io/library", "debian", "sha256:244fd47e07d10", "", map[string]string{
				"arch": "amd64",
				"tag":  "latest",
			}),
		}, {
			purlUri: "pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io/debian&tag=bullseye",
			expected: pkg("oci", "ghcr.io", "debian", "sha256:244fd47e07d10", "", map[string]string{
				"tag": "bullseye",
			}),
		}, {
			purlUri: "pkg:oci/hello-wasm@sha256%3A244fd47e07d10?tag=v1",
			expected: pkg("oci", "", "hello-wasm", "sha256:244fd47e07d10", "", map[string]string{
				"tag": "v1",
			}),
		}, {
			purlUri:  "pkg:pub/characters@1.2.0",
			expected: pkg("pub", "", "characters", "1.2.0", "", map[string]string{}),
		}, {
			purlUri:  "pkg:pypi/django-allauth@12.23",
			expected: pkg("pypi", "", "django-allauth", "12.23", "", map[string]string{}),
		}, {
			purlUri: "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
			expected: pkg("rpm", "fedora", "curl", "7.50.3-1.fc25", "", map[string]string{
				"arch":   "i386",
				"distro": "fedora-25",
			}),
		}, {
			purlUri: "pkg:swid/Acme/example.com/Enterprise+Server@1.0.0?tag_id=75b8c285-fa7b-485b-b199-4745e3004d0d",
			expected: pkg("swid", "Acme/example.com", "Enterprise+Server", "1.0.0", "", map[string]string{
				"tag_id": "75b8c285-fa7b-485b-b199-4745e3004d0d",
			}),
		}, {
			purlUri:  "pkg:swift/github.com/RxSwiftCommunity/RxFlow@2.12.4",
			expected: pkg("swift", "github.com/RxSwiftCommunity", "RxFlow", "2.12.4", "", map[string]string{}),
		},
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("processing %v", tt.purlUri), func(t *testing.T) {
			got, err := PurlToPkg(tt.purlUri)
			if err != nil {
				t.Errorf("unable to parse purl %v: %v", tt.purlUri, err)
				return
			}
			if diff := cmp.Diff(tt.expected, got, cmpOpts...); diff != "" {
				t.Errorf("model Package mismatch (-want +got):\n%s", diff)
				return
			}
		})
	}
}
