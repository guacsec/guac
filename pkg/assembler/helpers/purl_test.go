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
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
)

var cmpOpts = []cmp.Option{
	cmpopts.SortSlices(func(a, b model.PackageQualifierInputSpec) bool { return a.Key < b.Key }),
}

func TestPurlConvert(t *testing.T) {
	testCases := []struct {
		purlUri  string
		expected *model.PkgInputSpec
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
			purlUri:  "pkg:docker/customer/dockerimage@sha256%3A244fd47e07d10?repository_url=gcr.io",
			expected: pkg("docker", "gcr.io/customer", "dockerimage", "sha256:244fd47e07d10", "", map[string]string{}),
		}, {
			purlUri:  "pkg:oci/docker.io/library/alpine@sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870?tag=latest&repository_url=docker.io%2Flibrary",
			expected: pkg("oci", "docker.io/library", "alpine", "sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870", "", map[string]string{"tag": "latest"}),
		}, {
			purlUri:  "pkg:oci/debian@sha256:244fd47e07d10?arch=amd64&tag=latest&repository_url=docker.io%2Flibrary",
			expected: pkg("oci", "docker.io/library", "debian", "sha256:244fd47e07d10", "", map[string]string{"arch": "amd64", "tag": "latest"}),
		}, {
			// test case based on OCI PURLs that may not include repository_url.
			purlUri:  "pkg:oci/docker.io/library/alpine@sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870",
			expected: pkg("oci", "docker.io/library", "alpine", "sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870", "", map[string]string{}),
		},

		{
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
			purlUri:  "pkg:githubactions/shufo/auto-assign-reviewer-by-files@1.1.4",
			expected: pkg("githubactions", "shufo", "auto-assign-reviewer-by-files", "1.1.4", "", map[string]string{}),
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

func TestPkgInputSpecToPurl(t *testing.T) {
	testCases := []struct {
		expectedPurlUri string
		input           *model.PkgInputSpec
	}{
		{
			// alpine
			expectedPurlUri: "pkg:alpm/arch/pacman@6.0.1-1?arch=x86_64",
			input: pkg("alpm", "arch", "pacman", "6.0.1-1", "", map[string]string{
				"arch": "x86_64",
			}),
		}, {
			expectedPurlUri: "pkg:apk/alpine/curl@7.83.0-r0?arch=x86",
			input: pkg("apk", "alpine", "curl", "7.83.0-r0", "", map[string]string{
				"arch": "x86",
			}),
		}, {
			expectedPurlUri: "pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c",
			input:           pkg("bitbucket", "birkenfeld", "pygments-main", "244fd47e07d1014f0aed9c", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:cocoapods/ShareKit@2.0#Twitter",
			input:           pkg("cocoapods", "", "ShareKit", "2.0", "Twitter", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:cargo/rand@0.7.2",
			input:           pkg("cargo", "", "rand", "0.7.2", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:composer/laravel/laravel@5.5.0",
			input:           pkg("composer", "laravel", "laravel", "5.5.0", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:conan/openssl.org/openssl@3.0.3?channel=stable&user=bincrafters",
			input: pkg("conan", "openssl.org", "openssl", "3.0.3", "", map[string]string{
				"user":    "bincrafters",
				"channel": "stable",
			}),
		}, {
			expectedPurlUri: "pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=main&subdir=linux-64&type=tar.bz2",
			input: pkg("conda", "", "absl-py", "0.4.1", "", map[string]string{
				"build":   "py36h06a4308_0",
				"channel": "main",
				"subdir":  "linux-64",
				"type":    "tar.bz2",
			}),
		}, {
			expectedPurlUri: "pkg:cran/A3@1.0.0",
			input:           pkg("cran", "", "A3", "1.0.0", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:deb/debian/dpkg@1.19.0.4?arch=amd64&distro=stretch",
			input: pkg("deb", "debian", "dpkg", "1.19.0.4", "", map[string]string{
				"arch":   "amd64",
				"distro": "stretch",
			}),
		}, {
			// The following are for docker PURLs
			expectedPurlUri: "pkg:docker/dockerimage@sha256%3A244fd47e07d10?repository_url=gcr.io%2Fcustomer",
			input:           pkg("docker", "gcr.io/customer", "dockerimage", "sha256:244fd47e07d10", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:docker/debian@dc437cc87d10?repository_url=smartentry",
			input:           pkg("docker", "smartentry", "debian", "dc437cc87d10", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:docker/cassandra@latest",
			input:           pkg("docker", "", "cassandra", "latest", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:gem/ruby-advisory-db-check@0.12.4",
			input:           pkg("gem", "", "ruby-advisory-db-check", "0.12.4", "", map[string]string{}),
		}, {
			// TODO (Issue #635): url path escapes here? Will this be an issue when searching via purl in osv or deps.dev?
			expectedPurlUri: "pkg:generic/openssl@1.1.10g?checksum=sha256%3Ade4d501267da&download_url=https%3A%2F%2Fopenssl.org%2Fsource%2Fopenssl-1.1.0g.tar.gz",
			input: pkg("generic", "", "openssl", "1.1.10g", "", map[string]string{
				"download_url": "https://openssl.org/source/openssl-1.1.0g.tar.gz",
				"checksum":     "sha256:de4d501267da",
			}),
		}, {
			expectedPurlUri: "pkg:generic/bitwarderl?vcs_url=git%2Bhttps%3A%2F%2Fgit.fsfe.org%2Fdxtr%2Fbitwarderl%40cc55108da32",
			input: pkg("generic", "", "bitwarderl", "", "", map[string]string{
				"vcs_url": "git+https://git.fsfe.org/dxtr/bitwarderl@cc55108da32",
			}),
		}, {
			expectedPurlUri: "pkg:github/package-url/purl-spec@244fd47e07d1004#everybody/loves/dogs",
			input:           pkg("github", "package-url", "purl-spec", "244fd47e07d1004", "everybody/loves/dogs", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c#api",
			input:           pkg("golang", "github.com/gorilla", "context", "234fd47e07d1004f0aed9c", "api", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:hackage/3d-graphics-examples@0.0.0.2",
			input:           pkg("hackage", "", "3d-graphics-examples", "0.0.0.2", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:hex/bar@1.2.3?repository_url=https%3A%2F%2Fmyrepo.example.com",
			input: pkg("hex", "", "bar", "1.2.3", "", map[string]string{
				"repository_url": "https://myrepo.example.com",
			}),
		}, {
			expectedPurlUri: "pkg:hex/jason@1.1.2",
			input:           pkg("hex", "", "jason", "1.1.2", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:huggingface/distilbert-base-uncased@043235d6088ecd3dd5fb5ca3592b6913fd516027",
			input:           pkg("huggingface", "", "distilbert-base-uncased", "043235d6088ecd3dd5fb5ca3592b6913fd516027", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?classifier=dist&type=zip",
			input: pkg("maven", "org.apache.xmlgraphics", "batik-anim", "1.9.1", "", map[string]string{
				"type":       "zip",
				"classifier": "dist",
			}),
		}, {
			expectedPurlUri: "pkg:mlflow/trafficsigns@10?model_uuid=36233173b22f4c89b451f1228d700d49&repository_url=https%3A%2F%2Fadb-5245952564735461.0.azuredatabricks.net%2Fapi%2F2.0%2Fmlflow&run_id=410a3121-2709-4f88-98dd-dba0ef056b0a",
			input: pkg("mlflow", "", "trafficsigns", "10", "", map[string]string{
				"model_uuid":     "36233173b22f4c89b451f1228d700d49",
				"run_id":         "410a3121-2709-4f88-98dd-dba0ef056b0a",
				"repository_url": "https://adb-5245952564735461.0.azuredatabricks.net/api/2.0/mlflow",
			}),
		}, {
			expectedPurlUri: "pkg:npm/foobar@12.3.1",
			input:           pkg("npm", "", "foobar", "12.3.1", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:npm/%40angular/animation@12.3.1",
			input:           pkg("npm", "@angular", "animation", "12.3.1", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
			input:           pkg("nuget", "", "EnterpriseLibrary.Common", "6.0.1304", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:qpkg/blackberry/com.qnx.sdp@7.0.0.SGA201702151847",
			input:           pkg("qpkg", "blackberry", "com.qnx.sdp", "7.0.0.SGA201702151847", "", map[string]string{}),
		}, {
			// Special OCI case
			expectedPurlUri: "pkg:oci/debian@sha256%3A244fd47e07d10?arch=amd64&repository_url=docker.io%2Flibrary&tag=latest",
			input: pkg("oci", "docker.io/library", "debian", "sha256:244fd47e07d10", "", map[string]string{
				"arch": "amd64",
				"tag":  "latest",
			}),
		}, {
			expectedPurlUri: "pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io&tag=bullseye",
			input: pkg("oci", "ghcr.io", "debian", "sha256:244fd47e07d10", "", map[string]string{
				"tag": "bullseye",
			}),
		}, {
			expectedPurlUri: "pkg:oci/hello-wasm@sha256%3A244fd47e07d10?tag=v1",
			input: pkg("oci", "", "hello-wasm", "sha256:244fd47e07d10", "", map[string]string{
				"tag": "v1",
			}),
		}, {
			expectedPurlUri: "pkg:pub/characters@1.2.0",
			input:           pkg("pub", "", "characters", "1.2.0", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:pypi/django-allauth@12.23",
			input:           pkg("pypi", "", "django-allauth", "12.23", "", map[string]string{}),
		}, {
			expectedPurlUri: "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
			input: pkg("rpm", "fedora", "curl", "7.50.3-1.fc25", "", map[string]string{
				"arch":   "i386",
				"distro": "fedora-25",
			}),
		}, {
			expectedPurlUri: "pkg:swid/Acme/example.com/Enterprise%2BServer@1.0.0?tag_id=75b8c285-fa7b-485b-b199-4745e3004d0d",
			input: pkg("swid", "Acme/example.com", "Enterprise+Server", "1.0.0", "", map[string]string{
				"tag_id": "75b8c285-fa7b-485b-b199-4745e3004d0d",
			}),
		}, {
			expectedPurlUri: "pkg:swift/github.com/RxSwiftCommunity/RxFlow@2.12.4",
			input:           pkg("swift", "github.com/RxSwiftCommunity", "RxFlow", "2.12.4", "", map[string]string{}),
		},
	}
	for _, tt := range testCases {
		t.Run(fmt.Sprintf("processing %v", tt.expectedPurlUri), func(t *testing.T) {
			got := PkgInputSpecToPurl(tt.input)
			if got != tt.expectedPurlUri {
				t.Errorf("purl mismatch wanted: %s, got: %s", tt.expectedPurlUri, got)
				return
			}
		})
	}
}

func TestPkgToPurl(t *testing.T) {
	testCases := []struct {
		expectedPurlUri string
		pkgType         string
		namespace       string
		name            string
		version         string
		subpath         string
		qualifiers      []string
	}{
		{
			// alpine
			expectedPurlUri: "pkg:alpm/arch/pacman@6.0.1-1?arch=x86_64",
			pkgType:         "alpm",
			namespace:       "arch",
			name:            "pacman",
			version:         "6.0.1-1",
			subpath:         "",
			qualifiers:      []string{"arch", "x86_64"},
		}, {
			expectedPurlUri: "pkg:apk/alpine/curl@7.83.0-r0?arch=x86",
			pkgType:         "apk",
			namespace:       "alpine",
			name:            "curl",
			version:         "7.83.0-r0",
			qualifiers:      []string{"arch", "x86"},
		}, {
			expectedPurlUri: "pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c",
			pkgType:         "bitbucket",
			namespace:       "birkenfeld",
			name:            "pygments-main",
			version:         "244fd47e07d1014f0aed9c",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:cocoapods/ShareKit@2.0#Twitter",
			pkgType:         "cocoapods",
			namespace:       "",
			name:            "ShareKit",
			version:         "2.0",
			subpath:         "Twitter",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:cargo/rand@0.7.2",
			pkgType:         "cargo",
			namespace:       "",
			name:            "rand",
			version:         "0.7.2",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:composer/laravel/laravel@5.5.0",
			pkgType:         "composer",
			namespace:       "laravel",
			name:            "laravel",
			version:         "5.5.0",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:conan/openssl.org/openssl@3.0.3?channel=stable&user=bincrafters",
			pkgType:         "conan",
			namespace:       "openssl.org",
			name:            "openssl",
			version:         "3.0.3",
			subpath:         "",
			qualifiers:      []string{"channel", "stable", "user", "bincrafters"},
		}, {
			expectedPurlUri: "pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=main&subdir=linux-64&type=tar.bz2",
			pkgType:         "conda",
			namespace:       "",
			name:            "absl-py",
			version:         "0.4.1",
			subpath:         "",
			qualifiers:      []string{"build", "py36h06a4308_0", "channel", "main", "subdir", "linux-64", "type", "tar.bz2"},
		}, {
			expectedPurlUri: "pkg:cran/A3@1.0.0",
			pkgType:         "cran",
			namespace:       "",
			name:            "A3",
			version:         "1.0.0",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:deb/debian/dpkg@1.19.0.4?arch=amd64&distro=stretch",
			pkgType:         "deb",
			namespace:       "debian",
			name:            "dpkg",
			version:         "1.19.0.4",
			subpath:         "",
			qualifiers:      []string{"arch", "amd64", "distro", "stretch"},
		}, {
			// The following are for docker PURLs
			expectedPurlUri: "pkg:docker/dockerimage@sha256%3A244fd47e07d10?repository_url=gcr.io%2Fcustomer",
			pkgType:         "docker",
			namespace:       "gcr.io/customer",
			name:            "dockerimage",
			version:         "sha256:244fd47e07d10",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:docker/debian@dc437cc87d10?repository_url=smartentry",
			pkgType:         "docker",
			namespace:       "smartentry",
			name:            "debian",
			version:         "dc437cc87d10",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:docker/cassandra@latest",
			pkgType:         "docker",
			namespace:       "",
			name:            "cassandra",
			version:         "latest",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:gem/ruby-advisory-db-check@0.12.4",
			pkgType:         "gem",
			namespace:       "",
			name:            "ruby-advisory-db-check",
			version:         "0.12.4",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:generic/openssl@1.1.10g?checksum=sha256%3Ade4d501267da&download_url=https%3A%2F%2Fopenssl.org%2Fsource%2Fopenssl-1.1.0g.tar.gz",
			pkgType:         "generic",
			namespace:       "",
			name:            "openssl",
			version:         "1.1.10g",
			subpath:         "",
			qualifiers:      []string{"download_url", "https://openssl.org/source/openssl-1.1.0g.tar.gz", "checksum", "sha256:de4d501267da"},
		}, {
			expectedPurlUri: "pkg:generic/bitwarderl?vcs_url=git%2Bhttps%3A%2F%2Fgit.fsfe.org%2Fdxtr%2Fbitwarderl%40cc55108da32",
			pkgType:         "generic",
			namespace:       "",
			name:            "bitwarderl",
			version:         "",
			subpath:         "",
			qualifiers:      []string{"vcs_url", "git+https://git.fsfe.org/dxtr/bitwarderl@cc55108da32"},
		}, {
			expectedPurlUri: "pkg:github/package-url/purl-spec@244fd47e07d1004#everybody/loves/dogs",
			pkgType:         "github",
			namespace:       "package-url",
			name:            "purl-spec",
			version:         "244fd47e07d1004",
			subpath:         "everybody/loves/dogs",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c#api",
			pkgType:         "golang",
			namespace:       "github.com/gorilla",
			name:            "context",
			version:         "234fd47e07d1004f0aed9c",
			subpath:         "api",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:hackage/3d-graphics-examples@0.0.0.2",
			pkgType:         "hackage",
			namespace:       "",
			name:            "3d-graphics-examples",
			version:         "0.0.0.2",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:hex/bar@1.2.3?repository_url=https%3A%2F%2Fmyrepo.example.com",
			pkgType:         "hex",
			namespace:       "",
			name:            "bar",
			version:         "1.2.3",
			subpath:         "",
			qualifiers:      []string{"repository_url", "https://myrepo.example.com"},
		}, {
			expectedPurlUri: "pkg:hex/jason@1.1.2",
			pkgType:         "hex",
			namespace:       "",
			name:            "jason",
			version:         "1.1.2",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:huggingface/distilbert-base-uncased@043235d6088ecd3dd5fb5ca3592b6913fd516027",
			pkgType:         "huggingface",
			namespace:       "",
			name:            "distilbert-base-uncased",
			version:         "043235d6088ecd3dd5fb5ca3592b6913fd516027",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?classifier=dist&type=zip",
			pkgType:         "maven",
			namespace:       "org.apache.xmlgraphics",
			name:            "batik-anim",
			version:         "1.9.1",
			subpath:         "",
			qualifiers:      []string{"type", "zip", "classifier", "dist"},
		}, {
			expectedPurlUri: "pkg:mlflow/trafficsigns@10?model_uuid=36233173b22f4c89b451f1228d700d49&repository_url=https%3A%2F%2Fadb-5245952564735461.0.azuredatabricks.net%2Fapi%2F2.0%2Fmlflow&run_id=410a3121-2709-4f88-98dd-dba0ef056b0a",
			pkgType:         "mlflow",
			namespace:       "",
			name:            "trafficsigns",
			version:         "10",
			subpath:         "",
			qualifiers:      []string{"model_uuid", "36233173b22f4c89b451f1228d700d49", "run_id", "410a3121-2709-4f88-98dd-dba0ef056b0a", "repository_url", "https://adb-5245952564735461.0.azuredatabricks.net/api/2.0/mlflow"},
		}, {
			expectedPurlUri: "pkg:npm/foobar@12.3.1",
			pkgType:         "npm",
			namespace:       "",
			name:            "foobar",
			version:         "12.3.1",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:npm/%40angular/animation@12.3.1",
			pkgType:         "npm",
			namespace:       "@angular",
			name:            "animation",
			version:         "12.3.1",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
			pkgType:         "nuget",
			namespace:       "",
			name:            "EnterpriseLibrary.Common",
			version:         "6.0.1304",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:qpkg/blackberry/com.qnx.sdp@7.0.0.SGA201702151847",
			pkgType:         "qpkg",
			namespace:       "blackberry",
			name:            "com.qnx.sdp",
			version:         "7.0.0.SGA201702151847",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			// Special OCI case
			expectedPurlUri: "pkg:oci/debian@sha256%3A244fd47e07d10?arch=amd64&repository_url=docker.io%2Flibrary&tag=latest",
			pkgType:         "oci",
			namespace:       "docker.io/library",
			name:            "debian",
			version:         "sha256:244fd47e07d10",
			subpath:         "",
			qualifiers:      []string{"arch", "amd64", "tag", "latest"},
		}, {
			expectedPurlUri: "pkg:oci/debian@sha256%3A244fd47e07d10?repository_url=ghcr.io&tag=bullseye",
			pkgType:         "oci",
			namespace:       "ghcr.io",
			name:            "debian",
			version:         "sha256:244fd47e07d10",
			subpath:         "",
			qualifiers:      []string{"tag", "bullseye"},
		}, {
			expectedPurlUri: "pkg:oci/hello-wasm@sha256%3A244fd47e07d10?tag=v1",
			pkgType:         "oci",
			namespace:       "",
			name:            "hello-wasm",
			version:         "sha256:244fd47e07d10",
			subpath:         "",
			qualifiers:      []string{"tag", "v1"},
		}, {
			expectedPurlUri: "pkg:pub/characters@1.2.0",
			pkgType:         "pub",
			namespace:       "",
			name:            "characters",
			version:         "1.2.0",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:pypi/django-allauth@12.23",
			pkgType:         "pypi",
			namespace:       "",
			name:            "django-allauth",
			version:         "12.23",
			subpath:         "",
			qualifiers:      []string{},
		}, {
			expectedPurlUri: "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
			pkgType:         "rpm",
			namespace:       "fedora",
			name:            "curl",
			version:         "7.50.3-1.fc25",
			subpath:         "",
			qualifiers:      []string{"arch", "i386", "distro", "fedora-25"},
		}, {
			expectedPurlUri: "pkg:swid/Acme/example.com/Enterprise%2BServer@1.0.0?tag_id=75b8c285-fa7b-485b-b199-4745e3004d0d",
			pkgType:         "swid",
			namespace:       "Acme/example.com",
			name:            "Enterprise+Server",
			version:         "1.0.0",
			subpath:         "",
			qualifiers:      []string{"tag_id", "75b8c285-fa7b-485b-b199-4745e3004d0d"},
		}, {
			expectedPurlUri: "pkg:swift/github.com/RxSwiftCommunity/RxFlow@2.12.4",
			pkgType:         "swift",
			namespace:       "github.com/RxSwiftCommunity",
			name:            "RxFlow",
			version:         "2.12.4",
			subpath:         "",
			qualifiers:      []string{},
		},
	}
	for _, tt := range testCases {
		t.Run(fmt.Sprintf("processing %v", tt.expectedPurlUri), func(t *testing.T) {
			got := PkgToPurl(tt.pkgType, tt.namespace, tt.name, tt.version, tt.subpath, tt.qualifiers)
			if got != tt.expectedPurlUri {
				t.Errorf("purl mismatch wanted: %s, got: %s", tt.expectedPurlUri, got)
				return
			}
		})
	}
}

func TestGuacPkgPurl(t *testing.T) {
	testCases := []struct {
		pkgName    string
		pkgVersion *string
		expected   string
	}{
		{
			pkgName:    "hello",
			pkgVersion: strP("1.2"),
			expected:   "pkg:guac/pkg/hello@1.2",
		},
		{
			pkgName:    "hello",
			pkgVersion: nil,
			expected:   "pkg:guac/pkg/hello",
		},
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("processing %v@%v", tt.pkgName, tt.pkgVersion), func(t *testing.T) {
			got := GuacPkgPurl(tt.pkgName, tt.pkgVersion)
			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Errorf("model Package mismatch (-want +got):\n%s", diff)
				return
			}
		})
	}
}

func TestGuacFilePurl(t *testing.T) {
	testCases := []struct {
		alg      string
		digest   string
		filename *string
		expected string
	}{
		{
			alg:      "sha256",
			digest:   "cf194aa4315da360a262ff73ce63e2ff68a128c3a9ee7d97163c998fd1690cec",
			filename: strP("/test/path"),
			expected: "pkg:guac/files/sha256:cf194aa4315da360a262ff73ce63e2ff68a128c3a9ee7d97163c998fd1690cec#/test/path",
		},
		{
			alg:      "sha256",
			digest:   "cf194aa4315da360a262ff73ce63e2ff68a128c3a9ee7d97163c998fd1690cec",
			filename: nil,
			expected: "pkg:guac/files/sha256:cf194aa4315da360a262ff73ce63e2ff68a128c3a9ee7d97163c998fd1690cec",
		},
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("processing %v:%v (filename: %v)", tt.alg, tt.digest, tt.filename), func(t *testing.T) {
			got := GuacFilePurl(tt.alg, tt.digest, tt.filename)
			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Errorf("model Package mismatch (-want +got):\n%s", diff)
				return
			}
		})
	}
}

func strP(s string) *string {
	return &s
}
