//
// Copyright 2024 The GUAC Authors.
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

package coordinates

import (
	"fmt"
	"strings"

	purl "github.com/package-url/packageurl-go"
)

type Coordinate struct {
	coordinateType string
	provider       string
	namespace      string
	name           string
	revision       string
}

/*
Purl to coordinate mapping
Examples below illustrate coordinates for each of the following purl type supported. In general, the following holds true:

purl type = type in coordinates
purl namespace = namespace in coordinates
purl name = name in coordinates
purl version = revision in coordinates

There are some exceptions however, which are provided in the notes below.

cocoapods https://cdn.cocoapods.org/
-> pod (in coordinates)
e.g. pod/cocoapods/-/SoftButton/0.1.0

cargo https://crates.io/
-> crate (in coordinates)
e.g. crate/cratesio/-/bitflags/1.0.4

composer https://packagist.org
-> composer (in coordinates)
e.g. composer/packagist/symfony/polyfill-mbstring/1.11.0

conda https://repo.anaconda.com
-> conda (in coordinates)
e.g. conda/conda-forge/linux-aarch64/numpy/1.16.6-py36hdc1b780_0
notes:

channel -> provider in coordinates (3 providers: anaconda-main, anaconda-r, conda-forge)
subdir -> namespace in coordinates
version-build -> revision in coordinates
e.g.
pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=main&subdir=linux-64&type=tar.bz2
-> conda/anaconda-main/linux-64/absl-py/0.4.1-py36h06a4308_0

deb
-> deb (in coordinates)
e.g. deb/debian/-/mini-httpd/1.30-0.2_arm64
notes:

version_architecture -> revision in coordinates

source component: arch=source in purl -> debsrc type in coordinates,

e.g. debsrc/debian/-/mini-httpd/1.30-0.2

gem https://rubygems.org
-> gem (in coordinates)
e.g. gem/rubygems/-/sorbet/0.5.11226

github https://github.com
-> git/github (type/provider in coordinates)
e.g. git/github/ratatui-org/ratatui/bcf43688ec4a13825307aef88f3cdcd007b32641

golang for Go packages:
-> go (in coordinates)
e.g. go/golang/rsc.io/quote/v1.3.0
notes:

component name is url encoded.
maven https://repo.maven.apache.org/maven2
-> maven (in coordinates)
notes:

three providers: mavencentral, mavengoogle and gradleplugin
e.g.
maven/mavencentral/org.apache.httpcomponents/httpcore/4.3
maven/mavengoogle/android.arch.lifecycle/common/1.0.1
maven/gradleplugin/io.github.lognet/grpc-spring-boot-starter-gradle-plugin/4.6.0
source component:
e.g. sourcearchive/mavencentral/org.apache.httpcomponents/httpcore/4.3
npm
-> npm (in coordinates)
e.g. npm/npmjs/-/redis/0.1.0
notes:

namespace is used for scope
nuget: https://www.nuget.org
-> nuget (in coordinates)
e.g. nuget/nuget/-/xunit.core/2.4.1

pypi https://pypi.org
-> pypi (in coordinates)
e.g. pypi/pypi/-/backports.ssl_match_hostname/3.7.0.1
*/

func ConvertPurlToCoordinate(purlUri string) (*Coordinate, error) {
	pkg, err := purl.FromString(purlUri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse purl into a package with error: %w", err)
	}
	switch pkg.Type {
	case "cocoapods":
		return &Coordinate{
			coordinateType: "pod",
			provider:       "cocoapods",
			namespace:      "-",
			name:           pkg.Name,
			revision:       pkg.Version,
		}, nil
	case "cargo":
		return &Coordinate{
			coordinateType: "crate",
			provider:       "cratesio",
			namespace:      "-",
			name:           pkg.Name,
			revision:       pkg.Version,
		}, nil
	case "composer":
		return &Coordinate{
			coordinateType: pkg.Type,
			provider:       "packagist",
			namespace:      pkg.Namespace,
			name:           pkg.Name,
			revision:       pkg.Version,
		}, nil
	case "conda":
		// channel -> provider in coordinates (3 providers: anaconda-main, anaconda-r, conda-forge)
		var provider string
		qualifiers := pkg.Qualifiers.Map()
		if channel, ok := qualifiers["channel"]; ok {
			switch channel {
			case "main":
				provider = "anaconda-main"
			case "conda-forge":
				provider = "conda-forge"
			case "anaconda-r":
				provider = "anaconda-r"
			default:
				return nil, fmt.Errorf("channel does not match provider: %s", channel)
			}
		} else {
			return nil, fmt.Errorf("conda provider cannot be determined")
		}

		// version-build -> revision in coordinates
		var revision string
		if build, ok := qualifiers["build"]; ok {
			revision = pkg.Version + "-" + build
		} else {
			revision = pkg.Version
		}

		// subdir is the associated platform
		var namespace string
		if subdir, ok := qualifiers["subdir"]; ok {
			namespace = subdir
		} else {
			return nil, fmt.Errorf("failed to find subdir for conda")
		}

		return &Coordinate{
			coordinateType: pkg.Type,
			provider:       provider,
			namespace:      namespace,
			name:           pkg.Name,
			revision:       revision,
		}, nil

	case "deb":
		// channel -> provider in coordinates (3 providers: anaconda-main, anaconda-r, conda-forge)
		var pkgType string
		var revision string
		qualifiers := pkg.Qualifiers.Map()
		if arch, ok := qualifiers["arch"]; ok {
			if arch == "source" {
				// source component: arch=source in purl -> debsrc type in coordinates
				pkgType = "debsrc"
				revision = pkg.Version
			} else {
				pkgType = "deb"
				// version_architecture -> revision in coordinates
				revision = pkg.Version + "_" + arch
			}
		} else {
			pkgType = "deb"
			revision = pkg.Version
		}

		return &Coordinate{
			coordinateType: pkgType,
			provider:       "debian",
			namespace:      "-",
			name:           pkg.Name,
			revision:       revision,
		}, nil
	case "gem":
		return &Coordinate{
			coordinateType: pkg.Type,
			provider:       "rubygems",
			namespace:      "-",
			name:           pkg.Name,
			revision:       pkg.Version,
		}, nil
	case "github":
		return &Coordinate{
			coordinateType: "git",
			provider:       pkg.Type,
			namespace:      pkg.Namespace,
			name:           pkg.Name,
			revision:       pkg.Version,
		}, nil
	case "golang":
		return &Coordinate{
			coordinateType: "go",
			provider:       pkg.Type,
			namespace:      pkg.Namespace,
			name:           pkg.Name,
			revision:       pkg.Version,
		}, nil
	case "maven":
		// maven is a unique case where it can have 3 providers
		// and there is no real way to know which it is. Trying
		// the current heuristics
		var provider string
		if strings.Contains(pkg.Namespace, "android") {
			provider = "mavengoogle"
		} else if strings.Contains(pkg.Name, "gradle") {
			provider = "gradleplugin"
		} else {
			provider = "mavencentral"
		}

		return &Coordinate{
			coordinateType: "maven",
			provider:       provider,
			namespace:      pkg.Namespace,
			name:           pkg.Name,
			revision:       pkg.Version,
		}, nil
	case "npm":
		return &Coordinate{
			coordinateType: pkg.Type,
			provider:       "npmjs",
			namespace:      pkg.Namespace,
			name:           pkg.Name,
			revision:       pkg.Version,
		}, nil
	case "nuget":
		return &Coordinate{
			coordinateType: pkg.Type,
			provider:       "nuget",
			namespace:      "-",
			name:           pkg.Name,
			revision:       pkg.Version,
		}, nil
	case "pypi":
		// purl: PyPI treats - and _ as the same character
		// and is not case sensitive. Therefore a PyPI
		// package name must be lowercased and
		// underscore _ replaced with a dash -.
		return &Coordinate{
			coordinateType: pkg.Type,
			provider:       "pypi",
			namespace:      "-",
			name:           pkg.Name,
			revision:       pkg.Version,
		}, nil
	}
	return nil, fmt.Errorf("failed to get coordinates from purl: %s", purlUri)
}
