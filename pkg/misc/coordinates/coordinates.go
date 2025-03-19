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
	"golang.org/x/mod/semver"
)

type Coordinate struct {
	CoordinateType string
	Provider       string
	Namespace      string
	Name           string
	Revision       string
}

/*
Purl to coordinate mapping
Examples below illustrate coordinates for each of the following purl type supported. In general, the following holds true:

purl type = type in coordinates
purl Namespace = Namespace in coordinates
purl Name = Name in coordinates
purl version = Revision in coordinates

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

channel -> Provider in coordinates (3 Providers: anaconda-main, anaconda-r, conda-forge)
subdir -> Namespace in coordinates
version-build -> Revision in coordinates
e.g.
pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=main&subdir=linux-64&type=tar.bz2
-> conda/anaconda-main/linux-64/absl-py/0.4.1-py36h06a4308_0

deb
-> deb (in coordinates)
e.g. deb/debian/-/mini-httpd/1.30-0.2_arm64
notes:

version_architecture -> Revision in coordinates

source component: arch=source in purl -> debsrc type in coordinates,

e.g. debsrc/debian/-/mini-httpd/1.30-0.2

gem https://rubygems.org
-> gem (in coordinates)
e.g. gem/rubygems/-/sorbet/0.5.11226

github https://github.com
-> git/github (type/Provider in coordinates)
e.g. git/github/ratatui-org/ratatui/bcf43688ec4a13825307aef88f3cdcd007b32641

golang for Go packages:
-> go (in coordinates)
e.g. go/golang/rsc.io/quote/v1.3.0
notes:

component Name is url encoded.
maven https://repo.maven.apache.org/maven2
-> maven (in coordinates)
notes:

three Providers: mavencentral, mavengoogle and gradleplugin
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

Namespace is used for scope
nuget: https://www.nuget.org
-> nuget (in coordinates)
e.g. nuget/nuget/-/xunit.core/2.4.1

pypi https://pypi.org
-> pypi (in coordinates)
e.g. pypi/pypi/-/backports.ssl_match_hostName/3.7.0.1
*/

func ConvertPurlToCoordinate(purlUri string) (*Coordinate, error) {
	pkg, err := purl.FromString(purlUri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse purl into a package with error: %w", err)
	}
	switch pkg.Type {
	case "cocoapods":
		return &Coordinate{
			CoordinateType: "pod",
			Provider:       "cocoapods",
			Namespace:      emptyToHyphen(pkg.Namespace),
			Name:           pkg.Name,
			Revision:       pkg.Version,
		}, nil
	case "cargo":
		return &Coordinate{
			CoordinateType: "crate",
			Provider:       "cratesio",
			Namespace:      emptyToHyphen(pkg.Namespace),
			Name:           pkg.Name,
			Revision:       pkg.Version,
		}, nil
	case "composer":
		return &Coordinate{
			CoordinateType: pkg.Type,
			Provider:       "packagist",
			Namespace:      emptyToHyphen(pkg.Namespace),
			Name:           pkg.Name,
			Revision:       pkg.Version,
		}, nil
	case "conda":
		// channel -> Provider in coordinates (3 Providers: anaconda-main, anaconda-r, conda-forge)
		var Provider string
		qualifiers := pkg.Qualifiers.Map()
		if channel, ok := qualifiers["channel"]; ok {
			switch channel {
			case "main":
				Provider = "anaconda-main"
			case "conda-forge":
				Provider = "conda-forge"
			case "anaconda-r":
				Provider = "anaconda-r"
			default:
				return nil, fmt.Errorf("channel does not match Provider: %s", channel)
			}
		} else {
			return nil, fmt.Errorf("conda Provider cannot be determined")
		}

		// version-build -> Revision in coordinates
		var Revision string
		if build, ok := qualifiers["build"]; ok {
			Revision = pkg.Version + "-" + build
		} else {
			Revision = pkg.Version
		}

		// subdir is the associated platform
		var namespace string
		if subdir, ok := qualifiers["subdir"]; ok {
			namespace = subdir
		} else {
			return nil, fmt.Errorf("failed to find subdir for conda")
		}

		return &Coordinate{
			CoordinateType: pkg.Type,
			Provider:       Provider,
			Namespace:      emptyToHyphen(namespace),
			Name:           pkg.Name,
			Revision:       Revision,
		}, nil

	case "deb":
		// channel -> Provider in coordinates (3 Providers: anaconda-main, anaconda-r, conda-forge)
		var pkgType string
		var Revision string
		qualifiers := pkg.Qualifiers.Map()
		if arch, ok := qualifiers["arch"]; ok {
			if arch == "source" {
				// source component: arch=source in purl -> debsrc type in coordinates
				pkgType = "debsrc"
				Revision = pkg.Version
			} else {
				pkgType = "deb"
				// version_architecture -> Revision in coordinates
				Revision = pkg.Version + "_" + arch
			}
		} else {
			pkgType = "deb"
			Revision = pkg.Version
		}

		return &Coordinate{
			CoordinateType: pkgType,
			Provider:       "debian",
			Namespace:      "-",
			Name:           pkg.Name,
			Revision:       Revision,
		}, nil
	case "gem":
		return &Coordinate{
			CoordinateType: pkg.Type,
			Provider:       "rubygems",
			Namespace:      emptyToHyphen(pkg.Namespace),
			Name:           pkg.Name,
			Revision:       pkg.Version,
		}, nil
	case "github":
		return &Coordinate{
			CoordinateType: "git",
			Provider:       pkg.Type,
			Namespace:      emptyToHyphen(pkg.Namespace),
			Name:           pkg.Name,
			Revision:       pkg.Version,
		}, nil
	case "golang":
		return &Coordinate{
			CoordinateType: "go",
			Provider:       pkg.Type,
			Namespace:      emptyToHyphen(strings.ReplaceAll(pkg.Namespace, "/", "%2f")),
			Name:           pkg.Name,
			Revision:       ensureSemverPrefixGolang(pkg.Version),
		}, nil
	case "maven":
		// maven is a unique case where it can have 3 Providers
		// and there is no real way to know which it is. Trying
		// the current heuristics
		var Provider string
		if strings.Contains(pkg.Namespace, "android") {
			Provider = "mavengoogle"
		} else if strings.Contains(pkg.Name, "gradle") {
			Provider = "gradleplugin"
		} else {
			Provider = "mavencentral"
		}

		return &Coordinate{
			CoordinateType: "maven",
			Provider:       Provider,
			Namespace:      emptyToHyphen(pkg.Namespace),
			Name:           pkg.Name,
			Revision:       pkg.Version,
		}, nil
	case "npm":
		return &Coordinate{
			CoordinateType: pkg.Type,
			Provider:       "npmjs",
			Namespace:      emptyToHyphen(pkg.Namespace),
			Name:           pkg.Name,
			Revision:       pkg.Version,
		}, nil
	case "nuget":
		return &Coordinate{
			CoordinateType: pkg.Type,
			Provider:       "nuget",
			Namespace:      emptyToHyphen(pkg.Namespace),
			Name:           pkg.Name,
			Revision:       pkg.Version,
		}, nil
	case "pypi":
		// purl: PyPI treats - and _ as the same character
		// and is not case sensitive. Therefore a PyPI
		// package Name must be lowercased and
		// underscore _ replaced with a dash -.
		return &Coordinate{
			CoordinateType: pkg.Type,
			Provider:       "pypi",
			Namespace:      emptyToHyphen(pkg.Namespace),
			Name:           pkg.Name,
			Revision:       pkg.Version,
		}, nil
	}
	return nil, fmt.Errorf("failed to get coordinates from purl: %s", purlUri)
}

func (c *Coordinate) ToString() string {
	if c.Revision == "" {
		return fmt.Sprintf("%s/%s/%s/%s/%22%22", c.CoordinateType, c.Provider, c.Namespace, c.Name)
	} else {
		return fmt.Sprintf("%s/%s/%s/%s/%s", c.CoordinateType, c.Provider, c.Namespace, c.Name, c.Revision)
	}
}

func emptyToHyphen(namespace string) string {
	if namespace == "" {
		return "-"
	} else {
		return namespace
	}
}

// ensureSemverPrefixGolang checks if the version string is valid SemVer and ensures it starts with "v" for golang version
func ensureSemverPrefixGolang(version string) string {
	if semver.IsValid(version) {
		return version
	}

	vPrefixed := "v" + version
	if semver.IsValid(vPrefixed) {
		return vPrefixed
	}

	// If not a valid SemVer, return as-is
	return version
}
