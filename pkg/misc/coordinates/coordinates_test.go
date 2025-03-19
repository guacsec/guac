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
	"reflect"
	"testing"
)

func TestConvertPurlToCoordinate(t *testing.T) {
	tests := []struct {
		Name    string
		purlUri string
		want    *Coordinate
		wantErr bool
	}{
		{
			Name:    "cocoapods",
			purlUri: "pkg:cocoapods/AFNetworking@4.0.1",
			want: &Coordinate{
				CoordinateType: "pod",
				Provider:       "cocoapods",
				Namespace:      "-",
				Name:           "AFNetworking",
				Revision:       "4.0.1",
			},
			wantErr: false,
		}, {
			Name:    "cargo",
			purlUri: "pkg:cargo/rand@0.7.2",
			want: &Coordinate{
				CoordinateType: "crate",
				Provider:       "cratesio",
				Namespace:      "-",
				Name:           "rand",
				Revision:       "0.7.2",
			},
			wantErr: false,
		}, {
			Name:    "composer",
			purlUri: "pkg:composer/laravel/laravel@5.5.0",
			want: &Coordinate{
				CoordinateType: "composer",
				Provider:       "packagist",
				Namespace:      "laravel",
				Name:           "laravel",
				Revision:       "5.5.0",
			},
			wantErr: false,
		}, {
			Name:    "conda anaconda-mai",
			purlUri: "pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=main&subdir=linux-64&type=tar.bz2",
			want: &Coordinate{
				CoordinateType: "conda",
				Provider:       "anaconda-main",
				Namespace:      "linux-64",
				Name:           "absl-py",
				Revision:       "0.4.1-py36h06a4308_0",
			},
			wantErr: false,
		}, {
			Name:    "conda conda-forge",
			purlUri: "pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=conda-forge&subdir=linux-64&type=tar.bz2",
			want: &Coordinate{
				CoordinateType: "conda",
				Provider:       "conda-forge",
				Namespace:      "linux-64",
				Name:           "absl-py",
				Revision:       "0.4.1-py36h06a4308_0",
			},
			wantErr: false,
		}, {
			Name:    "conda anaconda-r",
			purlUri: "pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=anaconda-r&subdir=linux-64&type=tar.bz2",
			want: &Coordinate{
				CoordinateType: "conda",
				Provider:       "anaconda-r",
				Namespace:      "linux-64",
				Name:           "absl-py",
				Revision:       "0.4.1-py36h06a4308_0",
			},
			wantErr: false,
		}, {
			Name:    "deb",
			purlUri: "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie",
			want: &Coordinate{
				CoordinateType: "deb",
				Provider:       "debian",
				Namespace:      "-",
				Name:           "curl",
				Revision:       "7.50.3-1_i386",
			},
			wantErr: false,
		}, {
			Name:    "deb - source",
			purlUri: "pkg:deb/debian/curl@7.50.3-1?arch=source&distro=jessie",
			want: &Coordinate{
				CoordinateType: "debsrc",
				Provider:       "debian",
				Namespace:      "-",
				Name:           "curl",
				Revision:       "7.50.3-1",
			},
			wantErr: false,
		}, {
			Name:    "deb - no arch",
			purlUri: "pkg:deb/debian/curl@7.50.3-1?distro=jessie",
			want: &Coordinate{
				CoordinateType: "deb",
				Provider:       "debian",
				Namespace:      "-",
				Name:           "curl",
				Revision:       "7.50.3-1",
			},
			wantErr: false,
		}, {
			Name:    "gem",
			purlUri: "pkg:gem/ruby-advisory-db-check@0.12.4",
			want: &Coordinate{
				CoordinateType: "gem",
				Provider:       "rubygems",
				Namespace:      "-",
				Name:           "ruby-advisory-db-check",
				Revision:       "0.12.4",
			},
			wantErr: false,
		}, {
			Name:    "github",
			purlUri: "pkg:github/package-url/purl-spec@244fd47e07d1004#everybody/loves/dogs",
			want: &Coordinate{
				CoordinateType: "git",
				Provider:       "github",
				Namespace:      "package-url",
				Name:           "purl-spec",
				Revision:       "244fd47e07d1004",
			},
			wantErr: false,
		},
		{
			Name:    "github",
			purlUri: "pkg:github/purl-spec@244fd47e07d1004#everybody/loves/dogs",
			want: &Coordinate{
				CoordinateType: "git",
				Provider:       "github",
				Namespace:      "-",
				Name:           "purl-spec",
				Revision:       "244fd47e07d1004",
			},
			wantErr: false,
		},
		{
			Name:    "golang",
			purlUri: "pkg:golang/cloud.google.com/go/compute@1.23.0",
			want: &Coordinate{
				CoordinateType: "go",
				Provider:       "golang",
				Namespace:      "cloud.google.com%2fgo",
				Name:           "compute",
				Revision:       "v1.23.0",
			},
			wantErr: false,
		},
		{
			Name:    "golang",
			purlUri: "pkg:golang/github.com/aws/aws-lambda-go@v1.46.0",
			want: &Coordinate{
				CoordinateType: "go",
				Provider:       "golang",
				Namespace:      "github.com%2faws",
				Name:           "aws-lambda-go",
				Revision:       "v1.46.0",
			},
			wantErr: false,
		},
		{
			Name:    "golang",
			purlUri: "pkg:golang/context@234fd47e07d1004f0aed9c#api",
			want: &Coordinate{
				CoordinateType: "go",
				Provider:       "golang",
				Namespace:      "-",
				Name:           "context",
				Revision:       "234fd47e07d1004f0aed9c",
			},
			wantErr: false,
		}, {
			Name:    "maven - mavencentral",
			purlUri: "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=zip&classifier=dist",
			want: &Coordinate{
				CoordinateType: "maven",
				Provider:       "mavencentral",
				Namespace:      "org.apache.xmlgraphics",
				Name:           "batik-anim",
				Revision:       "1.9.1",
			},
			wantErr: false,
		}, {
			Name:    "maven - mavengoogle",
			purlUri: "pkg:maven/android.arch.lifecycle/common@1.0.1?type=zip&classifier=dist",
			want: &Coordinate{
				CoordinateType: "maven",
				Provider:       "mavengoogle",
				Namespace:      "android.arch.lifecycle",
				Name:           "common",
				Revision:       "1.0.1",
			},
			wantErr: false,
		}, {
			Name:    "maven - gradleplugin",
			purlUri: "pkg:maven/io.github.lognet/grpc-spring-boot-starter-gradle-plugin@4.6.0",
			want: &Coordinate{
				CoordinateType: "maven",
				Provider:       "gradleplugin",
				Namespace:      "io.github.lognet",
				Name:           "grpc-spring-boot-starter-gradle-plugin",
				Revision:       "4.6.0",
			},
			wantErr: false,
		}, {
			Name:    "npm",
			purlUri: "pkg:npm/%40angular/animation@12.3.1",
			want: &Coordinate{
				CoordinateType: "npm",
				Provider:       "npmjs",
				Namespace:      "@angular",
				Name:           "animation",
				Revision:       "12.3.1",
			},
			wantErr: false,
		}, {
			Name:    "nuget",
			purlUri: "pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
			want: &Coordinate{
				CoordinateType: "nuget",
				Provider:       "nuget",
				Namespace:      "-",
				Name:           "EnterpriseLibrary.Common",
				Revision:       "6.0.1304",
			},
			wantErr: false,
		}, {
			Name:    "pypi",
			purlUri: "pkg:pypi/django-allauth@12.23",
			want: &Coordinate{
				CoordinateType: "pypi",
				Provider:       "pypi",
				Namespace:      "-",
				Name:           "django-allauth",
				Revision:       "12.23",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			got, err := ConvertPurlToCoordinate(tt.purlUri)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertPurlToCoordinate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConvertPurlToCoordinate() = %v, want %v", got, tt.want)
			}
		})
	}
}
