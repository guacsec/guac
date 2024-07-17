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
		name    string
		purlUri string
		want    *Coordinate
		wantErr bool
	}{
		{
			name:    "cocoapods",
			purlUri: "pkg:cocoapods/AFNetworking@4.0.1",
			want: &Coordinate{
				coordinateType: "pod",
				provider:       "cocoapods",
				namespace:      "-",
				name:           "AFNetworking",
				revision:       "4.0.1",
			},
			wantErr: false,
		}, {
			name:    "cargo",
			purlUri: "pkg:cargo/rand@0.7.2",
			want: &Coordinate{
				coordinateType: "crate",
				provider:       "cratesio",
				namespace:      "-",
				name:           "rand",
				revision:       "0.7.2",
			},
			wantErr: false,
		}, {
			name:    "composer",
			purlUri: "pkg:composer/laravel/laravel@5.5.0",
			want: &Coordinate{
				coordinateType: "composer",
				provider:       "packagist",
				namespace:      "laravel",
				name:           "laravel",
				revision:       "5.5.0",
			},
			wantErr: false,
		}, {
			name:    "conda anaconda-mai",
			purlUri: "pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=main&subdir=linux-64&type=tar.bz2",
			want: &Coordinate{
				coordinateType: "conda",
				provider:       "anaconda-main",
				namespace:      "linux-64",
				name:           "absl-py",
				revision:       "0.4.1-py36h06a4308_0",
			},
			wantErr: false,
		}, {
			name:    "conda conda-forge",
			purlUri: "pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=conda-forge&subdir=linux-64&type=tar.bz2",
			want: &Coordinate{
				coordinateType: "conda",
				provider:       "conda-forge",
				namespace:      "linux-64",
				name:           "absl-py",
				revision:       "0.4.1-py36h06a4308_0",
			},
			wantErr: false,
		}, {
			name:    "conda anaconda-r",
			purlUri: "pkg:conda/absl-py@0.4.1?build=py36h06a4308_0&channel=anaconda-r&subdir=linux-64&type=tar.bz2",
			want: &Coordinate{
				coordinateType: "conda",
				provider:       "anaconda-r",
				namespace:      "linux-64",
				name:           "absl-py",
				revision:       "0.4.1-py36h06a4308_0",
			},
			wantErr: false,
		}, {
			name:    "deb",
			purlUri: "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie",
			want: &Coordinate{
				coordinateType: "deb",
				provider:       "debian",
				namespace:      "-",
				name:           "curl",
				revision:       "7.50.3-1_i386",
			},
			wantErr: false,
		}, {
			name:    "deb - source",
			purlUri: "pkg:deb/debian/curl@7.50.3-1?arch=source&distro=jessie",
			want: &Coordinate{
				coordinateType: "debsrc",
				provider:       "debian",
				namespace:      "-",
				name:           "curl",
				revision:       "7.50.3-1",
			},
			wantErr: false,
		}, {
			name:    "deb - no arch",
			purlUri: "pkg:deb/debian/curl@7.50.3-1?distro=jessie",
			want: &Coordinate{
				coordinateType: "deb",
				provider:       "debian",
				namespace:      "-",
				name:           "curl",
				revision:       "7.50.3-1",
			},
			wantErr: false,
		}, {
			name:    "gem",
			purlUri: "pkg:gem/ruby-advisory-db-check@0.12.4",
			want: &Coordinate{
				coordinateType: "gem",
				provider:       "rubygems",
				namespace:      "-",
				name:           "ruby-advisory-db-check",
				revision:       "0.12.4",
			},
			wantErr: false,
		}, {
			name:    "github",
			purlUri: "pkg:github/package-url/purl-spec@244fd47e07d1004#everybody/loves/dogs",
			want: &Coordinate{
				coordinateType: "git",
				provider:       "github",
				namespace:      "package-url",
				name:           "purl-spec",
				revision:       "244fd47e07d1004",
			},
			wantErr: false,
		}, {
			name:    "golang",
			purlUri: "pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c#api",
			want: &Coordinate{
				coordinateType: "go",
				provider:       "golang",
				namespace:      "github.com/gorilla",
				name:           "context",
				revision:       "234fd47e07d1004f0aed9c",
			},
			wantErr: false,
		}, {
			name:    "maven - mavencentral",
			purlUri: "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=zip&classifier=dist",
			want: &Coordinate{
				coordinateType: "maven",
				provider:       "mavencentral",
				namespace:      "org.apache.xmlgraphics",
				name:           "batik-anim",
				revision:       "1.9.1",
			},
			wantErr: false,
		}, {
			name:    "maven - mavengoogle",
			purlUri: "pkg:maven/android.arch.lifecycle/common@1.0.1?type=zip&classifier=dist",
			want: &Coordinate{
				coordinateType: "maven",
				provider:       "mavengoogle",
				namespace:      "android.arch.lifecycle",
				name:           "common",
				revision:       "1.0.1",
			},
			wantErr: false,
		}, {
			name:    "maven - gradleplugin",
			purlUri: "pkg:maven/io.github.lognet/grpc-spring-boot-starter-gradle-plugin@4.6.0",
			want: &Coordinate{
				coordinateType: "maven",
				provider:       "gradleplugin",
				namespace:      "io.github.lognet",
				name:           "grpc-spring-boot-starter-gradle-plugin",
				revision:       "4.6.0",
			},
			wantErr: false,
		}, {
			name:    "npm",
			purlUri: "pkg:npm/%40angular/animation@12.3.1",
			want: &Coordinate{
				coordinateType: "npm",
				provider:       "npmjs",
				namespace:      "@angular",
				name:           "animation",
				revision:       "12.3.1",
			},
			wantErr: false,
		}, {
			name:    "nuget",
			purlUri: "pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
			want: &Coordinate{
				coordinateType: "nuget",
				provider:       "nuget",
				namespace:      "-",
				name:           "EnterpriseLibrary.Common",
				revision:       "6.0.1304",
			},
			wantErr: false,
		}, {
			name:    "pypi",
			purlUri: "pkg:pypi/django-allauth@12.23",
			want: &Coordinate{
				coordinateType: "pypi",
				provider:       "pypi",
				namespace:      "-",
				name:           "django-allauth",
				revision:       "12.23",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
