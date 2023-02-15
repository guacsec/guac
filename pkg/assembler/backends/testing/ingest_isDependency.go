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

func registerAllIsDependency(client *demoClient) error {
	// TestData1

	// Package:
	// pkg:deb/ubuntu/dpkg@1.19.0.4?arch=amd64
	// "deb", "ubuntu", "dpkg", "1.19.0.4", "", "arch=amd64"

	selectedType := "deb"
	selectedNameSpace := "ubuntu"
	selectedName := "dpkg"
	selectedVersion := "1.19.0.4"
	qualifierA := "amd64"
	selectedQualifiers := []*model.PackageQualifierInput{{Key: "arch", Value: &qualifierA}}
	selectedPkgSpec := &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Qualifiers: selectedQualifiers}
	selectedPackage, err := client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}

	// Dependent Package:
	// pkg:conan/openssl@3.0.3
	// "conan", "", "openssl", "3.0.3", ""
	// pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
	// "conan", "openssl.org", "openssl", "3.0.3", "", "user=bincrafters", "channel=stable"

	depType := "conan"
	depdNameSpace := "openssl.org"
	depdName := "openssl"
	depPkgNameSpec := &model.PkgNameSpec{Type: &depType, Namespace: &depdNameSpace, Name: &depdName}
	depPkgSpec := &model.PkgSpec{Type: depPkgNameSpec.Type, Namespace: depPkgNameSpec.Namespace, Name: depPkgNameSpec.Name}

	depPackage, err := client.Packages(context.TODO(), depPkgSpec)
	if err != nil {
		return err
	}

	client.registerIsDependency(selectedPackage[0], depPackage[0], "3.0.3", "deb: part of SBOM - openssl")

	// TestData2

	// pkg:docker/smartentry/debian@dc437cc87d10
	// client.registerPackage("docker", "smartentry", "debian", "dc437cc87d10", "")

	selectedType = "docker"
	selectedNameSpace = "smartentry"
	selectedName = "debian"
	selectedVersion = "dc437cc87d10"
	selectedPkgSpec = &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion}
	selectedPackage, err = client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}

	// Dependent Package:
	// pkg:apk/alpine/curl@7.83.0-r0?arch=x86
	client.registerPackage("apk", "alpine", "curl", "7.83.0-r0", "", "arch=x86")

	depType = "apk"
	depdNameSpace = "alpine"
	depdName = "curl"
	depPkgNameSpec = &model.PkgNameSpec{Type: &depType, Namespace: &depdNameSpace, Name: &depdName}
	depPkgSpec = &model.PkgSpec{Type: depPkgNameSpec.Type, Namespace: depPkgNameSpec.Namespace, Name: depPkgNameSpec.Name}
	depPackage, err = client.Packages(context.TODO(), depPkgSpec)
	if err != nil {
		return err
	}

	client.registerIsDependency(selectedPackage[0], depPackage[0], "7.83.0-r0", "docker: part of SBOM - curl")

	// TestData3

	// Dependent Package:
	// pkg:conan/openssl@3.0.3
	// "conan", "", "openssl", "3.0.3", ""
	// pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
	// "conan", "openssl.org", "openssl", "3.0.3", "", "user=bincrafters", "channel=stable"

	depType = "conan"
	depdNameSpace = "openssl.org"
	depdName = "openssl"
	depPkgNameSpec = &model.PkgNameSpec{Type: &depType, Namespace: &depdNameSpace, Name: &depdName}
	depPkgSpec = &model.PkgSpec{Type: depPkgNameSpec.Type, Namespace: depPkgNameSpec.Namespace, Name: depPkgNameSpec.Name}

	depPackage, err = client.Packages(context.TODO(), depPkgSpec)
	if err != nil {
		return err
	}

	client.registerIsDependency(selectedPackage[0], depPackage[0], "3.0.3", "docker: part of SBOM - openssl")

	return nil
}

func (c *demoClient) registerIsDependency(selectedPackage *model.Package, dependentPackage *model.Package, versionRange string, justification string) {

	for _, dependency := range c.isDependency {
		if dependency.DependentPackage == dependentPackage && dependency.Justification == justification &&
			dependency.Package == selectedPackage && dependency.VersionRange == versionRange {
			return
		}
	}

	newIsOccurrence := &model.IsDependency{
		Package:          selectedPackage,
		DependentPackage: dependentPackage,
		VersionRange:     versionRange,
		Justification:    justification,
		Origin:           "testing backend",
		Collector:        "testing backend",
	}
	c.isDependency = append(c.isDependency, newIsOccurrence)
}
