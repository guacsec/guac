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
	selectedQualifiers := []*model.PackageQualifierSpec{{Key: "arch", Value: &qualifierA}}
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

// Ingest IsDependency

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

// Query IsDependency

func (c *demoClient) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	var isDependencies []*model.IsDependency

	justificationMatchOrSkip := false
	collectorMatchOrSkip := false
	originMatchOrSkip := false
	versionRangeMatchOrSkip := false
	for _, h := range c.isDependency {
		if isDependencySpec.Justification == nil || h.Justification == *isDependencySpec.Justification {
			justificationMatchOrSkip = true
		}
		if isDependencySpec.Collector == nil || h.Collector == *isDependencySpec.Collector {
			collectorMatchOrSkip = true
		}
		if isDependencySpec.Origin == nil || h.Origin == *isDependencySpec.Origin {
			originMatchOrSkip = true
		}
		if isDependencySpec.VersionRange == nil || h.VersionRange == *isDependencySpec.VersionRange {
			versionRangeMatchOrSkip = true
		}

		if justificationMatchOrSkip && collectorMatchOrSkip && originMatchOrSkip && versionRangeMatchOrSkip {
			if isDependencySpec.Package == nil && isDependencySpec.DependentPackage == nil {
				isDependencies = append(isDependencies, h)
			} else if isDependencySpec.Package != nil && h.Package != nil && isDependencySpec.DependentPackage == nil {
				if isDependencySpec.Package.Type == nil || h.Package.Type == *isDependencySpec.Package.Type {
					newPkg := filterPackageNamespace(h.Package, isDependencySpec.Package)
					if newPkg != nil {
						isDependencies = append(isDependencies, h)
					}
				}
			} else if isDependencySpec.Package == nil && isDependencySpec.DependentPackage != nil && h.DependentPackage != nil {
				if isDependencySpec.DependentPackage.Type == nil || h.DependentPackage.Type == *isDependencySpec.DependentPackage.Type {
					depPkgSpec := &model.PkgSpec{Type: isDependencySpec.DependentPackage.Type, Namespace: isDependencySpec.DependentPackage.Namespace,
						Name: isDependencySpec.DependentPackage.Name}
					newPkg := filterPackageNamespace(h.DependentPackage, depPkgSpec)
					if newPkg != nil {
						isDependencies = append(isDependencies, h)
					}
				}
			} else if isDependencySpec.Package != nil && h.Package != nil && isDependencySpec.DependentPackage != nil && h.DependentPackage != nil {
				if isDependencySpec.Package.Type == nil || h.Package.Type == *isDependencySpec.Package.Type {
					newPkg := filterPackageNamespace(h.Package, isDependencySpec.Package)
					depPkgSpec := &model.PkgSpec{Type: isDependencySpec.DependentPackage.Type, Namespace: isDependencySpec.DependentPackage.Namespace,
						Name: isDependencySpec.DependentPackage.Name}
					depPkg := filterPackageNamespace(h.DependentPackage, depPkgSpec)
					if newPkg != nil && depPkg != nil {
						isDependencies = append(isDependencies, h)
					}
				}
			}
		}
	}

	return isDependencies, nil
}
