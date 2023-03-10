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

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
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

	client.registerIsDependency(selectedPackage[0], depPackage[0], "3.0.3", "deb: part of SBOM - openssl", "testing backend", "testing backend")

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
	client.registerPackage("apk", "alpine", "curl", "7.83.0-r0", "", "arch", "x86")

	depType = "apk"
	depdNameSpace = "alpine"
	depdName = "curl"
	depPkgNameSpec = &model.PkgNameSpec{Type: &depType, Namespace: &depdNameSpace, Name: &depdName}
	depPkgSpec = &model.PkgSpec{Type: depPkgNameSpec.Type, Namespace: depPkgNameSpec.Namespace, Name: depPkgNameSpec.Name}
	depPackage, err = client.Packages(context.TODO(), depPkgSpec)
	if err != nil {
		return err
	}

	client.registerIsDependency(selectedPackage[0], depPackage[0], "7.83.0-r0", "docker: part of SBOM - curl", "testing backend", "testing backend")

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

	client.registerIsDependency(selectedPackage[0], depPackage[0], "3.0.3", "docker: part of SBOM - openssl", "testing backend", "testing backend")

	return nil
}

// Ingest IsDependency

func (c *demoClient) registerIsDependency(selectedPackage *model.Package, dependentPackage *model.Package, versionRange, justification, origin, collector string) *model.IsDependency {

	for _, dependency := range c.isDependency {
		if dependency.DependentPackage == dependentPackage && dependency.Justification == justification &&
			dependency.Package == selectedPackage && dependency.VersionRange == versionRange {
			return dependency
		}
	}

	newIsDependency := &model.IsDependency{
		Package:          selectedPackage,
		DependentPackage: dependentPackage,
		VersionRange:     versionRange,
		Justification:    justification,
		Origin:           origin,
		Collector:        collector,
	}
	c.isDependency = append(c.isDependency, newIsDependency)

	selectedPackageNodeId := c.pkgId(selectedPackage)
	if _, ok := c.backEdges[selectedPackageNodeId]; !ok {
		c.backEdges[selectedPackageNodeId] = &evidenceTrees{}
	}
	c.backEdges[selectedPackageNodeId].isDependency = append(c.backEdges[selectedPackageNodeId].isDependency, newIsDependency)

	dependentPackageNodeId := c.pkgId(dependentPackage)
	if _, ok := c.backEdges[dependentPackageNodeId]; !ok {
		c.backEdges[dependentPackageNodeId] = &evidenceTrees{}
	}
	c.backEdges[dependentPackageNodeId].isDependency = append(c.backEdges[dependentPackageNodeId].isDependency, newIsDependency)

	return newIsDependency
}

func (c *demoClient) IngestDependency(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, dependency model.IsDependencyInputSpec) (*model.IsDependency, error) {

	selectedPkgSpec := helper.ConvertPkgInputSpecToPkgSpec(&pkg)

	collectedPkg, err := c.Packages(ctx, selectedPkgSpec)
	if err != nil {
		return nil, err
	}
	if len(collectedPkg) != 1 {
		return nil, gqlerror.Errorf(
			"IngestDependency :: multiple package found")
	}

	// Note: depPkgSpec only takes up to the pkgName as IsDependency does not allow for the attestation
	// to be made at the pkgVersion level. Version range for the dependent package is defined as a property
	// on IsDependency.
	depPkgSpec := model.PkgSpec{
		Type:      &depPkg.Type,
		Namespace: depPkg.Namespace,
		Name:      &depPkg.Name,
	}
	collectedDepPkg, err := c.Packages(ctx, &depPkgSpec)
	if err != nil {
		return nil, err
	}
	if len(collectedDepPkg) != 1 {
		return nil, gqlerror.Errorf(
			"IngestDependency :: multiple dependent package found")
	}

	return c.registerIsDependency(
		collectedPkg[0],
		collectedDepPkg[0],
		dependency.VersionRange,
		dependency.Justification,
		dependency.Origin,
		dependency.Collector), nil
}

// Query IsDependency

func (c *demoClient) IsDependency(ctx context.Context, isDependencySpec *model.IsDependencySpec) ([]*model.IsDependency, error) {
	var isDependencies []*model.IsDependency

	for _, h := range c.isDependency {
		matchOrSkip := true

		if isDependencySpec.Justification != nil && h.Justification != *isDependencySpec.Justification {
			matchOrSkip = false
		}
		if isDependencySpec.Collector != nil && h.Collector != *isDependencySpec.Collector {
			matchOrSkip = false
		}
		if isDependencySpec.Origin != nil && h.Origin != *isDependencySpec.Origin {
			matchOrSkip = false
		}
		if isDependencySpec.VersionRange != nil && h.VersionRange != *isDependencySpec.VersionRange {
			matchOrSkip = false
		}

		if isDependencySpec.Package != nil && h.Package != nil {
			if isDependencySpec.Package.Type == nil || h.Package.Type == *isDependencySpec.Package.Type {
				newPkg := filterPackageNamespace(h.Package, isDependencySpec.Package)
				if newPkg == nil {
					matchOrSkip = false
				}
			}
		}

		if isDependencySpec.DependentPackage != nil && h.DependentPackage != nil {
			if isDependencySpec.DependentPackage.Type == nil || h.DependentPackage.Type == *isDependencySpec.DependentPackage.Type {
				depPkgSpec := &model.PkgSpec{Type: isDependencySpec.DependentPackage.Type, Namespace: isDependencySpec.DependentPackage.Namespace,
					Name: isDependencySpec.DependentPackage.Name}
				newPkg := filterPackageNamespace(h.DependentPackage, depPkgSpec)
				if newPkg == nil {
					matchOrSkip = false
				}
			}
		}

		if matchOrSkip {
			isDependencies = append(isDependencies, h)
		}
	}

	return isDependencies, nil
}
