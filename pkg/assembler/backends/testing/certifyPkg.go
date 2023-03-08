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
	"reflect"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func registerAllCertifyPkg(client *demoClient) error {

	// pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
	//	("conan", "openssl.org", "openssl", "3.0.3", "", "user=bincrafters", "channel=stable")

	selectedType := "conan"
	selectedNameSpace := "openssl.org"
	selectedName := "openssl"
	selectedVersion := "3.0.3"
	selectedSubPath := ""
	qualifierA := "bincrafters"
	qualifierB := "stable"
	selectedQualifiers := []*model.PackageQualifierSpec{{Key: "user", Value: &qualifierA}, {Key: "channel", Value: &qualifierB}}
	selectedPkgSpec := &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Subpath: &selectedSubPath, Qualifiers: selectedQualifiers}
	selectedPackage1, err := client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}

	// pkg:conan/openssl@3.0.3
	//	("conan", "", "openssl", "3.0.3", "")
	selectedType = "conan"
	selectedNameSpace = ""
	selectedName = "openssl"
	selectedVersion = "3.0.3"
	selectedSubPath = ""
	selectedPkgSpec = &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Subpath: &selectedSubPath}
	selectedPackage2, err := client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}
	client.registerCertifyPkg([]*model.Package{selectedPackage1[0], selectedPackage2[0]}, "these two opnessl packages are the same", "testing backend", "testing backend")

	// pkg:pypi/django@1.11.1
	// client.registerPackage("pypi", "", "django", "1.11.1", "")

	selectedType = "pypi"
	selectedNameSpace = ""
	selectedName = "django"
	selectedVersion = "1.11.1"
	selectedSubPath = ""
	selectedPkgSpec = &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Subpath: &selectedSubPath}
	selectedPackage3, err := client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}

	// pkg:pypi/django@1.11.1#subpath
	// client.registerPackage("pypi", "", "django", "1.11.1", "subpath")

	selectedType = "pypi"
	selectedNameSpace = ""
	selectedName = "django"
	selectedVersion = "1.11.1"
	selectedSubPath = "subpath"
	selectedPkgSpec = &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Subpath: &selectedSubPath}
	selectedPackage4, err := client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}
	client.registerCertifyPkg([]*model.Package{selectedPackage3[0], selectedPackage4[0]}, "these two pypi packages are the same", "testing backend", "testing backend")

	return nil
}

// Ingest CertifyPkg

func (c *demoClient) registerCertifyPkg(selectedPackages []*model.Package, justification, origin, collector string) (*model.CertifyPkg, error) {

	for _, certPkg := range c.certifyPkg {
		if reflect.DeepEqual(certPkg.Packages, selectedPackages) && certPkg.Justification == justification {
			return certPkg, nil
		}
	}

	newCertifyPkg := &model.CertifyPkg{
		Packages:      selectedPackages,
		Justification: justification,
		Origin:        origin,
		Collector:     collector,
	}
	c.certifyPkg = append(c.certifyPkg, newCertifyPkg)
	return newCertifyPkg, nil
}

func (c *demoClient) IngestCertifyPkg(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, certifyPkg model.CertifyPkgInputSpec) (*model.CertifyPkg, error) {

	pkgQualifiers := []*model.PackageQualifierSpec{}
	for _, quali := range pkg.Qualifiers {
		pkgQualifier := &model.PackageQualifierSpec{
			Key:   quali.Key,
			Value: &quali.Value,
		}
		pkgQualifiers = append(pkgQualifiers, pkgQualifier)
	}

	pkgSpec := model.PkgSpec{
		Type:       &pkg.Type,
		Namespace:  pkg.Namespace,
		Name:       &pkg.Name,
		Version:    pkg.Version,
		Qualifiers: pkgQualifiers,
		Subpath:    pkg.Subpath,
	}
	collectedPkg, err := c.Packages(ctx, &pkgSpec)
	if err != nil {
		return nil, err
	}
	if len(collectedPkg) != 1 {
		return nil, gqlerror.Errorf(
			"IngestCertifyPkg :: multiple package found")
	}

	depPkgQualifiers := []*model.PackageQualifierSpec{}
	for _, quali := range pkg.Qualifiers {
		pkgQualifier := &model.PackageQualifierSpec{
			Key:   quali.Key,
			Value: &quali.Value,
		}
		depPkgQualifiers = append(depPkgQualifiers, pkgQualifier)
	}

	depPkgSpec := model.PkgSpec{
		Type:       &depPkg.Type,
		Namespace:  depPkg.Namespace,
		Name:       &depPkg.Name,
		Version:    depPkg.Version,
		Qualifiers: depPkgQualifiers,
		Subpath:    depPkg.Subpath,
	}
	collectedDepPkg, err := c.Packages(ctx, &depPkgSpec)
	if err != nil {
		return nil, err
	}
	if len(collectedDepPkg) != 1 {
		return nil, gqlerror.Errorf(
			"IngestCertifyPkg :: multiple secondary package found")
	}

	return c.registerCertifyPkg(
		[]*model.Package{collectedPkg[0], collectedDepPkg[0]},
		certifyPkg.Justification,
		certifyPkg.Origin,
		certifyPkg.Collector)
}

// Query CertifyPkg

func (c *demoClient) CertifyPkg(ctx context.Context, certifyPkgSpec *model.CertifyPkgSpec) ([]*model.CertifyPkg, error) {
	var certifyPkgs []*model.CertifyPkg

	queryPkgs, err := getPackagesFromInput(c, ctx, certifyPkgSpec.Packages)
	if err != nil {
		return nil, err
	}

	for _, h := range c.certifyPkg {
		matchOrSkip := true

		if certifyPkgSpec.Justification != nil && h.Justification != *certifyPkgSpec.Justification {
			matchOrSkip = false
		}
		if certifyPkgSpec.Collector != nil && h.Collector != *certifyPkgSpec.Collector {
			matchOrSkip = false
		}
		if certifyPkgSpec.Origin != nil && h.Origin != *certifyPkgSpec.Origin {
			matchOrSkip = false
		}
		if len(queryPkgs) > 0 {
			for _, pkg := range queryPkgs {
				if !packagesContain(h.Packages, pkg) {
					matchOrSkip = false
				}
			}
		}

		if matchOrSkip {
			certifyPkgs = append(certifyPkgs, h)
		}

	}

	return certifyPkgs, nil
}

func packagesContain(selectedPackages []*model.Package, queryPackage *model.Package) bool {
	for _, pkg := range selectedPackages {
		if reflect.DeepEqual(pkg, queryPackage) {
			return true
		}
	}
	return false
}

func getPackagesFromInput(client *demoClient, ctx context.Context, queryPackages []*model.PkgSpec) ([]*model.Package, error) {
	collectedPkg := []*model.Package{}
	for _, value := range queryPackages {
		selectedPackage, err := client.Packages(context.TODO(), value)
		if err != nil {
			return nil, err
		}
		if selectedPackage != nil {
			collectedPkg = append(collectedPkg, selectedPackage...)
		}
	}
	return collectedPkg, nil
}
