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
	selectedQualifiers := []*model.PackageQualifierInput{{Key: "user", Value: &qualifierA}, {Key: "channel", Value: &qualifierB}}
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
	client.registerCertifyPkg([]*model.Package{selectedPackage1[0], selectedPackage2[0]}, "these two opnessl packages are the same")

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
	client.registerCertifyPkg([]*model.Package{selectedPackage3[0], selectedPackage4[0]}, "these two pypi packages are the same")

	return nil
}

func (c *demoClient) registerCertifyPkg(selectedPackages []*model.Package, justification string) {

	for _, a := range c.certifyPkg {
		if reflect.DeepEqual(a.Packages, selectedPackages) && a.Justification == justification {
			return
		}
	}

	newCertifyPkg := &model.CertifyPkg{
		Packages:      selectedPackages,
		Justification: justification,
		Origin:        "testing backend",
		Collector:     "testing backend",
	}
	c.certifyPkg = append(c.certifyPkg, newCertifyPkg)
}
