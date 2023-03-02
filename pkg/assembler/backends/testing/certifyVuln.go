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
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func registerAllCertifyVuln(client *demoClient) error {

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
	selectedYear := "2019"
	selectedCveID := "CVE-2019-13110"
	selectedCVESpec := &model.CVESpec{Year: &selectedYear, CveID: &selectedCveID}
	selectedCve, err := client.Cve(context.TODO(), selectedCVESpec)
	if err != nil {
		return err
	}
	client.registerCertifyVuln(selectedPackage1[0], nil, selectedCve[0], nil, time.Now(), "MITRE", "v1.0.0", "osv.dev", "0.0.14")

	// pkg:pypi/django@1.11.1
	// client.registerPackage("pypi", "", "django", "1.11.1", "")

	selectedType = "pypi"
	selectedNameSpace = ""
	selectedName = "django"
	selectedVersion = "1.11.1"
	selectedSubPath = ""
	selectedPkgSpec = &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Subpath: &selectedSubPath}
	selectedPackage2, err := client.Packages(context.TODO(), selectedPkgSpec)
	if err != nil {
		return err
	}
	selectedOsvID := "CVE-2019-13110"
	selectedOsvSpec := &model.OSVSpec{OsvID: &selectedOsvID}
	selectedOsv, err := client.Osv(context.TODO(), selectedOsvSpec)
	if err != nil {
		return err
	}
	client.registerCertifyVuln(selectedPackage2[0], selectedOsv[0], nil, nil, time.Now(), "MITRE", "v1.0.0", "osv.dev", "0.0.14")

	selectedGhsaID := "GHSA-h45f-rjvw-2rv2"
	selectedGhsaSpec := &model.GHSASpec{GhsaID: &selectedGhsaID}
	selectedGhsa, err := client.Ghsa(context.TODO(), selectedGhsaSpec)
	if err != nil {
		return err
	}
	client.registerCertifyVuln(selectedPackage1[0], nil, nil, selectedGhsa[0], time.Now(), "MITRE", "v1.0.0", "osv.dev", "0.0.14")

	return nil
}

// Ingest CertifyPkg

func (c *demoClient) registerCertifyVuln(selectedPackage *model.Package, selectedOsv *model.Osv, selectedCve *model.Cve, selectedGhsa *model.Ghsa, timeScanned time.Time,
	dbUri string, dbVersion string, scannerUri string, scannerVersion string) {

	for _, vuln := range c.certifyVuln {
		if vuln.Package == selectedPackage && vuln.DbURI == dbUri && vuln.DbVersion == dbVersion &&
			vuln.ScannerURI == scannerUri && vuln.ScannerVersion == scannerVersion {
			if val, ok := vuln.Vulnerability.(model.Osv); ok {
				if &val == selectedOsv {
					return
				}
			} else if val, ok := vuln.Vulnerability.(model.Cve); ok {
				if &val == selectedCve {
					return
				}
			} else if val, ok := vuln.Vulnerability.(model.Ghsa); ok {
				if &val == selectedGhsa {
					return
				}
			}
		}
	}

	newCertifyVuln := &model.CertifyVuln{
		Package:        selectedPackage,
		TimeScanned:    timeScanned,
		DbURI:          dbUri,
		DbVersion:      dbVersion,
		ScannerURI:     scannerUri,
		ScannerVersion: scannerVersion,
		Origin:         "testing backend",
		Collector:      "testing backend",
	}
	if selectedOsv != nil {
		newCertifyVuln.Vulnerability = selectedOsv
	} else if selectedCve != nil {
		newCertifyVuln.Vulnerability = selectedCve
	} else {
		newCertifyVuln.Vulnerability = selectedGhsa
	}

	c.certifyVuln = append(c.certifyVuln, newCertifyVuln)
}

// Query CertifyPkg

func (c *demoClient) CertifyVuln(ctx context.Context, certifyVulnSpec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	if certifyVulnSpec.Cve != nil && certifyVulnSpec.Osv != nil && certifyVulnSpec.Ghsa != nil {
		return nil, gqlerror.Errorf("cannot specify cve, osv and ghsa together for CertifyVuln")
	}
	if certifyVulnSpec.Cve != nil && certifyVulnSpec.Osv != nil {
		return nil, gqlerror.Errorf("cannot specify cve and osv together for CertifyVuln")
	}
	if certifyVulnSpec.Cve != nil && certifyVulnSpec.Ghsa != nil {
		return nil, gqlerror.Errorf("cannot specify cve and ghsa together for CertifyVuln")
	}
	if certifyVulnSpec.Osv != nil && certifyVulnSpec.Ghsa != nil {
		return nil, gqlerror.Errorf("cannot specify cve and ghsa together for CertifyVuln")
	}

	var foundCertifyBad []*model.CertifyVuln

	for _, h := range c.certifyVuln {
		matchOrSkip := true

		if certifyVulnSpec.DbURI != nil && h.DbURI != *certifyVulnSpec.DbURI {
			matchOrSkip = false
		}
		if certifyVulnSpec.DbVersion != nil && h.DbVersion != *certifyVulnSpec.DbVersion {
			matchOrSkip = false
		}
		if certifyVulnSpec.ScannerURI != nil && h.ScannerURI != *certifyVulnSpec.ScannerURI {
			matchOrSkip = false
		}
		if certifyVulnSpec.ScannerVersion != nil && h.ScannerVersion != *certifyVulnSpec.ScannerVersion {
			matchOrSkip = false
		}
		if certifyVulnSpec.Collector != nil && h.Collector != *certifyVulnSpec.Collector {
			matchOrSkip = false
		}
		if certifyVulnSpec.Origin != nil && h.Origin != *certifyVulnSpec.Origin {
			matchOrSkip = false
		}

		if certifyVulnSpec.Package != nil && h.Package != nil {
			if certifyVulnSpec.Package.Type == nil || h.Package.Type == *certifyVulnSpec.Package.Type {
				newPkg := filterPackageNamespace(h.Package, certifyVulnSpec.Package)
				if newPkg == nil {
					matchOrSkip = false
				}
			} else {
				matchOrSkip = false
			}
		}

		if certifyVulnSpec.Cve != nil {
			if val, ok := h.Vulnerability.(*model.Cve); ok {
				if certifyVulnSpec.Cve.Year == nil || val.Year == *certifyVulnSpec.Cve.Year {
					newCve, err := filterCVEID(val, certifyVulnSpec.Cve)
					if err != nil {
						return nil, err
					}
					if newCve == nil {
						matchOrSkip = false
					}
				}
			} else {
				matchOrSkip = false

			}
		}

		if certifyVulnSpec.Osv != nil {
			if val, ok := h.Vulnerability.(*model.Osv); ok {
				newOSV, err := filterOSVID(val, certifyVulnSpec.Osv)
				if err != nil {
					return nil, err
				}
				if newOSV == nil {
					matchOrSkip = false
				}
			} else {
				matchOrSkip = false
			}
		}

		if certifyVulnSpec.Ghsa != nil {
			if val, ok := h.Vulnerability.(*model.Ghsa); ok {
				newGhsa, err := filterGHSAID(val, certifyVulnSpec.Ghsa)
				if err != nil {
					return nil, err
				}
				if newGhsa == nil {
					matchOrSkip = false
				}
			} else {
				matchOrSkip = false
			}
		}

		if matchOrSkip {
			foundCertifyBad = append(foundCertifyBad, h)
		}
	}

	return foundCertifyBad, nil
}
