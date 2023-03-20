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
	"time"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
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
	selectedYear := 2019
	selectedCveID := "CVE-2019-13110"
	selectedCVESpec := &model.CVESpec{Year: &selectedYear, CveID: &selectedCveID}
	selectedCve, err := client.Cve(context.TODO(), selectedCVESpec)
	if err != nil {
		return err
	}
	client.registerCertifyVuln(selectedPackage1[0], nil, selectedCve[0], nil, time.Now(), "MITRE", "v1.0.0", "osv.dev", "0.0.14", "testing backend", "testing backend")

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
	client.registerCertifyVuln(selectedPackage2[0], selectedOsv[0], nil, nil, time.Now(), "MITRE", "v1.0.0", "osv.dev", "0.0.14", "testing backend", "testing backend")

	selectedGhsaID := "GHSA-h45f-rjvw-2rv2"
	selectedGhsaSpec := &model.GHSASpec{GhsaID: &selectedGhsaID}
	selectedGhsa, err := client.Ghsa(context.TODO(), selectedGhsaSpec)
	if err != nil {
		return err
	}
	client.registerCertifyVuln(selectedPackage1[0], nil, nil, selectedGhsa[0], time.Now(), "MITRE", "v1.0.0", "osv.dev", "0.0.14", "testing backend", "testing backend")

	return nil
}

// Ingest CertifyVuln

func (c *demoClient) registerCertifyVuln(selectedPackage *model.Package, selectedOsv *model.Osv, selectedCve *model.Cve, selectedGhsa *model.Ghsa, timeScanned time.Time,
	dbUri, dbVersion, scannerUri, scannerVersion, origin, collector string) *model.CertifyVuln {

	for _, vuln := range c.certifyVuln {
		if reflect.DeepEqual(vuln.Package, selectedPackage) && vuln.Metadata.DbURI == dbUri && vuln.Metadata.DbVersion == dbVersion &&
			vuln.Metadata.ScannerURI == scannerUri && vuln.Metadata.ScannerVersion == scannerVersion {
			if val, ok := vuln.Vulnerability.(model.Osv); ok {
				if &val == selectedOsv {
					return vuln
				}
			} else if val, ok := vuln.Vulnerability.(model.Cve); ok {
				if &val == selectedCve {
					return vuln
				}
			} else if val, ok := vuln.Vulnerability.(model.Ghsa); ok {
				if &val == selectedGhsa {
					return vuln
				}
			}
		}
	}

	metadata := &model.VulnerabilityMetaData{
		TimeScanned:    timeScanned,
		DbURI:          dbUri,
		DbVersion:      dbVersion,
		ScannerURI:     scannerUri,
		ScannerVersion: scannerVersion,
		Origin:         origin,
		Collector:      collector,
	}

	newCertifyVuln := &model.CertifyVuln{
		Package:  selectedPackage,
		Metadata: metadata,
	}
	if selectedOsv != nil {
		newCertifyVuln.Vulnerability = selectedOsv
	} else if selectedCve != nil {
		newCertifyVuln.Vulnerability = selectedCve
	} else {
		newCertifyVuln.Vulnerability = selectedGhsa
	}

	c.certifyVuln = append(c.certifyVuln, newCertifyVuln)
	return newCertifyVuln
}

func (c *demoClient) IngestVulnerability(ctx context.Context, pkg model.PkgInputSpec, vulnerability model.OsvCveOrGhsaInput, certifyVuln model.VulnerabilityMetaDataInput) (*model.CertifyVuln, error) {

	err := helper.ValidateOsvCveOrGhsaIngestionInput(vulnerability)
	if err != nil {
		return nil, err
	}

	selectedPkgSpec := helper.ConvertPkgInputSpecToPkgSpec(&pkg)

	collectedPkg, err := c.Packages(ctx, selectedPkgSpec)
	if err != nil {
		return nil, err
	}

	if len(collectedPkg) != 1 {
		return nil, gqlerror.Errorf(
			"IngestOccurrence :: multiple packages found")
	}

	if vulnerability.Osv != nil {
		osvSpec := helper.ConvertOsvInputSpecToOsvSpec(vulnerability.Osv)

		collectedOsv, err := c.Osv(ctx, osvSpec)
		if err != nil {
			return nil, err
		}
		if len(collectedOsv) != 1 {
			return nil, gqlerror.Errorf(
				"IngestVulnerability :: osv argument must match one, found %d",
				len(collectedOsv))
		}
		return c.registerCertifyVuln(
			collectedPkg[0],
			collectedOsv[0],
			nil,
			nil,
			certifyVuln.TimeScanned,
			certifyVuln.DbURI,
			certifyVuln.DbVersion,
			certifyVuln.ScannerURI,
			certifyVuln.ScannerVersion,
			certifyVuln.Origin,
			certifyVuln.Collector), nil
	}

	if vulnerability.Cve != nil {

		cveSpec := helper.ConvertCveInputSpecToCveSpec(vulnerability.Cve)
		collectedCve, err := c.Cve(ctx, cveSpec)
		if err != nil {
			return nil, err
		}
		if len(collectedCve) != 1 {
			return nil, gqlerror.Errorf(
				"IngestVulnerability :: cve argument must match one, found %d",
				len(collectedCve))
		}
		return c.registerCertifyVuln(
			collectedPkg[0],
			nil,
			collectedCve[0],
			nil,
			certifyVuln.TimeScanned,
			certifyVuln.DbURI,
			certifyVuln.DbVersion,
			certifyVuln.ScannerURI,
			certifyVuln.ScannerVersion,
			certifyVuln.Origin,
			certifyVuln.Collector), nil
	}

	if vulnerability.Ghsa != nil {
		ghsaSpec := helper.ConvertGhsaInputSpecToGhsaSpec(vulnerability.Ghsa)

		collectedGhsa, err := c.Ghsa(ctx, ghsaSpec)
		if err != nil {
			return nil, err
		}
		if len(collectedGhsa) != 1 {
			return nil, gqlerror.Errorf(
				"IngestVulnerability :: ghsa argument must match one, found %d",
				len(collectedGhsa))
		}
		return c.registerCertifyVuln(
			collectedPkg[0],
			nil,
			nil,
			collectedGhsa[0],
			certifyVuln.TimeScanned,
			certifyVuln.DbURI,
			certifyVuln.DbVersion,
			certifyVuln.ScannerURI,
			certifyVuln.ScannerVersion,
			certifyVuln.Origin,
			certifyVuln.Collector), nil
	}
	// it should never reach here else it failed
	return nil, gqlerror.Errorf("IngestVulnerability failed")
}

// Query CertifyVuln

func (c *demoClient) CertifyVuln(ctx context.Context, certifyVulnSpec *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {

	queryAll, err := helper.ValidateOsvCveOrGhsaQueryInput(certifyVulnSpec.Vulnerability)
	if err != nil {
		return nil, err
	}
	var foundCertifyBad []*model.CertifyVuln

	for _, h := range c.certifyVuln {
		matchOrSkip := true

		if certifyVulnSpec.DbURI != nil && h.Metadata.DbURI != *certifyVulnSpec.DbURI {
			matchOrSkip = false
		}
		if certifyVulnSpec.DbVersion != nil && h.Metadata.DbVersion != *certifyVulnSpec.DbVersion {
			matchOrSkip = false
		}
		if certifyVulnSpec.ScannerURI != nil && h.Metadata.ScannerURI != *certifyVulnSpec.ScannerURI {
			matchOrSkip = false
		}
		if certifyVulnSpec.ScannerVersion != nil && h.Metadata.ScannerVersion != *certifyVulnSpec.ScannerVersion {
			matchOrSkip = false
		}
		if certifyVulnSpec.Collector != nil && h.Metadata.Collector != *certifyVulnSpec.Collector {
			matchOrSkip = false
		}
		if certifyVulnSpec.Origin != nil && h.Metadata.Origin != *certifyVulnSpec.Origin {
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
		if !queryAll {
			if certifyVulnSpec.Vulnerability != nil && certifyVulnSpec.Vulnerability.Cve != nil {
				if val, ok := h.Vulnerability.(*model.Cve); ok {
					if certifyVulnSpec.Vulnerability.Cve.Year == nil || val.Year == *certifyVulnSpec.Vulnerability.Cve.Year {
						newCve, err := filterCVEID(val, certifyVulnSpec.Vulnerability.Cve)
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

			if certifyVulnSpec.Vulnerability != nil && certifyVulnSpec.Vulnerability.Osv != nil {
				if val, ok := h.Vulnerability.(*model.Osv); ok {
					newOSV, err := filterOSVID(val, certifyVulnSpec.Vulnerability.Osv)
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

			if certifyVulnSpec.Vulnerability != nil && certifyVulnSpec.Vulnerability.Ghsa != nil {
				if val, ok := h.Vulnerability.(*model.Ghsa); ok {
					newGhsa, err := filterGHSAID(val, certifyVulnSpec.Vulnerability.Ghsa)
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
		}

		if matchOrSkip {
			foundCertifyBad = append(foundCertifyBad, h)
		}
	}

	return foundCertifyBad, nil
}
