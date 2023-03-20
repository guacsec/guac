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
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func registerAllCertifyVEXStatement(client *demoClient) error {

	// pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
	// "conan", "openssl.org", "openssl", "3.0.3", "", "user=bincrafters", "channel=stable"
	selectedType := "conan"
	selectedNameSpace := "openssl.org"
	selectedName := "openssl"
	selectedVersion := "3.0.3"
	qualifierA := "bincrafters"
	qualifierB := "stable"
	selectedQualifiers := []*model.PackageQualifierSpec{{Key: "user", Value: &qualifierA}, {Key: "channel", Value: &qualifierB}}
	selectedPkgSpec := &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Qualifiers: selectedQualifiers}
	selectedPackage, err := client.Packages(context.TODO(), selectedPkgSpec)
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
	_, err = client.registerCertifyVEXStatement(selectedPackage[0], nil, selectedCve[0], nil, "this package is not vulnerable to this CVE", "testing backend", "testing backend", time.Now())
	if err != nil {
		return err
	}

	selectedGhsaID := "GHSA-h45f-rjvw-2rv2"
	selectedGhsaSpec := &model.GHSASpec{GhsaID: &selectedGhsaID}
	selectedGhsa, err := client.Ghsa(context.TODO(), selectedGhsaSpec)
	if err != nil {
		return err
	}
	_, err = client.registerCertifyVEXStatement(nil, &model.Artifact{Digest: "5a787865sd676dacb0142afa0b83029cd7befd9", Algorithm: "sha1"}, nil, selectedGhsa[0], "this artifact is not vulnerable to this GHSA", "testing backend", "testing backend", time.Now())
	if err != nil {
		return err
	}
	return nil
}

// Ingest CertifyPkg

func (c *demoClient) registerCertifyVEXStatement(selectedPackage *model.Package, selectedArtifact *model.Artifact, selectedCve *model.Cve, selectedGhsa *model.Ghsa, justification, origin, collector string, timestamp time.Time) (*model.CertifyVEXStatement, error) {

	if selectedPackage != nil && selectedArtifact != nil {
		return nil, fmt.Errorf("cannot specify both package and artifact for CertifyVEXStatement")
	}

	for _, vex := range c.certifyVEXStatement {
		if vex.Justification == justification {
			if val, ok := vex.Subject.(model.Package); ok {
				if reflect.DeepEqual(val, *selectedPackage) {
					return vex, nil
				}
			} else if val, ok := vex.Subject.(model.Artifact); ok {
				if reflect.DeepEqual(val, *selectedArtifact) {
					return vex, nil
				}
			}
			if val, ok := vex.Vulnerability.(model.Cve); ok {
				if reflect.DeepEqual(val, *selectedCve) {
					return vex, nil
				}
			} else if val, ok := vex.Vulnerability.(model.Ghsa); ok {
				if reflect.DeepEqual(val, *selectedGhsa) {
					return vex, nil
				}
			}
		}
	}

	newCertifyVEXStatement := &model.CertifyVEXStatement{
		KnownSince:    timestamp,
		Justification: justification,
		Origin:        origin,
		Collector:     collector,
	}
	if selectedCve != nil {
		newCertifyVEXStatement.Vulnerability = selectedCve
	} else {
		newCertifyVEXStatement.Vulnerability = selectedGhsa
	}
	if selectedPackage != nil {
		newCertifyVEXStatement.Subject = selectedPackage
	} else {
		newCertifyVEXStatement.Subject = selectedArtifact
	}

	c.certifyVEXStatement = append(c.certifyVEXStatement, newCertifyVEXStatement)
	return newCertifyVEXStatement, nil
}

func (c *demoClient) IngestVEXStatement(ctx context.Context, subject model.PackageOrArtifactInput, vulnerability model.CveOrGhsaInput, vexStatement model.VexStatementInputSpec) (*model.CertifyVEXStatement, error) {
	err := helper.ValidatePackageOrArtifactInput(&subject, "IngestVEXStatement")
	if err != nil {
		return nil, err
	}
	err = helper.ValidateCveOrGhsaIngestionInput(vulnerability, "IngestVEXStatement")
	if err != nil {
		return nil, err
	}

	if subject.Package != nil {
		selectedPkgSpec := helper.ConvertPkgInputSpecToPkgSpec(subject.Package)

		collectedPkg, err := c.Packages(ctx, selectedPkgSpec)
		if err != nil {
			return nil, err
		}
		if len(collectedPkg) != 1 {
			return nil, gqlerror.Errorf(
				"IngestVEXStatement :: multiple packages found")
		}

		if vulnerability.Cve != nil {

			cveSpec := helper.ConvertCveInputSpecToCveSpec(vulnerability.Cve)
			collectedCve, err := c.Cve(ctx, cveSpec)
			if err != nil {
				return nil, err
			}
			if len(collectedCve) != 1 {
				return nil, gqlerror.Errorf(
					"IngestVEXStatement :: cve argument must match one, found %d",
					len(collectedCve))
			}
			return c.registerCertifyVEXStatement(
				collectedPkg[0],
				nil,
				collectedCve[0],
				nil,
				vexStatement.Justification,
				vexStatement.Origin,
				vexStatement.Collector,
				vexStatement.KnownSince)
		}

		if vulnerability.Ghsa != nil {
			ghsaSpec := helper.ConvertGhsaInputSpecToGhsaSpec(vulnerability.Ghsa)

			collectedGhsa, err := c.Ghsa(ctx, ghsaSpec)
			if err != nil {
				return nil, err
			}
			if len(collectedGhsa) != 1 {
				return nil, gqlerror.Errorf(
					"IngestVEXStatement :: ghsa argument must match one, found %d",
					len(collectedGhsa))
			}
			return c.registerCertifyVEXStatement(
				collectedPkg[0],
				nil,
				nil,
				collectedGhsa[0],
				vexStatement.Justification,
				vexStatement.Origin,
				vexStatement.Collector,
				vexStatement.KnownSince)
		}
	}

	if subject.Artifact != nil {
		collectedArt, err := c.Artifacts(ctx, &model.ArtifactSpec{Algorithm: &subject.Artifact.Algorithm, Digest: &subject.Artifact.Digest})
		if err != nil {
			return nil, err
		}
		if len(collectedArt) != 1 {
			return nil, gqlerror.Errorf(
				"IngestVEXStatement :: multiple artifacts found")
		}
		if vulnerability.Cve != nil {

			cveSpec := helper.ConvertCveInputSpecToCveSpec(vulnerability.Cve)
			collectedCve, err := c.Cve(ctx, cveSpec)
			if err != nil {
				return nil, err
			}
			if len(collectedCve) != 1 {
				return nil, gqlerror.Errorf(
					"IngestVEXStatement :: cve argument must match one, found %d",
					len(collectedCve))
			}
			return c.registerCertifyVEXStatement(
				nil,
				collectedArt[0],
				collectedCve[0],
				nil,
				vexStatement.Justification,
				vexStatement.Origin,
				vexStatement.Collector,
				vexStatement.KnownSince)
		}

		if vulnerability.Ghsa != nil {
			ghsaSpec := helper.ConvertGhsaInputSpecToGhsaSpec(vulnerability.Ghsa)

			collectedGhsa, err := c.Ghsa(ctx, ghsaSpec)
			if err != nil {
				return nil, err
			}
			if len(collectedGhsa) != 1 {
				return nil, gqlerror.Errorf(
					"IngestVEXStatement :: ghsa argument must match one, found %d",
					len(collectedGhsa))
			}
			return c.registerCertifyVEXStatement(
				nil,
				collectedArt[0],
				nil,
				collectedGhsa[0],
				vexStatement.Justification,
				vexStatement.Origin,
				vexStatement.Collector,
				vexStatement.KnownSince)
		}
	}
	// it should never reach here else it failed
	return nil, gqlerror.Errorf("IngestVEXStatement failed")
}

// Query CertifyPkg

func (c *demoClient) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {

	querySubjectAll, err := helper.ValidatePackageOrArtifactQueryInput(certifyVEXStatementSpec.Subject)
	if err != nil {
		return nil, err
	}

	queryVulnAll, err := helper.ValidateCveOrGhsaQueryInput(certifyVEXStatementSpec.Vulnerability)
	if err != nil {
		return nil, err
	}

	queryAll := false
	if querySubjectAll && queryVulnAll {
		queryAll = true
	}

	var foundCertifyVEXStatement []*model.CertifyVEXStatement

	for _, h := range c.certifyVEXStatement {
		matchOrSkip := true

		if certifyVEXStatementSpec.Justification != nil && h.Justification != *certifyVEXStatementSpec.Justification {
			matchOrSkip = false
		}
		if certifyVEXStatementSpec.Collector != nil && h.Collector != *certifyVEXStatementSpec.Collector {
			matchOrSkip = false
		}
		if certifyVEXStatementSpec.Origin != nil && h.Origin != *certifyVEXStatementSpec.Origin {
			matchOrSkip = false
		}

		if !queryAll {
			if !querySubjectAll {
				if certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Package != nil && h.Subject != nil {
					if val, ok := h.Subject.(*model.Package); ok {
						if certifyVEXStatementSpec.Subject.Package.Type == nil || val.Type == *certifyVEXStatementSpec.Subject.Package.Type {
							newPkg := filterPackageNamespace(val, certifyVEXStatementSpec.Subject.Package)
							if newPkg == nil {
								matchOrSkip = false
							}
						}
					} else {
						matchOrSkip = false
					}
				}

				if certifyVEXStatementSpec.Subject != nil && certifyVEXStatementSpec.Subject.Artifact != nil && h.Subject != nil {
					if val, ok := h.Subject.(*model.Artifact); ok {
						queryArt := &model.Artifact{
							Algorithm: strings.ToLower(*certifyVEXStatementSpec.Subject.Artifact.Algorithm),
							Digest:    strings.ToLower(*certifyVEXStatementSpec.Subject.Artifact.Digest),
						}
						if !reflect.DeepEqual(val, queryArt) {
							matchOrSkip = false
						}
					} else {
						matchOrSkip = false
					}
				}
			}

			if !queryVulnAll {
				if certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Cve != nil && h.Vulnerability != nil {
					if val, ok := h.Vulnerability.(*model.Cve); ok {
						if certifyVEXStatementSpec.Vulnerability.Cve.Year == nil || val.Year == *certifyVEXStatementSpec.Vulnerability.Cve.Year {
							newCve, err := filterCVEID(val, certifyVEXStatementSpec.Vulnerability.Cve)
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

				if certifyVEXStatementSpec.Vulnerability != nil && certifyVEXStatementSpec.Vulnerability.Ghsa != nil && h.Vulnerability != nil {
					if val, ok := h.Vulnerability.(*model.Ghsa); ok {
						newGhsa, err := filterGHSAID(val, certifyVEXStatementSpec.Vulnerability.Ghsa)
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
		}

		if matchOrSkip {
			foundCertifyVEXStatement = append(foundCertifyVEXStatement, h)
		}
	}

	return foundCertifyVEXStatement, nil
}
