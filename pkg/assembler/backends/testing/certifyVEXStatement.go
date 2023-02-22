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
	selectedYear := "2019"
	selectedCveID := "CVE-2019-13110"
	selectedCVESpec := &model.CVESpec{Year: &selectedYear, CveID: &selectedCveID}
	selectedCve, err := client.Cve(context.TODO(), selectedCVESpec)
	if err != nil {
		return err
	}
	err = client.registerCertifyVEXStatement(selectedPackage[0], nil, selectedCve[0], nil, "this package is not vulnerable to this CVE", time.Now())
	if err != nil {
		return err
	}

	selectedGhsaID := "GHSA-h45f-rjvw-2rv2"
	selectedGhsaSpec := &model.GHSASpec{GhsaID: &selectedGhsaID}
	selectedGhsa, err := client.Ghsa(context.TODO(), selectedGhsaSpec)
	if err != nil {
		return err
	}
	err = client.registerCertifyVEXStatement(nil, &model.Artifact{Digest: "5a787865sd676dacb0142afa0b83029cd7befd9", Algorithm: "sha1"}, nil, selectedGhsa[0], "this artifact is not vulnerable to this GHSA", time.Now())
	if err != nil {
		return err
	}
	return nil
}

// Ingest CertifyPkg

func (c *demoClient) registerCertifyVEXStatement(selectedPackage *model.Package, selectedArtifact *model.Artifact, selectedCve *model.Cve, selectedGhsa *model.Ghsa, justification string, timestamp time.Time) error {

	if selectedPackage != nil && selectedArtifact != nil {
		return fmt.Errorf("cannot specify both package and artifact for CertifyVEXStatement")
	}

	for _, vex := range c.certifyVEXStatement {
		if vex.Justification == justification {
			if val, ok := vex.Subject.(model.Package); ok {
				if &val == selectedPackage {
					return nil
				}
			} else if val, ok := vex.Subject.(model.Artifact); ok {
				if &val == selectedArtifact {
					return nil
				}
			}
			if val, ok := vex.Vulnerability.(model.Cve); ok {
				if &val == selectedCve {
					return nil
				}
			} else if val, ok := vex.Vulnerability.(model.Ghsa); ok {
				if &val == selectedGhsa {
					return nil
				}
			}
		}
	}

	newCertifyVEXStatement := &model.CertifyVEXStatement{
		KnownSince:    timestamp.String(),
		Justification: justification,
		Origin:        "testing backend",
		Collector:     "testing backend",
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
	return nil
}

// Query CertifyPkg

func (c *demoClient) CertifyVEXStatement(ctx context.Context, certifyVEXStatementSpec *model.CertifyVEXStatementSpec) ([]*model.CertifyVEXStatement, error) {

	if certifyVEXStatementSpec.Cve != nil && certifyVEXStatementSpec.Ghsa != nil {
		return nil, gqlerror.Errorf("cannot specify cve and ghsa together for CertifyVEXStatement")
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

		if certifyVEXStatementSpec.Package != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Package); ok {
				if certifyVEXStatementSpec.Package.Type == nil || val.Type == *certifyVEXStatementSpec.Package.Type {
					newPkg := filterPackageNamespace(val, certifyVEXStatementSpec.Package)
					if newPkg == nil {
						matchOrSkip = false
					}
				}
			} else {
				matchOrSkip = false
			}
		}

		if certifyVEXStatementSpec.Artifact != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Artifact); ok {
				queryArt := &model.Artifact{
					Algorithm: strings.ToLower(*certifyVEXStatementSpec.Artifact.Algorithm),
					Digest:    strings.ToLower(*certifyVEXStatementSpec.Artifact.Digest),
				}
				if !reflect.DeepEqual(val, queryArt) {
					matchOrSkip = false
				}
			} else {
				matchOrSkip = false
			}
		}

		if certifyVEXStatementSpec.Cve != nil {
			if val, ok := h.Vulnerability.(*model.Cve); ok {
				if certifyVEXStatementSpec.Cve.Year == nil || val.Year == *certifyVEXStatementSpec.Cve.Year {
					newCve, err := filterCVEID(val, certifyVEXStatementSpec.Cve)
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

		if certifyVEXStatementSpec.Ghsa != nil {
			if val, ok := h.Vulnerability.(*model.Ghsa); ok {
				newGhsa, err := filterGHSAID(val, certifyVEXStatementSpec.Ghsa)
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
			foundCertifyVEXStatement = append(foundCertifyVEXStatement, h)
		}
	}

	return foundCertifyVEXStatement, nil
}
