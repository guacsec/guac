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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func registerAllCertifyBad(client *demoClient) error {
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
	err = client.registerCertifyBad(selectedPackage[0], nil, nil, "this openssl package is a typosquatting")
	if err != nil {
		return err
	}
	// "git", "github", "github.com/guacsec/guac", "tag=v0.0.1"
	selectedSourceType := "git"
	selectedSourceNameSpace := "github"
	selectedSourceName := "github.com/guacsec/guac"
	selectedTag := "v0.0.1"
	selectedSourceSpec := &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Tag: &selectedTag}
	selectedSource, err := client.Sources(context.TODO(), selectedSourceSpec)
	if err != nil {
		return err
	}
	err = client.registerCertifyBad(nil, selectedSource[0], nil, "this source is associated with a bad author")
	if err != nil {
		return err
	}

	err = client.registerCertifyBad(nil, nil, &model.Artifact{Digest: "5a787865sd676dacb0142afa0b83029cd7befd9", Algorithm: "sha1"}, "this artifact is associated with a bad package")
	if err != nil {
		return err
	}

	return nil
}

// Ingest CertifyBad

func (c *demoClient) registerCertifyBad(selectedPackage *model.Package, selectedSource *model.Source, selectedArtifact *model.Artifact, justification string) error {

	if selectedPackage != nil && selectedSource != nil && selectedArtifact != nil {
		return fmt.Errorf("cannot specify package, source or artifact together for CertifyBad")
	}

	for _, occurrence := range c.certifyBad {
		if occurrence.Justification == justification {
			if val, ok := occurrence.Subject.(model.Package); ok {
				if &val == selectedPackage {
					return nil
				}
			} else if val, ok := occurrence.Subject.(model.Source); ok {
				if &val == selectedSource {
					return nil
				}
			} else if val, ok := occurrence.Subject.(model.Artifact); ok {
				if &val == selectedArtifact {
					return nil
				}
			}
		}
	}

	newCertifyBad := &model.CertifyBad{
		Justification: justification,
		Origin:        "testing backend",
		Collector:     "testing backend",
	}
	if selectedPackage != nil {
		newCertifyBad.Subject = selectedPackage
	} else if selectedSource != nil {
		newCertifyBad.Subject = selectedSource
	} else {
		newCertifyBad.Subject = selectedArtifact
	}

	c.certifyBad = append(c.certifyBad, newCertifyBad)
	return nil
}

// Query CertifyBad

func (c *demoClient) CertifyBad(ctx context.Context, certifyBadSpec *model.CertifyBadSpec) ([]*model.CertifyBad, error) {
	err := checkCertifyBadInputs(certifyBadSpec)
	if err != nil {
		return nil, err
	}

	var foundCertifyBad []*model.CertifyBad

	for _, h := range c.certifyBad {
		matchOrSkip := true

		if certifyBadSpec.Justification != nil && h.Justification != *certifyBadSpec.Justification {
			matchOrSkip = false
		}
		if certifyBadSpec.Collector != nil && h.Collector != *certifyBadSpec.Collector {
			matchOrSkip = false
		}
		if certifyBadSpec.Origin != nil && h.Origin != *certifyBadSpec.Origin {
			matchOrSkip = false
		}

		if certifyBadSpec.Package != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Package); ok {
				if certifyBadSpec.Package.Type == nil || val.Type == *certifyBadSpec.Package.Type {
					newPkg := filterPackageNamespace(val, certifyBadSpec.Package)
					if newPkg == nil {
						matchOrSkip = false
					}
				}
			} else {
				matchOrSkip = false
			}
		}

		if certifyBadSpec.Source != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Source); ok {
				if certifyBadSpec.Source.Type == nil || val.Type == *certifyBadSpec.Source.Type {
					newSource, err := filterSourceNamespace(val, certifyBadSpec.Source)
					if err != nil {
						return nil, err
					}
					if newSource == nil {
						matchOrSkip = false
					}
				}
			} else {
				matchOrSkip = false
			}
		}

		if certifyBadSpec.Artifact != nil && h.Subject != nil {
			if val, ok := h.Subject.(*model.Artifact); ok {
				queryArt := &model.Artifact{
					Algorithm: strings.ToLower(*certifyBadSpec.Artifact.Algorithm),
					Digest:    strings.ToLower(*certifyBadSpec.Artifact.Digest),
				}
				if *queryArt != *val {
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

// TODO (pxp928): combine with neo4j backend in shared utility
func checkCertifyBadInputs(certifyBadSpec *model.CertifyBadSpec) error {
	invalidSubject := false
	if certifyBadSpec.Package != nil && certifyBadSpec.Source != nil && certifyBadSpec.Artifact != nil {
		invalidSubject = true
	}
	if certifyBadSpec.Package != nil && certifyBadSpec.Source != nil {
		invalidSubject = true
	}
	if certifyBadSpec.Package != nil && certifyBadSpec.Artifact != nil {
		invalidSubject = true
	}
	if certifyBadSpec.Source != nil && certifyBadSpec.Artifact != nil {
		invalidSubject = true
	}
	if invalidSubject {
		return gqlerror.Errorf("cannot specify more than one subject for CertifyBad query")
	}
	return nil
}
