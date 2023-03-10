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

package helper

import (
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func CheckVulnerabilityIngestionInput(vulnerability model.OsvCveOrGhsaInput) error {
	vulnDefined := 0
	if vulnerability.Osv != nil {
		vulnDefined = vulnDefined + 1
	}
	if vulnerability.Ghsa != nil {
		vulnDefined = vulnDefined + 1
	}
	if vulnerability.Cve != nil {
		vulnDefined = vulnDefined + 1
	}
	if vulnDefined != 1 {
		return gqlerror.Errorf("Must specify at most one vulnerability (cve, osv, or ghsa)")
	}
	return nil
}

func CheckVulnerabilityQueryInput(vulnerability *model.OsvCveOrGhsaSpec) (bool, error) {
	if vulnerability == nil {
		return true, nil
	} else {
		vulnDefined := 0
		if vulnerability.Osv != nil {
			vulnDefined = vulnDefined + 1
		}
		if vulnerability.Ghsa != nil {
			vulnDefined = vulnDefined + 1
		}
		if vulnerability.Cve != nil {
			vulnDefined = vulnDefined + 1
		}
		if vulnDefined != 1 {
			return false, gqlerror.Errorf("Must specify at most one vulnerability (cve, osv, or ghsa)")
		}
	}
	return false, nil
}

func CheckOccurrenceQueryInput(subject *model.PackageOrSourceSpec) (bool, error) {
	if subject == nil {
		return true, nil
	} else {
		if subject.Package == nil && subject.Source == nil || subject.Package != nil && subject.Source != nil {
			return false, gqlerror.Errorf("must specify one package or source for IsOccurrence")
		}
	}
	return false, nil
}

func CheckOccurrenceIngestionInput(subject model.PackageOrSourceInput) error {
	if subject.Package == nil && subject.Source == nil || subject.Package != nil && subject.Source != nil {
		return gqlerror.Errorf("must specify one package or source for IsOccurrence")
	}
	return nil
}

func CheckCertifyBadQueryInput(subject *model.PackageSourceOrArtifactSpec) (bool, error) {
	if subject == nil {
		return true, nil
	} else {
		subjectDefined := 0
		if subject.Package != nil {
			subjectDefined = subjectDefined + 1
		}
		if subject.Source != nil {
			subjectDefined = subjectDefined + 1
		}
		if subject.Artifact != nil {
			subjectDefined = subjectDefined + 1
		}
		if subjectDefined != 1 {
			return false, gqlerror.Errorf("must specify at most one subject (package, source, or artifact)")
		}
	}
	return false, nil
}

func ValidatePackageSourceOrArtifactInput(item *model.PackageSourceOrArtifactInput, path string) error {
	valuesDefined := 0
	if item.Package != nil {
		valuesDefined = valuesDefined + 1
	}
	if item.Source != nil {
		valuesDefined = valuesDefined + 1
	}
	if item.Artifact != nil {
		valuesDefined = valuesDefined + 1
	}
	if valuesDefined != 1 {
		return gqlerror.Errorf("Must specify at most one package, source, or artifact for %v", path)
	}

	return nil
}
