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

func ValidateVulnerabilityIngestionInput(vulnerability model.VulnerabilityInput, path string, noVulnAllowed bool) error {
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
	if noVulnAllowed && vulnerability.NoVuln != nil && *vulnerability.NoVuln {
		if vulnDefined != 0 {
			return gqlerror.Errorf("Since NoVuln is set, no other vulnerability type is allowed for %v", path)
		}
		return nil
	}
	if vulnDefined != 1 {
		return gqlerror.Errorf("Must specify at most one vulnerability (cve, osv, or ghsa) for %v", path)
	}
	return nil
}

func ValidateVulnerabilityQueryFilter(vulnerability *model.VulnerabilitySpec, noVulnAllowed bool) error {
	if vulnerability == nil {
		return nil
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
		if noVulnAllowed && vulnerability.NoVuln != nil {
			if vulnDefined != 0 {
				return gqlerror.Errorf("Since NoVuln is set, no other vulnerability type is allowed")
			}
			return nil
		}
		if vulnDefined != 1 {
			return gqlerror.Errorf("Must specify at most one vulnerability (cve, osv, or ghsa)")
		}
	}
	return nil
}

func ValidateCveOrGhsaIngestionInput(cveOrGhsa model.CveOrGhsaInput, path string) error {
	vulnDefined := 0
	if cveOrGhsa.Ghsa != nil {
		vulnDefined = vulnDefined + 1
	}
	if cveOrGhsa.Cve != nil {
		vulnDefined = vulnDefined + 1
	}
	if vulnDefined != 1 {
		return gqlerror.Errorf("Must specify at most one vulnerability (cve, or ghsa) for %v", path)
	}
	return nil
}

func ValidateCveOrGhsaQueryFilter(cveOrGhsa *model.CveOrGhsaSpec) error {
	if cveOrGhsa == nil {
		return nil
	} else {
		vulnDefined := 0
		if cveOrGhsa.Ghsa != nil {
			vulnDefined = vulnDefined + 1
		}
		if cveOrGhsa.Cve != nil {
			vulnDefined = vulnDefined + 1
		}
		if vulnDefined != 1 {
			return gqlerror.Errorf("Must specify at most one vulnerability (cve, or ghsa)")
		}
	}
	return nil
}

func ValidatePackageSourceOrArtifactQueryFilter(subject *model.PackageSourceOrArtifactSpec) error {
	if subject == nil {
		return nil
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
			return gqlerror.Errorf("must specify at most one subject (package, source, or artifact)")
		}
	}
	return nil
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

func ValidatePackageOrSourceInput(item *model.PackageOrSourceInput, path string) error {
	valuesDefined := 0
	if item.Package != nil {
		valuesDefined = valuesDefined + 1
	}
	if item.Source != nil {
		valuesDefined = valuesDefined + 1
	}
	if valuesDefined != 1 {
		return gqlerror.Errorf("Must specify at most one package or source for %v", path)
	}

	return nil
}

func ValidatePackageOrSourceQueryFilter(subject *model.PackageOrSourceSpec) error {
	if subject == nil {
		return nil
	} else {
		subjectDefined := 0
		if subject.Package != nil {
			subjectDefined = subjectDefined + 1
		}
		if subject.Source != nil {
			subjectDefined = subjectDefined + 1
		}
		if subjectDefined != 1 {
			return gqlerror.Errorf("must specify at most one subject (package or source)")
		}
	}
	return nil
}

func ValidatePackageOrArtifactInput(item *model.PackageOrArtifactInput, path string) error {
	valuesDefined := 0
	if item.Package != nil {
		valuesDefined = valuesDefined + 1
	}
	if item.Artifact != nil {
		valuesDefined = valuesDefined + 1
	}
	if valuesDefined != 1 {
		return gqlerror.Errorf("Must specify at most one package or artifact for %v", path)
	}

	return nil
}

func ValidatePackageOrArtifactQueryFilter(subject *model.PackageOrArtifactSpec) error {
	if subject == nil {
		return nil
	} else {
		subjectDefined := 0
		if subject.Package != nil {
			subjectDefined = subjectDefined + 1
		}
		if subject.Artifact != nil {
			subjectDefined = subjectDefined + 1
		}
		if subjectDefined != 1 {
			return gqlerror.Errorf("must specify at most one subject (package or artifact)")
		}
	}
	return nil
}
