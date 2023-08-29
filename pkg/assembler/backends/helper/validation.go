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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

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

func ValidateLicenseInput(license *model.LicenseInputSpec) error {
	var inline string
	var listVersion string
	if license.Inline != nil {
		inline = *license.Inline
	}
	if license.ListVersion != nil {
		listVersion = *license.ListVersion
	}
	if inline == "" && listVersion == "" {
		return gqlerror.Errorf("Neither Inline nor ListVersion are provided.")
	}
	if inline != "" && listVersion != "" {
		return gqlerror.Errorf("Both Inline and ListVersion are provided.")
	}
	if inline == "" && strings.HasPrefix(license.Name, "LicenseRef") {
		return gqlerror.Errorf("LicenseRef name provided without inline.")
	}
	if listVersion == "" && !strings.HasPrefix(license.Name, "LicenseRef") {
		return gqlerror.Errorf("Inline provided provided with non LicenseRef name.")
	}
	return nil
}
