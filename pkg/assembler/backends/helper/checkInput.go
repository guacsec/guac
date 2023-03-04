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

func CheckCertifyVulnInputs(certifyVulnSpec *model.CertifyVulnSpec) error {
	invalidVuln := false
	if certifyVulnSpec.Osv != nil && certifyVulnSpec.Cve != nil && certifyVulnSpec.Ghsa != nil {
		invalidVuln = true
	}
	if certifyVulnSpec.Osv != nil && certifyVulnSpec.Cve != nil {
		invalidVuln = true
	}
	if certifyVulnSpec.Osv != nil && certifyVulnSpec.Ghsa != nil {
		invalidVuln = true
	}
	if certifyVulnSpec.Cve != nil && certifyVulnSpec.Ghsa != nil {
		invalidVuln = true
	}
	if invalidVuln {
		return gqlerror.Errorf("cannot specify more than one vulnerability for CertifyVuln query")
	}
	return nil
}

func CheckIngestVulnInputs(osv *model.OSVInputSpec, cve *model.CVEInputSpec, ghsa *model.GHSAInputSpec) error {
	invalidVuln := false
	if osv != nil && cve != nil && ghsa != nil {
		invalidVuln = true
	}
	if osv != nil && cve != nil {
		invalidVuln = true
	}
	if osv != nil && ghsa != nil {
		invalidVuln = true
	}
	if cve != nil && ghsa != nil {
		invalidVuln = true
	}
	if invalidVuln {
		return gqlerror.Errorf("cannot specify more than one vulnerability for IngestVulnerability")
	}
	return nil
}
