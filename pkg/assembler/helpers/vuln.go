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

package helpers

import (
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
)

func VulnInputToVURI(vuln *generated.VulnerabilityInputSpec) string {
	s := fmt.Sprintf("vuln://"+"%s/%s", strings.ToLower(vuln.Type), strings.ToLower(vuln.VulnerabilityID))
	return s
}

func OSVToGHSACVE(OSVId string) (*generated.VulnerabilityInputSpec, *generated.VulnerabilityInputSpec, error) {
	if strings.HasPrefix(OSVId, "CVE") {
		p := strings.Split(OSVId, "-")
		if len(p) != 3 {
			return nil, nil, fmt.Errorf("malformed CVE identifier: %q", OSVId)
		}
		return &generated.VulnerabilityInputSpec{
			Type:            "cve",
			VulnerabilityID: strings.ToLower(OSVId),
		}, nil, nil
	}
	if strings.HasPrefix(OSVId, "GHSA") {
		return nil, &generated.VulnerabilityInputSpec{
			Type:            "ghsa",
			VulnerabilityID: strings.ToLower(OSVId),
		}, nil
	}
	return nil, nil, fmt.Errorf("unknown OSV identifier: %q", OSVId)
}
