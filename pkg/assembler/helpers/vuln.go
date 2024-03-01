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
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type VulnIds struct {
	TypeId          string
	VulnerabilityID string
}

func VulnServerKey(vuln *model.VulnerabilityInputSpec) VulnIds {
	return guacVulnId(vuln.Type, vuln.VulnerabilityID)
}

func VulnClientKey(vuln *generated.VulnerabilityInputSpec) VulnIds {
	return guacVulnId(vuln.Type, vuln.VulnerabilityID)
}

func guacVulnId(vulnType, vulnID string) VulnIds {
	ids := VulnIds{}
	ids.TypeId = strings.ToLower(vulnType)
	ids.VulnerabilityID = fmt.Sprintf("%s::%s", ids.TypeId, strings.ToLower(vulnID))
	return ids
}

func CreateVulnInput(vulnID string) (*generated.VulnerabilityInputSpec, error) {
	v := strings.Split(vulnID, "-")
	if len(v) == 1 {
		return nil, fmt.Errorf("malformed vulnerability identifier: %q", vulnID)
	}
	return &generated.VulnerabilityInputSpec{
		Type:            strings.ToLower(v[0]),
		VulnerabilityID: strings.ToLower(vulnID),
	}, nil
}
