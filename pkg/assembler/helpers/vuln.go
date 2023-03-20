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
	"strconv"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
)

func OSVToGHSACVE(OSVId string) (*generated.CVEInputSpec, *generated.GHSAInputSpec, error) {
	if strings.HasPrefix(OSVId, "CVE") {
		p := strings.Split(OSVId, "-")
		if len(p) != 3 {
			return nil, nil, fmt.Errorf("malformed CVE identifier: %q", OSVId)
		}
		year, err := strconv.Atoi(p[1])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert year to int: %w", err)
		}
		return &generated.CVEInputSpec{
			CveId: OSVId,
			Year:  year,
		}, nil, nil
	}
	if strings.HasPrefix(OSVId, "GHSA") {
		return nil, &generated.GHSAInputSpec{
			GhsaId: OSVId,
		}, nil
	}
	return nil, nil, fmt.Errorf("unknown OSV identifier: %q", OSVId)
}
